'''
Created on Feb 25, 2012

@author: rcs
'''
import exceptions
import sys
import errno
import json
import logging
import Queue
import re
import socket

from pox.lib.util import assert_type, makePinger
from pox.lib.recoco import Select, Task

log = logging.getLogger()
log.debug = lambda msg, *args: None

class JSONIOWorker(object):
  def __init__(self, io_worker, on_json_received=None):
    self.io_worker = io_worker
    self.worker = LineIOWorker(io_worker)
    self.worker.on_line_received = self._receive_line

    if on_json_received is None:
      on_json_received = lambda worker, json_hash: log.warn("Received json_hash: %s, but no delegate yet", json_hash)

    self.on_json_received = on_json_received

  def _receive_line(self, worker, line):
    # log.debug("JSONIOWorker _receive_line: %s", line)
    json_hash = json.loads(line)
    self.on_json_received(self, json_hash)

  def send(self, json_object):
    self.worker.send_line(json.dumps(json_object))

  def close(self):
    self.worker.close()


class LineIOWorker(object):
  """ Wraps a IOWorker and delivers the data line by line """

  new_line = re.compile(r"([^\r\n]*)(\r\n|\r|\n)")

  def __init__(self, io_worker):
    self.io_worker = io_worker
    io_worker.set_receive_handler(self._receive_data)
    self._on_line_received = lambda: None

  def get_on_line_received(self):
    return self._on_line_received

  def set_on_line_received(self, on_line_received):
    self._on_line_received = on_line_received

  on_line_received = property(get_on_line_received, set_on_line_received)

  def _receive_data(self, io_worker):
    data = str(io_worker.peek_receive_buf())
    length = 0

    while True:
      match = LineIOWorker.new_line.match(data)
      if match is None:
        break

      self._on_line_received(self, match.group(1))
      match_len = len(match.group(0))
      length += match_len
      data = data[match_len:]

    io_worker.consume_receive_buf(length)

  def send_line(self, line):
    self.io_worker.send(''.join([line, "\n"]))

  def close(self):
    self.io_worker.close()

class IOWorker(object):
  """ Generic IOWorker class. Defines the IO contract for our simulator. Fire and forget semantics for send.
      Received data is being queued until explicitely consumed by the client
  """
  def __init__(self):
    self.send_buf = ""
    self.receive_buf = ""
    self._on_data_receive = lambda worker: None

  def set_receive_handler(self, block):
    """ Cause us to call the given block whenever data is ready to be read """
    self._on_data_receive = block

  def send(self, data):
    """ send data from the client side. fire and forget. """
    assert_type("data", data, [bytes], none_ok=False)
    #log.debug("IOWorker.send: sending %s (send_buf is %s)", repr(data), repr(self.send_buf))
    self.send_buf += data

  def _push_receive_data(self, new_data):
    #log.debug("IOWorker._push_receive_data: new_data=%s", repr(new_data))
    # notify client of new received data. called by a Select loop
    self.receive_buf += new_data
    self._on_data_receive(self)

  def peek_receive_buf(self):
    """ Grab the receive buffer. Don't modify it! """
    return self.receive_buf

  def consume_receive_buf(self, l):
    """ Consume receive buffer """
    # called from the client
    assert(len(self.receive_buf) >= l)
    self.receive_buf = self.receive_buf[l:]

  @property
  def _ready_to_send(self):
    # called by Select loop
    return len(self.send_buf) > 0

  def _consume_send_buf(self, l):
    # Throw out the first l bytes of the send buffer
    # Called by Select loop
    assert(len(self.send_buf)>=l)
    #log.debug("IOWorker._consume_send_buf: _consuming %d bytes of send_buf is %s", l, repr(self.send_buf))
    self.send_buf = self.send_buf[l:]
    #log.debug("IOWorker._consume_send_buf: send_buf is now %s", repr(self.send_buf))

  def close(self):
    """ Close this socket """
    pass

class RecocoIOWorker(IOWorker):
  """ An IOWorker that works with our RecocoIOLoop, and notifies it via pinger """
  def __init__(self, socket, pinger, on_close):
    IOWorker.__init__(self)
    self.socket = socket
    self.pinger = pinger
    # (on_close factory method hides details of the Select loop)
    self.on_close = on_close

  def fileno(self):
    """ Return the wrapped sockets' fileno """
    return self.socket.fileno()

  def send(self, data):
    """ send data from the client side. fire and forget. """
    IOWorker.send(self, data)
    self.pinger.ping()

  def close(self):
    """ Register this socket to be closed. fire and forget """
    # (don't close until Select loop is ready)
    IOWorker.close(self)
    # on_close is a function not a method
    self.on_close(self)

class RecocoIOLoop(Task):
  """
  recoco task that handles the actual IO for our IO workers
  """
  _select_timeout = 5
  _BUF_SIZE = 8192

  def __init__ (self):
    Task.__init__(self)
    self._workers = set()
    self.pinger = makePinger()
    # socket.open() and socket.close() are performed by this Select task
    # other threads register open() and close() requests by adding lambdas
    # to this thread-safe queue.
    self._pending_commands = Queue.Queue()

  def create_worker_for_socket(self, socket):
    '''
    Return an IOWorker wrapping the given socket.
    '''
    # Called from external threads.
    # Does not register the IOWorker immediately with the select loop --
    # rather, adds a command to the pending queue

    # Our callback for io_worker.close():
    def on_close(worker):
      def close_worker(worker):
        # Actually close the worker (called by Select loop)
        worker.socket.close()
        self._workers.discard(worker)
      # schedule close_worker to be called by Select loop
      self._pending_commands.put(lambda: close_worker(worker))
      self.pinger.ping()

    worker = RecocoIOWorker(socket, pinger=self.pinger, on_close=on_close)
    # Don't add immediately, since we're in the wrong thread
    self._pending_commands.put(lambda: self._workers.add(worker))
    self.pinger.ping()
    return worker

  def stop(self):
    self.running = False
    self.pinger.ping()

  def run (self):
    self.running = True
    while self.running:
      try:
        # First, execute pending commands
        while not self._pending_commands.empty():
          self._pending_commands.get()()

        # Now grab workers
        read_sockets = list(self._workers) + [ self.pinger ]
        write_sockets = [ worker for worker in self._workers if worker._ready_to_send ]
        exception_sockets = list(self._workers)

        rlist, wlist, elist = yield Select(read_sockets, write_sockets,
                exception_sockets, self._select_timeout)

        if self.pinger in rlist :
          self.pinger.pongAll()
          rlist.discard(self.pinger)

        for worker in elist:
          worker.close()
          if worker in self._workers:
            self._workers.discard(worker)

        for worker in rlist:
          try:
            data = worker.socket.recv(self._BUF_SIZE)
            if data:
              worker._push_receive_data(data)
            else:
              worker.close()
              self._workers.discard(worker)
          except socket.error as (s_errno, strerror):
            log.error("Socket error: %s", strerror)
            worker.close()
            self._workers.discard(worker)

        for worker in wlist:
          try:
            l = worker.socket.send(worker.send_buf)
            #log.debug("RecocoIOLoop: sent %d bytes from send buf %s", l,  worker.send_buf)
            if l > 0:
              worker._consume_send_buf(l)
          except socket.error as (s_errno, strerror):
            if s_errno != errno.EAGAIN:
              log.error("Socket error: %s", strerror)
              worker.close()
              self._workers.discard(worker)

      except exceptions.KeyboardInterrupt:
        break
