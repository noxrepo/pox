'''
Created on Feb 25, 2012

@author: rcs
'''
import exceptions
import sys
import errno
import logging
import Queue
import socket

from pox.lib.util import assert_type, makePinger
from pox.lib.recoco import Select, Task

log = logging.getLogger()

class IOWorker(object):
  """ Generic IOWorker class. Defines the IO contract for our simulator. Fire and forget semantics for send. 
      Received data is being queued until explicitely consumed by the client
  """
  def __init__(self):
    self.send_buf = ""
    self.receive_buf = ""
    self._on_data_receive = lambda worker: None

  def set_receive_handler(self, block):
    self._on_data_receive = block

  def send(self, data):
    """ send data from the client side. fire and forget. """
    assert_type("data", data, [bytes], none_ok=False)
    self.send_buf += data

  def push_receive_data(self, new_data):
    """ notify client of new received data. called by a Select loop """
    self.receive_buf += new_data
    self._on_data_receive(self)

  def peek_receive_buf(self):
    return self.receive_buf

  def consume_receive_buf(self, l):
    """ called from the client to consume receive buffer """
    assert(len(self.receive_buf) >= l)
    self.receive_buf = self.receive_buf[l:]

  @property
  def ready_to_send(self):
    return len(self.send_buf) > 0

  def consume_send_buf(self, l):
    assert(len(self.send_buf)>=l)
    self.send_buf = self.send_buf[l:]

  def close(self):
    pass

class RecocoIOWorker(IOWorker):
  """ An IOWorker that works with our RecocoIOLoop, and notifies it via pinger """
  def __init__(self, socket, pinger, on_close):
    IOWorker.__init__(self)
    self.socket = socket
    self.pinger = pinger
    self.on_close = on_close

  def fileno(self):
    return self.socket.fileno()

  def send(self, data):
    IOWorker.send(self, data)
    self.pinger.ping()

  def close(self):
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
    self.workers = set()
    self.pinger = makePinger()
    # socket.close() must be performed by this Select task -- otherwise
    # we'll end up blocking on socket that doesn't exist.
    self.pending_worker_closes = []

  def create_worker_for_socket(self, socket):
    def on_close(worker):
      ''' callback for io_worker.close() '''
      self.pending_worker_closes.append(worker)
      self.pinger.ping()
    worker = RecocoIOWorker(socket, pinger=self.pinger, on_close=on_close)
    self.workers.add(worker)
    self.pinger.ping()
    return worker
    
  def _close_worker(self, worker):
    ''' only called by our Select task ''' 
    worker.socket.close()
    self.workers.discard(worker)
    
  def stop(self):
    self.running = False
    self.pinger.ping()

  def run (self):
    self.running = True
    while self.running:
      try:
        # First, close and pending sockets
        for io_worker in self.pending_worker_closes:
          self._close_worker(io_worker)
        self.pending_socket_closes = []
        
        # Now grab remaining workers
        read_sockets = list(self.workers) + [ self.pinger ]
        write_sockets = [ worker for worker in self.workers if worker.ready_to_send ]
        exception_sockets = list(self.workers)

        rlist, wlist, elist = yield Select(read_sockets, write_sockets,
                exception_sockets, self._select_timeout)

        if self.pinger in rlist :
          self.pinger.pongAll()
          rlist.remove(self.pinger)

        for worker in elist:
          worker.close()
          if worker in self.workers:
            self.workers.remove(worker)

        for worker in rlist:
          try:
            data = worker.socket.recv(self._BUF_SIZE)
            worker.push_receive_data(data)
          except socket.error as (s_errno, strerror):
            log.error("Socket error: " + strerror)
            worker.close()
            self.workers.discard(worker)

        for worker in wlist:
          try:
            l = worker.socket.send(worker.send_buf)
            if l > 0:
              worker.consume_send_buf(l)
          except socket.error as (s_errno, strerror):
            if s_errno != errno.EAGAIN:
              log.error("Socket error: " + strerror)
              worker.close()
              self.workers.discard(worker)

      except exceptions.KeyboardInterrupt:
        break
