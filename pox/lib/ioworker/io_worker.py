# Copyright 2012 Colin Scott
# Copyright 2012 Andreas Wundsam
# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
IOWorkers provide a convenient IO abstraction.  Sends are fire-and-forget,
and read data is buffered and you can get notifications when data is
available.
"""

import sys
import errno
from collections import deque
import socket

from pox.lib.util import assert_type, makePinger
from pox.lib.recoco import Select, Task

from pox.core import core
log = core.getLogger()

_dummy_handler = lambda worker : None

def _call_safe (f, socket=None):
  try:
    f()
  except Exception as e:
    if socket:
      log.error("Exception on socket %s..." % (socket))
    log.exception(e)


class IOWorker (object):
  """
  Generic IOWorker class.
  Fire and forget semantics for send. 
  Received data is queued until read.
  """
  def __init__(self):
    self.send_buf = b""
    self.receive_buf = b""
    self.closed = False

    self._custom_rx_handler = None
    self._custom_close_handler = None
    self._custom_connect_handler = None

    self._connecting = False

    self.rx_handler = None
    self.close_handler = None
    self.connect_handler = None

  def _handle_rx (self):
    """ Can be overridden OR you can just use rx_handler """
    self._custom_rx_handler(self)

  def _handle_close (self):
    """ Can be overridden OR you can just use close_handler """
    self._custom_close_handler(self)

  def _handle_connect (self):
    """ Can be overridden OR you can just use connect_handler """
    self._custom_connect_handler(self)

  def _do_exception (self, loop):
    self.close()
    loop._workers.discard(self)

  def _do_recv (self, loop):
    if self._connecting:
      self._connecting = False
      _call_safe(self._handle_connect)
    try:
      data = self.socket.recv(loop._BUF_SIZE)
      if len(data) == 0:
        self.close()
        loop._workers.discard(self)
      else:
        self._push_receive_data(data)
    except socket.error as (s_errno, strerror):
      if s_errno == errno.ENOENT:
        # SSL library does this sometimes
        log.error("Socket %s: ENOENT", str(self))
        return
      log.error("Socket %s error %i during recv: %s", str(self),
          s_errno, strerror)
      self.close()
      loop._workers.discard(self)

  def _do_send (self, loop):
    try:
      if self._connecting:
        self._connecting = False
        _call_safe(self._handle_connect)
      if len(self.send_buf):
        l = self.socket.send(self.send_buf)
        if l > 0:
          self._consume_send_buf(l)
    except socket.error as (s_errno, strerror):
      if s_errno != errno.EAGAIN:
        log.error("Socket %s error %i during send: %s", str(self),
          s_errno, strerror)
        self.close()
        loop._workers.discard(self)

  @property
  def available (self):
    """
    Number of available bytes to read()
    """
    return len(self.receive_buf)

  @property
  def connect_handler (self):
    if self._custom_connect_handler is _dummy_handler:
      return None
    return self._custom_connect_handler

  @connect_handler.setter
  def connect_handler (self, callback):
    """
    Handler to call when data is available to read
    """
    # Not sure if this is a good idea, but it might be...
    if self.connect_handler is not None or callback is not None:
      log.debug("Resetting connect_handler on %s?", self)
    if callback is None: callback = _dummy_handler
    self._custom_connect_handler = callback

  @property
  def close_handler (self):
    if self._custom_close_handler is _dummy_handler:
      return None
    return self._custom_close_handler

  @close_handler.setter
  def close_handler (self, callback):
    """
    Handler to call when data is available to read
    """
    # Not sure if this is a good idea, but it might be...
    if self.close_handler is not None or callback is not None:
      log.debug("Resetting close_handler on %s?", self)
    if callback is None: callback = _dummy_handler
    self._custom_close_handler = callback

  @property
  def rx_handler (self):
    if self._custom_rx_handler is _dummy_handler:
      return None
    return self._custom_rx_handler

  @rx_handler.setter
  def rx_handler (self, callback):
    """
    Handler to call when data is available to read
    """
    # Not sure if this is a good idea, but it might be...
    if self.rx_handler is not None or callback is not None:
      log.debug("Resetting rx_handler on %s?", self)
    if callback is None: callback = _dummy_handler
    self._custom_rx_handler = callback

  def send_fast (self, data):
    return self.send(data)

  def send (self, data):
    """ Send data.  Fire and forget. """
    assert assert_type("data", data, [bytes], none_ok=False)
    self.send_buf += data

  def _push_receive_data (self, new_data):
    # notify client of new received data. called by a Select loop
    self.receive_buf += new_data
    self._handle_rx()

  def peek (self, length = None):
    """ Peek up to length bytes from receive buffer. """
    if length is None:
      return self.receive_buf
    else:
      return self.receive_buf[:length]

  def consume_receive_buf (self, l):
    """ Consume receive buffer """
    # called from the client 
    if len(self.receive_buf) < l:
      raise RuntimeError("Receive buffer underrun")
    self.receive_buf = self.receive_buf[l:]

  def read (self, length = None):
    """
    Read up to length bytes from receive buffer
    (defaults to all)
    """
    if length is None:
      length = len(self.receive_buf)
    r = self.receive_buf[:length]
    self.receive_buf = self.receive_buf[length:]
    return r

  @property
  def _ready_to_send (self):
    # called by Select loop
    return len(self.send_buf) > 0 or self._connecting

  def _consume_send_buf (self, l):
    # Throw out the first l bytes of the send buffer 
    # Called by Select loop
    assert(len(self.send_buf)>=l)
    self.send_buf = self.send_buf[l:]

  def close(self):
    """ Close this socket """
    if self.closed: return
    self.closed = True
    _call_safe(self._handle_close)

  def __repr__ (self):
    return "<" + self.__class__.__name__ + ">"

class RecocoIOWorker (IOWorker):
  """
  An IOWorker that works with our RecocoIOLoop.
  """

  def __init__ (self, socket, pinger, on_close):
    """
    pinger is a pinger that will wake the RecocoIOLoop
    on_close is a factory that hides details of Select loop
    """
    IOWorker.__init__(self)
    self.socket = socket
    self.pinger = pinger
    self.on_close = on_close

  def fileno (self):
    """ Return the wrapped sockets' fileno """
    return self.socket.fileno()

  def send_fast (self, data):
    """
    send data from the client side. fire and forget.
    Must only be called from the same cooperative context as the
    IOWorker.
    """
    if len(self.send_buf)==0 and not self._connecting and not self.closed:
      try:
        l = self.socket.send(data, socket.MSG_DONTWAIT)
        if l == len(self.send_buf):
          return
        data = data[l]
      except socket.error as (s_errno, strerror):
        if s_errno != errno.EAGAIN:
          log.error("Socket error: " + strerror)
          self.close()
          return

    IOWorker.send(self, data)
    self.pinger.ping()

  def send (self, data):
    IOWorker.send(self, data)
    self.pinger.ping()

  def close (self):
    """ Register this socket to be closed. fire and forget """
    # (don't close until Select loop is ready) 
    if self.closed: return
    IOWorker.close(self)
    # on_close is a function not a method
    try:
      self.socket.shutdown(socket.SHUT_RD)
    except Exception:
      pass
    self.on_close(self)

if not hasattr(socket, "MSG_DONTWAIT"):
  # Don't have this feature.
  RecocoIOWorker.send_fast = RecocoIOWorker.send
  log.debug("RecocoIOWorker.send_fast() not available")
else:
  pass


def _format_lists (rlist, wlist, elist):
  everything = set()
  everything.update(rlist)
  everything.update(wlist)
  everything.update(elist)
  if len(everything) == 0: return "None"
  everything = list(everything)
  everything.sort()
  msg = ""
  for fd in everything:
    msg += str(fd).strip("<>").replace(" ", "-") + "|"
    if fd in rlist: msg += "R"
    if fd in wlist: msg += "W"
    if fd in elist: msg += "X"
    msg += " "
  msg = msg.strip()
  return msg


class RecocoIOLoop (Task):
  """
  recoco task that handles the actual IO for our IO workers
  """
  _select_timeout = 5
  _BUF_SIZE = 8192
  more_debugging = False

  def __init__ (self, worker_type = RecocoIOWorker):
    Task.__init__(self)
    self._worker_type = worker_type
    self._workers = set()
    self.pinger = makePinger()
    # socket.open() and socket.close() are performed by this Select task
    # other threads register open() and close() requests by adding lambdas
    # to this thread-safe queue.
    self._pending_commands = deque()

  def new_worker (self, *args, **kw):
    '''
    Return an IOWorker wrapping the given socket.

    You can create a specific worker type by specifying
    _worker_type.
    '''
    # Called from external threads.
    # Does not register the IOWorker immediately with the select loop --
    # rather, adds a command to the pending queue

    _worker_type = kw.pop("_worker_type", None)
    
    # Our callback for io_worker.close():
    def on_close (worker):
      def close_worker (worker):
        # Actually close the worker (called by Select loop)
        worker.socket.close()
        self._workers.discard(worker)
      # schedule close_worker to be called by Select loop
      self._pending_commands.append(lambda: close_worker(worker))
      self.pinger.ping()
    
    if _worker_type is None:
      _worker_type = self._worker_type
    assert issubclass(_worker_type, RecocoIOWorker)
    worker = _worker_type(pinger=self.pinger, on_close=on_close, *args, **kw)
    # Don't add immediately, since we're in the wrong thread
    self._pending_commands.append(lambda: self._workers.add(worker))
    self.pinger.ping()
    return worker
     
  def stop (self):
    self.running = False
    self.pinger.ping()

  def run (self):
    self.running = True

    while self.running and core.running:
      try:
        # First, execute pending commands
        while len(self._pending_commands) > 0:
          self._pending_commands.popleft()()

        # Now grab workers
        read_sockets = list(self._workers) + [ self.pinger ]
        write_sockets = [ worker for worker in self._workers
                          if worker._ready_to_send ]
        exception_sockets = list(self._workers)

        if self.more_debugging:
          log.debug("Select In : " + _format_lists(read_sockets,
              write_sockets, exception_sockets))

        rlist, wlist, elist = yield Select(read_sockets, write_sockets,
                exception_sockets, self._select_timeout)

        if self.more_debugging:
          log.debug("Select Out: " + _format_lists(rlist, wlist, elist))

        if self.pinger in rlist:
          self.pinger.pongAll()
          rlist.remove(self.pinger)

        for worker in elist:
          worker._do_exception(self)
          if worker in rlist:
            rlist.remove(worker)
          if worker in wlist:
            wlist.remove(worker)

        for worker in rlist:
          worker._do_recv(self)

        for worker in wlist:
          worker._do_send(self)

      except GeneratorExit:
        # Must be shutting down
        break
      except BaseException as e:
        log.exception(e)
        break
