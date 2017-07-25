# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A collection of some useful IOWorkers

These were quickly adapted from another project.  The versions of the
server ones here haven't been tested.  The persistent ones at least
sort of have.  The backoff one is new.
"""

import errno
import socket
from pox.lib.addresses import IP_ANY, IPAddr
from pox.lib.ioworker import *
from pox.core import core

log = core.getLogger()


class LoggerBase (object):
  def _error (self, *args, **kw):
    log.error(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)
  def _warn (self, *args, **kw):
    log.warn(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)
  def _info (self, *args, **kw):
    log.info(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)
  def _debug (self, *args, **kw):
    log.debug(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)


class TCPServerWorkerBase (IOWorker, LoggerBase):
  def __init__ (self, ip = IP_ANY, port = None,
        backlog = 5, *args, **kw):
    """
    Listens on ip/port and fires _do_accept when there's a connection
    """
    #super(TCPServerWorkerBase,self).__init__(*args, **kw)
    IOWorker.__init__(self)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket = s
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #s.setblocking(0)
    if port is None: port = 0
    s.bind((str(IPAddr(ip)), port))
    s.listen(backlog)

  @property
  def local_ip (self):
    return IPAddr(s.getsockname()[0])
  @property
  def local_port (self):
    return s.getsockname()[1]

  def _do_accept (self, loop, socket):
    """
    Override me
    """
    pass

  def _do_recv (self, loop):
    s,addr = self.socket.accept()
    s.setblocking(0)

    self._do_accept(loop, s)

  def _handle_close (self):
    # Just here to kill log message
    pass


class TCPServerWorker (TCPServerWorkerBase):
  def __init__ (self, child_worker_type, ip = IP_ANY, port = None,
      child_args = {}, *args, **kw):
    """
    Listens on ip/port and creates a child_worker_type for each connnection
    """
    super(TCPServerWorker,self).__init__(ip=ip,port=port,*args, **kw)

    self.child_worker_type = child_worker_type
    self.child_args = child_args

  def _do_accept (self, loop, socket):
    addr = socket.getpeername()
    self._debug("accepting %s:%i" % addr)
    out = loop.new_worker(socket = socket,
        _worker_type = self.child_worker_type,
        **self.child_args)
    return out


class RecocoServerWorker (TCPServerWorker, RecocoIOWorker):
  """
  Recoco TCP server worker
  """
  pass


class PersistentIOWorker (RecocoIOWorker, LoggerBase):
  """
  An IOWorker which opens a duplicate of itself when it closes

  Subclasses can add keyword parameters for constructor
  """

  _default_retry_delay = 2

  def __repr__ (self):
    return object.__repr__(self)

  def __init__ (self, **kw):
    """
    Initialize

    See _make_connection for arg list.

    callbacks take a single arg -- the worker in question
    If the disconnect callback returns False, a new connection will NOT
    be opened.
    """
    #IOWorker.__init__(self)

    # We pass None in as the socket, because we set it up in a moment in
    # _make_connection().  This probably means that it shouldn't be
    # a required argument for RecocoIOWorker...
    super(PersistentIOWorker,self).__init__(None)

    self.kw = kw

    self._connecting = True

    self._make_connection(**kw)

  def _make_connection (self, loop, addr, port,
      reconnect_delay = _default_retry_delay,
      connect_callback = None, disconnect_callback = None, **kw):

    self.loop = loop
    self.addr = addr #IPAddr(addr)
    self.port = port
    self.reconnect_delay = reconnect_delay
    self.connect_callback = connect_callback
    self.disconnect_callback = disconnect_callback

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket = s
    s.setblocking(0)
    self._debug("Attempting to connect to %s:%s", self.addr, self.port)
    r = s.connect_ex((str(self.addr), self.port))
    if r in (0, errno.EINPROGRESS, errno.EAGAIN, 10035): # 10035=WSAEWOULDBLOCK
      # We either connected or connection is in progress
      pass
    else:
      #self._error("Couldn't connect to %s:%s", self.addr, self.port)
      #raise RuntimeError("Couldn't connect")
      core.callLater(self._handle_close)
      return

    self.loop.register_worker(self)

  @classmethod
  def begin (cls, **kw):
    #if len(args) >= 4:
    #  reconnect_delay = args[3]
    #else:
    reconnect_delay = kw.get('reconnect_delay',
        cls._default_retry_delay)

    try:
      w = cls(**kw)
      return w
    except:
      raise
      core.callDelayed(reconnect_delay, cls.begin, **kw)
      return None

  def open_later (self):
    core.callDelayed(self.reconnect_delay, self.begin, **self.kw)

  def _handle_close (self):
    self._debug("Disconnected")
    super(PersistentIOWorker, self)._handle_close()
    if self.disconnect_callback:
      if self.disconnect_callback(self) is False:
        return
    self.open_later()

  def _handle_connect (self):
    super(PersistentIOWorker, self)._handle_connect()
    if self.connect_callback:
      self.connect_callback(self)


class BackoffWorker (PersistentIOWorker):
  def __init__ (self, **kw):
    kw.setdefault('reconnect_delay', 0.5)
    self.max_retry_delay = kw.get('max_retry_delay',16)
    super(BackoffWorker,self).__init__(**kw)

  def _handle_connect (self):
    self.reconnect_delay = 0.5
    super(BackoffWorker, self)._handle_connect()

  def open_later (self):
    self.reconnect_delay *= 2
    self.reconnect_delay = int(self.reconnect_delay)
    if self.reconnect_delay > self.max_retry_delay:
      self.reconnect_delay = self.max_retry_delay
    self.kw['reconnect_delay'] = self.reconnect_delay
    self._debug("Try again in %s seconds", self.reconnect_delay)
    from pox.core import core
    core.callDelayed(self.reconnect_delay, self.begin, **self.kw)
