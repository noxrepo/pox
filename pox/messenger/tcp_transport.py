# Copyright 2011,2012 James McCauley
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
Active (connect) and passive (listen) TCP transports for messenger.
"""

from pox.lib.revent import *
from pox.lib.recoco import *
from pox.core import core
from pox.messenger import *
import errno

log = core.getLogger()


class TCPConnection (Connection, Task):
  def __init__ (self, transport, socket):
    self._socket = socket
    # Note: we cache name of the socket because socket.getpeername()
    # is unavailable after the socket was closed!
    self._socket_name = self._get_socket_name(socket)
    Connection.__init__(self, transport)
    Task.__init__(self)

    #self.start()
    self._send_welcome()

  def _close (self):
    super(TCPConnection, self)._close()
    try:
      self._socket.shutdown(socket.SHUT_RDWR)
    except:
      pass

  def send_raw (self, data):
    try:
      l = self._socket.send(data)
      if l == len(data): return
    except:
      pass
    #TODO: do something more graceful!
    self._close()

  def run (self):
    log.debug("%s started" % (self,))
    while self.is_connected:
      d = yield Recv(self._socket)
      if d is None or len(d) == 0:
        break
      #print "RECV", d
      self._rx_raw(d)
    self._close()
    log.debug("%s stopped" % (self,))

  def __str__ (self):
    s = "" + self.__class__.__name__ + " " + self._socket_name
    return s

  @staticmethod
  def _get_socket_name(socket):
    s = "%s:%i" % socket.getsockname()
    s += "/%s:%i" % socket.getpeername()
    return s


class ActiveTCPTransport (Task, Transport):
  """
  Opens a TCP connection to a (passive) TCPTransport

  This attempts to open a single connection, retrying forever.  When the
  connection closes, attempts to reopen it.
  """
  #TODO: Rewrite this to use IOWorker

  _timeout = 5 # Seconds to wait for connection

  def __init__ (self, address, port = 7790, nexus = None,
                connection_class = TCPConnection, max_backoff = 8):
    port = int(port)
    Task.__init__(self)
    Transport.__init__(self, nexus)
    self._addr = (str(address),port)
    self._connections = set()
    self._connection_class = connection_class
    self._max_backoff = max_backoff
    self.log = log or core.getLogger()

  def _forget (self, connection):
    """ Forget about a connection (because it has closed) """
    if connection in self._connections:
      #print "forget about",connection
      self._connections.remove(connection)
      if core.running:
        # Attempt to reopen!
        self.start()

  def run (self):
    while core.running:
      yield 0 # Make sure we always yield at least once

      delay = 1
      show_notices = True
      while core.running:
        #self.log.debug("Trying %s:%s...", self._addr[0], self._addr[1])

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        r = s.connect_ex(self._addr)

        if r == 0:
          #self._finish_connecting(s)
          break

        if r in (errno.EINPROGRESS,errno.EAGAIN,10035): #10035=WSAEWOULDBLOCK
          # Connection in progress...
          rr,ww,xx = yield Select([s], [s], [s], self._timeout)
          if not core.running: return
          if xx:
            # Bad news!
            pass
          elif rr or ww:
            try:
              s.recv(0)
              # Good news!
              #self._finish_connecting(s)
              break
            except:
              # Nope
              pass
          else:
            # Timeout -- bad news!
            pass

        else:
          # Connection failed
          pass

        delay *= 2
        if delay > self._max_backoff:
          delay = self._max_backoff
          if show_notices:
            self.log.debug("Connection to %s:%s failed.  Retrying in %s "
                "seconds.", self._addr[0], self._addr[1], delay)
            self.log.debug("(Further reconnect messages will be squelched.)")
          show_notices = False
        elif show_notices:
          self.log.debug("Connection to %s:%s failed.  Retrying in %s "
              "seconds.", self._addr[0], self._addr[1], delay)

        # Try again later...
        yield Sleep(delay)

      if not core.running: return

      self.log.info("Connected to %s:%i" % (self._addr))

      rc = self._connection_class(self, s)
      self._connections.add(rc)
      self._nexus.register_session(rc)
      rc.start()

      yield False # May be rescheduled later


class TCPTransport (Task, Transport):
  def __init__ (self, address = "0.0.0.0", port = 7790, nexus = None,
                connection_class = TCPConnection):
    port = int(port)
    Task.__init__(self)
    Transport.__init__(self, nexus)
    self._addr = (address,port)
    self._connections = set()
    self._connection_class = connection_class

  def _forget (self, connection):
    """ Forget about a connection (because it has closed) """
    if connection in self._connections:
      #print "forget about",connection
      self._connections.remove(connection)

  def run (self):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(self._addr)
    listener.listen(0)

    log.debug("Listening on %s:%i" % (self._addr))

    con = None
    while core.running:
      try:
        rlist, wlist, elist = yield Select([listener])
        if len(rlist) == 0:
          # Must have been interrupted
          break

        rc = self._connection_class(self, listener.accept()[0])
        self._connections.add(rc)
        self._nexus.register_session(rc)
        rc.start()
      except:
        traceback.print_exc()
        break

    try:
      listener.close()
    except:
      pass
    log.debug("No longer listening for connections")


def active (tcp_address, tcp_port = 7790):
  def start ():
    t = ActiveTCPTransport(tcp_address, tcp_port)
    t.start()
  core.call_when_ready(start, "MessengerNexus", __name__)


def launch (tcp_address = "0.0.0.0", tcp_port = 7790):
  def start ():
    t = TCPTransport(tcp_address, tcp_port)
    t.start()
  core.call_when_ready(start, "MessengerNexus", __name__)
