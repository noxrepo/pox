# Copyright 2011,2012 James McCauley
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

from pox.lib.revent.revent import *
from pox.core import core as core
from pox.messenger import *

log = core.getLogger()

from pox.lib.recoco.recoco import *

class TCPTransport (Task, Transport):
  def __init__ (self, address = "0.0.0.0", port = 7790, nexus = None):
    port = int(port)
    Task.__init__(self)
    Transport.__init__(self, nexus)
    self._addr = (address,port)
    self._connections = set()

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

        rc = TCPConnection(self, listener.accept()[0])
        self._connections.add(rc)
        rc.start()
      except:
        traceback.print_exc()
        break

    try:
      listener.close()
    except:
      pass
    log.debug("No longer listening for connections")


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


import pox.core

def launch (tcp_address = "0.0.0.0", tcp_port = 7790):
  def start ():
    t = TCPTransport(tcp_address, tcp_port)
    t.start()
  core.call_when_ready(start, "MessengerNexus", __name__)
