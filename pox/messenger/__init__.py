# Copyright 2011 James McCauley
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
The POX Messenger system.


The Messenger is a way to build services in POX that can be consumed by
external clients.

Sometimes a controller might need to interact with the outside world.
Sometimes you need to integrate with an existing piece of software and
maybe you don't get to choose how you communicate with it.  Other times,
you have the opportunity and burden of rolling your own.  The Messenger
is meant to help you with the latter case.

In short, the POX Messenger is a system for communicating between NOX and
external programs by exchanging messages encoded in JSON.  It is intended
to be quite general, and supports multiple communication models (for
example, you can use it for pub/sub, virtual circuits, broadcasts...).
It is also transport-independent (as of this writing, it supports a
straightforward TCP socket transport and an HTTP transport).

*Connections* are somehow established when a client connects via some
*Transport*, and this causes a ConnectionStarted event on MessengerHub.
Messages sent by the client at this point raise a MessageReceived event
on MessengerHub, and a disconnection will raise ConnectionClosed.  A
listener of ConnectionStarted or MessageReceived messages may use the
Connection's send() method to send a message back to the client, or may
store the Connection to send() a reply later (e.g., to implement a pubsub
communication model).

Incoming messages are often intended to be received only be specific
services.  To make this happen, a service can create a Target object
specifying name for the target, and then listen to events on this
specific Target object (e.g., MessageReceived, ConnectionClosed).
Then clients can include a TARGET key in their messages with the
value set to be the target name (or a list of target names, or null to
broadcast through MessengerHub).  Messages which have specified an
available TARGET will only appear as messages on the corresponding Target
object -- not on MessengerHub itself.  Messages with a TARGET that is
not available will continue to show up on MessengerHub.

There are also times when a service would like to do a lot communication
with a client over a specific connection.  In this case, the service can
"claim" a connection (via the .claim() method of the event) and listen
to it directly.  After being claimed, the connection will no longer
raise events on the MessengerHub.  This allows for connection-oriented
communication patterns.

Generally, listeners will listen to MessageReceived events and respond
to those.  However, it is also possible to set a connection to buffer
the messages it receives, and it can be polled later.
"""


from pox.lib.revent import *
from pox.lib.recoco import *
import pox.core
from pox.core import core as core

try:
  from weakref import WeakSet
except:
  # python 2.6 compatibility
  from weakrefset import WeakSet
import json

log = pox.core.getLogger()

# JSON decoder used by default
defaultDecoder = json.JSONDecoder()

class MessengerListening(Event):
  pass

class ConnectionClosed (Event):
  def __init__ (self, connection):
    Event.__init__(self)
    self.con = connection

class MessengerListening(Event):
  pass

class ConnectionStarted (Event):
  def __init__ (self, connection):
    Event.__init__(self)
    self.con = connection
    self._claimed = False

  def claim (self):
    #assert self._claimed == False
    self._claimed = True
    self.halt = True
    return self.con


class MessageReceived (Event):
  def __init__ (self, connection, msg):
    Event.__init__(self)
    self.con = connection
    self._claimed = False
    self.msg = msg

  def claim (self):
    assert self._claimed == False
    self._claimed = True
    self.halt = True
    return self.con

  def _invoke (self, handler, *args, **kw):
    # Special handling.  If the handler doesn't return any disposition, then
    # we look to see if they read the message.  If so, we stop processing
    # this event now.
    l = len(self.con._msgs) # Sleazy
    r = handler(self, self.msg, *args, **kw)
    if r is not None:
      return r
    if len(self.con._msgs) < l:
      # Looks like they read it.  Stop processing.
      return EventHalt


class Target (object):
  pass
  #TODO


class MessengerConnection (EventMixin):
  _eventMixin_events = set([
    MessageReceived,
    ConnectionClosed,
  ])

  ID = "INVALID ID"

  def __init__ (self, source=None, ID = None):
    EventMixin.__init__(self)
    self._isConnected = True
    self._buf = bytes()
    self._msgs = []
    self._source = source
    self._newlines = False
    self.buffered = False
    if ID is not None:
      self.ID = ID

    claimed = False
    e = core.messenger.raiseEventNoErrors(ConnectionStarted, self)
    if e is not None:
      claimed = e._claimed

    if not claimed:
      # Unclaimed events get forwarded to here too
      self.addListener(MessageReceived, self._defaultMessageReceived, priority=-1) # Low priority

  def _close (self):
    # Called internally
    if self._isConnected is False: return
    if self._source:
      self._source._forget(self)
    self._isConnected = False
    self.raiseEventNoErrors(ConnectionClosed, self)
    self.raiseEventNoErrors(MessageReceived, self, None)
    core.messenger.raiseEventNoErrors(ConnectionClosed, self)

  def send (self, whatever, **kw):
    if self._isConnected is False: return False
    s = json.dumps(whatever, **kw)
    if self._newlines: s += "\n"
    self.sendRaw(s)
    return True

  def sendRaw (self, data):
    raise RuntimeError("Not implemented")

  def isConnected (self):
    return self._isConnected

  def isReadable (self):
    return len(self._msgs) > 0

  def peek (self, default = None):
    return self.read(default = default, peek=True)

  def read (self, default = None, peek = False):
    if len(self._msgs) == 0: return default
    if peek:
      return self._msgs[0]
    else:
      return self._msgs.pop(0)

  def _recv_msg (self, msg):
    #print self,"recv:",msg
    self._msgs.append(msg)
    self.raiseEventNoErrors(MessageReceived, self, msg)
    if not self.buffered:
      del self._msgs[:]

  def _recv_raw (self, data):
    if len(data) == 0: return
    if len(self._buf) == 0:
      if data[0].isspace():
        self._buf = data.lstrip()
      else:
        self._buf = data
    else:
      self._buf += data

    while len(self._buf) > 0:
      try:
        msg, l = defaultDecoder.raw_decode(self._buf)
      except:
        # Need more data before it's a valid message
        # (.. or the stream is corrupt and things will never be okay ever again)
        return

      self._buf = self._buf[l:]
      if len(self._buf) != 0 and self._buf[0].isspace():
        self._buf = self._buf.lstrip()
      self._recv_msg(msg)

  def __str__ (self):
    # Subclasses probably want to change this
    return "<" + self.__class__.__name__ + "/" + self.ID + ">"

  def _defaultMessageReceived (self, event, msg):
    #print self,"default recv:",msg
    #TODO: make sure this actually works. I have never tried re-raising an event.
    core.messenger.raiseEventNoErrors(event)
    if event._claimed:
      # Someone claimed this connection -- stop forwarding it globally
      return EventRemove

  def close (self):
    self._close()


class TCPMessengerConnection (MessengerConnection, Task):
  def __init__ (self, source=None, socket=None):
    self._socket = socket
    MessengerConnection.__init__(self, source, ID=str(id(self))) #TODO: better ID
    Task.__init__(self)

    #self.start()

  def _close (self):
    super(TCPMessengerConnection, self)._close()
    try:
      self._socket.shutdown(socket.SHUT_RDWR)
    except:
      pass

  def sendRaw (self, data):
    try:
      l = self._socket.send(data)
      if l == len(data): return
    except:
      pass
    #TODO: do something more graceful!
    self._close()

  def run (self):
    log.debug("%s started" % (self,))
    while self.isConnected():
      d = yield Recv(self._socket)
      if d is None or len(d) == 0:
        break
      self._recv_raw(d)
    self._close()
    log.debug("%s stopped" % (self,))

  #TODO: __str__ with port numbers, etc

#TODO: a queued listener base class (like for HTTP)


class MessengerHub (EventMixin):
  _eventMixin_events = set([
    ConnectionStarted,  # Immediately when a connection goes up
    ConnectionClosed,   # When a connection goes down
    MessageReceived,    # For unclaimed messages
    MessengerListening, # The TCP listening port is up
  ])
  def __init__ (self):
    EventMixin.__init__(self)
    self.connections = WeakSet()


#TODO: make a superclass source
class TCPMessengerSource (Task):
  def __init__ (self, address = "0.0.0.0", port = 7790):
    port = int(port)
    Task.__init__(self)
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

    log.debug("Listening for connections on %s:%i" % (self._addr))
    core.messenger.raiseEventNoErrors(MessengerListening())

    con = None
    while core.running:
      try:
        rlist, wlist, elist = yield Select([listener])
        if len(rlist) == 0:
          # Must have been interrupted
          break

        rc = TCPMessengerConnection(self, listener.accept()[0])
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


def launch (tcp_address = "0.0.0.0", tcp_port = 7790):
  core.register("messenger", MessengerHub())
  t = TCPMessengerSource(tcp_address, tcp_port)
  core.addListener(pox.core.GoingUpEvent, lambda event: t.start())
