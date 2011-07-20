"""
Messenger works like this:

Somehow a connection to a client is started.  pox.messenger raises a
MessengerConnectEvent event.  If a listener wants the connection, it can call .claim()
on the event, which returns a Connection.
"""


from pox.lib.revent.revent import *
from pox.lib.recoco.recoco import *
import pox.core
from pox.core import core as core
import weakref
import json

log = pox.core.getLogger()

# JSON decoder used by default
defaultDecoder = json.JSONDecoder()


class ConnectionClosed (Event):
  def __init__ (self, connection):
    Event.__init__(self)
    self.con = connection


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


class MessageRecieved (Event):
  def __init__ (self, connection):
    Event.__init__(self)
    self.con = connection
    self._claimed = False

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
    r = handler(self, *args, **kw)
    if r is not None:
      return r
    if len(self.con._msgs) < l:
      # Looks like they read it.  Stop processing.
      return EventHalt


class MessengerConnection (EventMixin):
  _eventMixin_events = set([
    MessageRecieved,
    ConnectionClosed,
  ])

  ID = "INVALID ID"

  def __init__ (self, source, ID = None):
    EventMixin.__init__(self)
    self._isConnected = True
    self._buf = bytes()
    self._msgs = []
    self._source = source
    if ID is not None:
      self.ID = ID

  def _close (self):
    # Called internally
    if self._isConnected is False: return
    self._source._forget(self)
    self._isConnected = False
    self.raiseEventNoErrors(ConnectionClosed, self)
    self.raiseEventNoErrors(MessageRecieved, self)

  def send (self, whatever, **kw):
    self.sendRaw(json.dumps(whatever, **kw))

  def sendRaw (self, data):
    raise RuntimeError("Not implemented")

  def isConnected (self):
    return self._isConnected

  def isReadable (self):
    return len(self._msgs) > 0

  def read (self, default = None, peek = False):
    if len(self._msgs) == 0: return default
    if peek:
      return self._msgs[0]
    else:
      return self._msgs.pop(0)

  def _recv_msg (self, msg):
    #print self,"recv:",msg
    self._msgs.append(msg)
    self.raiseEventNoErrors(MessageRecieved, self)

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


class TCPMessengerConnection (MessengerConnection, Task):
  def __init__ (self, source, socket):
    MessengerConnection.__init__(self, source, ID=str(id(self))) #TODO: better ID
    Task.__init__(self)

    claimed = False
    e = core.messenger.raiseEventNoErrors(ConnectionStarted, self)
    if e is not None:
      claimed = e._claimed

    if not claimed:
      # Unclaimed events get forwarded to here too
      self.addListener(MessageRecieved, self._defaultMessageRecieved, priority=-1) # Low priority

    #self.start()

    self._socket = socket

    self._newlines = False

  def close (self):
    self._close()

  def _close (self):
    super(TCPMessengerConnection, self)._close()
    self._socket.shutdown(socket.SHUT_RDWR)

  def _defaultMessageRecieved (self, event):
    #TODO: move to base class?
    #TODO: make sure this actually works. I have never tried re-raising an event.
    core.messenger.raiseEventNoErrors(event)
    if event._claimed:
      # Someone claimed this connection -- stop forwarding it globally
      return EventRemove

  def send (self, whatever, **kw):
    """ Overridden because we may insert newlines """
    s = json.dumps(whatever, **kw)
    if self._newlines: s += "\n"
    self.sendRaw(s)

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
    MessageRecieved,    # For unclaimed messages
  ])
  def __init__ (self):
    EventMixin.__init__(self)
    self.connections = weakref.WeakSet()

#TODO: make a superclass source
class TCPMessengerSource (Task):
  def __init__ (self, address = "0.0.0.0", port = 7790):
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

    log.debug("Listening for connections")

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


def start ():
  core.register("messenger", MessengerHub())
  t = TCPMessengerSource()
  core.addListener(pox.core.GoingUpEvent, lambda event: t.start())
