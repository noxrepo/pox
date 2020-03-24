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
The POX Messenger system.


The Messenger system is a way to build services in POX that can be
consumed by external clients.

Sometimes a controller might need to interact with the outside world.
Sometimes you need to integrate with an existing piece of software and
maybe you don't get to choose how you communicate with it.  Other times,
you have the opportunity and burden of rolling your own.  The Messenger
system is meant to help you with the latter case.

In short, channels are a system for communicating between POX and
external programs by exchanging messages encoded in JSON.  It is intended
to be quite general, both in the communication models it supports and in
the transports is supports (as of this writing, it supports a
straightforward TCP socket transport and an HTTP transport).  Any
service written to use the Messenger should theoretically be usable via
any transport.

*Connections* are somehow established when a client connects via some
*Transport*.  The server can individually send messages to a specific client.
A client can send messages to a *Channel* on the server.  A client can also
become a member of a channel, after which it will receive any messages
the server sends to that channel.  There is always a default channel with
no name.

Channels can either be permanent or temporary.  Temporary channels are
automatically destroyed when they no longer contain any members.
"""

from pox.lib.revent.revent import *
from pox.core import core as core
import json
import time
import random
import hashlib
from base64 import b32encode

log = core.getLogger()

# JSON decoder used by default
defaultDecoder = json.JSONDecoder()


class ChannelJoin (Event):
  """ Fired on a channel when a client joins. """
  def __init__ (self, connection, channel, msg = {}):
    self.con = connection
    self.channel = channel
    self.msg = msg

class ConnectionOpened (Event):
  """ Fired by the nexus for each new connection """
  def __init__ (self, connection):
    self.con = connection

class ConnectionClosed (Event):
  """ Fired on a connection when it closes. """
  def __init__ (self, connection):
    self.con = connection

class ChannelLeave (Event):
  """ Fired on a channel when a client leaves. """
  def __init__ (self, connection, channel):
    self.con = connection
    self.channel = channel

class ChannelCreate (Event):
  """ Fired on a Nexus when a channel is created. """
  def __init__ (self, channel):
    self.channel = channel

class ChannelDestroy (Event):
  """
  Fired on the channel and its Nexus right before a channel is destroyed.
  Set .keep = True to keep the channel after all.
  """
  def __init__ (self, channel):
    self.channel = channel
    self.keep = False

class ChannelDestroyed (Event):
  """
  Fired on the channel and its Nexus right after a channel is destroyed.
  """
  def __init__ (self, channel):
    self.channel = channel

class MissingChannel (Event):
  """
  Fired on a Nexus when a message has been received to a non-existant channel.
  You can create the channel in response to this.
  """
  def __init__ (self, connection, channel_name, msg):
    self.con = connection
    self.channel_name = channel_name
    self.msg = msg

class MessageReceived (Event):
  """
  Fired by a channel when a message has been receieved.

  Always fired on the Connection itself.  Also fired on the corresponding
  Channel object as specified by the CHANNEL key.

  The listener looks like:
  def _handle_MessageReceived (event, msg):
  """
  def __init__ (self, connection, channel, msg):
    self.con = connection
    self.msg = msg
    self.channel = channel

  def is_to_channel (self, channel):
    """
    Returns True if this message is to the given channel
    """
    if isinstance(channel, Channel):
      channel = channel.name
    if channel == self.channel: return True
    if channel in self.channel: return True
    return False

  def _invoke (self, handler, *args, **kw):
    # Special handling -- pass the message
    return handler(self, self.msg, *args, **kw)


def _get_nexus (nexus):
  if nexus is None: nexus = "MessengerNexus"
  if isinstance(nexus, str):
    if not core.hasComponent(nexus):
      #TODO: Wait for channel Nexus
      s = "MessengerNexus %s is not available" % (nexus,)
      log.error(s)
      raise RuntimeError(s)
    return getattr(core, nexus)
  assert isinstance(nexus, MessengerNexus), nexus
  return nexus


class Transport (object):
  def __init__ (self, nexus):
    self._nexus = _get_nexus(nexus)

  def _forget (self, connection):
    """ Forget about a connection """
    raise RuntimeError("Not implemented")


class Connection (EventMixin):
  """
  Superclass for Connections.

  This could actually be a bit thinner, if someone wants to clean it up.

  Maintains the state and handles message parsing and dispatch for a
  single connection.
  """
  _eventMixin_events = set([
    MessageReceived,
    ConnectionClosed,
  ])

  def __init__ (self, transport):
    """
    transport is the source of the connection (e.g, TCPTransport).
    """
    EventMixin.__init__(self)
    self._is_connected = True
    self._transport = transport
    self._newlines = False

    # If we connect to another messenger, this contains our session ID as far
    # as it is concerned.
    self._remote_session_id = None

    # Transports that don't do their own encapsulation can use _recv_raw(),
    # which uses this.  (Such should probably be broken into a subclass.)
    self._buf = bytes()

    key,num = self._transport._nexus.generate_session()
    self._session_id,self._session_num = key,num

  def _rx_welcome (self, event):
    """
    Called by the default channelbot if we connect to another messenger.
    """
    self._remote_session_id = event.msg.get('session_id')
    log.debug("%s welcomed as %s.", self, self._remote_session_id)

  def _send_welcome (self):
    """
    Send a message to a client so they know they're connected
    """
    self.send({"CHANNEL":"","cmd":"welcome","session_id":self._session_id})

  def _close (self):
    """
    Called internally to shut the connection down.
    """
    if self._is_connected is False: return
    self._transport._forget(self)
    self._is_connected = False
    for name,chan in list(self._transport._nexus._channels.items()):
      chan._remove_member(self)
    self.raiseEventNoErrors(ConnectionClosed, self)
    #self._transport._nexus.raiseEventNoErrors(ConnectionClosed, self)

  def send (self, whatever):
    """
    Send data over the connection.

    It will first be encoded into JSON, and optionally followed with
    a newline.  Ultimately, it will be passed to send_raw() to actually
    be sent.
    """
    if self._is_connected is False: return False
    s = json.dumps(whatever, default=str)
    if self._newlines: s += "\n"
    self.send_raw(s)
    return True

  def send_raw (self, data):
    """
    This method should actually send data out over the connection.

    Subclasses need to implement this.
    """
    raise RuntimeError("Not implemented")

  @property
  def is_connected (self):
    """
    True if this Connection is still connected.
    """
    return self._is_connected

  def _rx_message (self, msg):
    """
    Raises events when a complete message is available.

    Subclasses may want to call this when they have a new message
    available.  See _recv_raw().
    """
    e = self.raiseEventNoErrors(MessageReceived,self,msg.get('CHANNEL'),msg)
    self._transport._nexus._rx_message(self, msg)

  def _rx_raw (self, data):
    """
    If your subclass receives a stream instead of discrete messages, this
    method can parse out individual messages and call _recv_msg() when
    it has full messages.
    """
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
        # (.. or the stream is corrupt and things will never be okay
        # ever again)
        return

      self._buf = self._buf[l:]
      if len(self._buf) != 0 and self._buf[0].isspace():
        self._buf = self._buf.lstrip()
      self._rx_message(msg)

  def __str__ (self):
    """
    Subclasses should implement better versions of this.
    """
    return "<%s/%s/%i>" % (self.__class__.__name__, self._session_id,
                           self._session_num)

  def close (self):
    """
    Close the connection.
    """
    self._close()


class Channel (EventMixin):
  """
  Allows one to easily listen to only messages that have a CHANNEL key
  with a specific name.

  Generally you will not create these classes directly, but by calling
  getChannel() on the ChannelNexus.
  """
  _eventMixin_events = set([
    MessageReceived,
    ChannelJoin,          # Immedaitely when a connection goes up
    ChannelLeave,         # When a connection goes down
    ChannelDestroy,
    ChannelDestroyed,
  ])

  def __init__ (self, name, nexus = None, temporary = False):
    """
    name is the name for the channel (i.e., the value for the messages'
    CHANNEL key).
    nexus is the specific MessengerNexus with which this channel is to be
    associated (defaults to core.MessengerNexus).
    """
    EventMixin.__init__(self)
    assert isinstance(name, str)
    self._name = name

    self._nexus = _get_nexus(nexus)
    self._nexus._channels[name] = self

    self.temporary = temporary

    self._members = set() # Member Connections

  @property
  def name (self):
    return self._name

  def _destroy (self):
    """ Remove channel """
    e = self.raiseEvent(ChannelDestroy, self)
    if e:
      if e.keep: return False
      self._nexus.raiseEvent(e)
      if e.keep: return False

    del self._nexus._channels[self._name]

    # We can't just do the follow because then listeners
    # can't tell if the channel is now empty...
    #for sub in set(self._members):
    #  sub.raiseEvent(ChannelLeave, sub, self)
    #
    #self._members.clear()
    # .. so do the following really straightforward...
    for sub in set(self._members):
      self._remove_member(sub, allow_destroy = False)

    e = ChannelDestroyed(self)
    self.raiseEvent(e)
    self._nexus.raiseEvent(e)

  def _add_member (self, con, msg = {}):
    if con in self._members: return
    self._members.add(con)
    self.raiseEvent(ChannelJoin, con, self, msg)

  def _remove_member (self, con, allow_destroy = True):
    if con not in self._members: return
    self._members.remove(con)
    self.raiseEvent(ChannelLeave, con, self)

    if not allow_destroy: return

    if self.temporary is True:
      if len(self._members) == 0:
        self._destroy()

  def send (self, msg):
    d = dict(msg)
    d['CHANNEL'] = self._name
    for r in list(self._members):
      if not r.is_connected: continue
      r.send(d)

  def __str__ (self):
    return "<Channel " + self.name + ">"


def reply (_msg, **kw):
  if not isinstance(_msg, dict):
    # We'll also take an event...
    _msg = _msg.msg
  kw['CHANNEL'] = _msg.get('CHANNEL')
  if 'XID' in _msg: kw['XID'] = _msg.get('XID')
  return kw


class ChannelBot (object):
  """
  A very simple framework for writing "bots" that respond to messages
  on a channel.
  """

  def __str__ (self):
    return "<%s@%s>" % (self.__class__.__name__, self.channel)

  def __init__ (self, channel, nexus = None, weak = False, extra = {}):
    self._startup(channel, nexus, weak, extra)

  def _startup (self, channel, nexus = None, weak = False, extra = {}):
    self._nexus = _get_nexus(nexus)
    if isinstance(channel, Channel):
      self.channel = channel
    else:
      self.channel = self._nexus.get_channel(channel, create=True)
    self.listeners = self.channel.addListeners(self, weak = weak)
    self.prefixes = None

    self._init(extra)

    if self.prefixes is None:
      self.prefixes = []
      for n in dir(self):
        if n.startswith("_exec_"):
          n = n.split("_")[2]
          self.prefixes.append(n)

  def _handle_ChannelDestroyed (self, event):
    self.channel.removeListeners(self.listeners)
    self._destroyed()

  def _handle_ChannelJoin (self, event):
    self._join(event, event.con, event.msg)

  def _handle_ChannelLeave (self, event):
    self._leave(event.con, len(self.channel._members) == 0)

  def _handle_MessageReceived (self, event, msg):
    for prefix in self.prefixes:
      if prefix in event.msg:
        cmd = "_exec_%s_%s" % (prefix, str(event.msg[prefix]))
        if hasattr(self, cmd):
          getattr(self, cmd)(event)
          return #TODO: Return val?

    for prefix in self.prefixes:
      if prefix in event.msg:
        cmd = "_exec_" + prefix
        if hasattr(self, cmd):
          getattr(self, cmd)(event, msg[prefix])
          return #TODO: Return val?

    self._unhandled(event)

  def _unhandled (self, event):
    """ Called when no command found """
    pass

  def _join (self, event, connection, msg):
    """ Called when a connection joins """
    pass

  def _leave (self, connection, empty):
    """
    Called when a connection leaves

    If channel now has no members, empty is True
    """
    pass

  def _destroyed (self):
    """ Called when channel is destroyed """
    pass

  def _init (self, extra):
    """
    Called during initialization
    'extra' is any additional information passed in when initializing
    the bot.  In particular, this may be the message that goes along
    with its invitation into a channel.
    """
    pass

  def reply (__self, __event, **kw):
    """
    Unicast reply to a specific message.
    """
    __event.con.send(reply(__event, **kw))

  def send (__self, __msg={}, **kw):
    """
    Send a message to all members of this channel.
    """
    m = {}
    m.update(__msg)
    m.update(kw)
    __self.channel.send(m)


class DefaultChannelBot (ChannelBot):
  def _init (self, extra):
    self._bots = {}

  def add_bot (self, bot, name = None):
    """
    Registers a bot (an instance of ChannelBot) so that it can be
    invited to other channels.
    """
    assert issubclass(bot, ChannelBot)
    if name is None:
      name = bot.__name__
    self._bots[name] = bot

  def _exec_newlines_False (self, event):
    event.con._newlines = False

  def _exec_newlines_True (self, event):
    event.con._newlines = True

  def _exec_cmd_invite (self, event):
    """
    Invites a bot that has been registered with add_bot() to a channel.

    Note that you can invite a bot to an empty (new) temporary channel.
    It will stay until the first member leaves.
    """
    botname = event.msg.get('bot')
    botclass = self._bots.get(botname)
    channel = event.msg.get('channel')
    new_channel = False
    if channel is None:
      new_channel = True
      channel = self._gen_channel_name(event.msg.get("prefix", "temp"))

    chan = self._nexus.get_channel(channel, create=True, temporary=True)
    if chan is None:
      #TODO: send an error
      log.warning("A bot was invited to a nonexistent channel (%s)"
                  % (channel,))
      return
    if botclass is None:
      #TODO: send an error
      log.warning("A nonexistent bot (%s) was invited to a channel"
                  % (botname,))
      return
    bot = botclass(channel, self._nexus)
    if new_channel:
      self.reply(event, new_channel = new_channel)

  def _unhandled (self, event):
    log.warn("Default channel got unknown command: "
              + str(event.msg.get('cmd')))

  def _gen_channel_name (self, prefix = "temp"):
    """ Makes up a channel name """
    prefix += "_"
    import random
    while True:
      # Sloppy
      r = random.randint(1, 100000)
      n = prefix + str(r)
      if r not in self._nexus._channels:
        break
    return n

  def _exec_cmd_new_channel (self, event):
    """ Generates a new channel with random name """
    prefix = event.msg.get('prefix', 'temp')
    n = self._gen_channel_name(prefix)
    ch = self._nexus.get_channel(n, create=True, temporary=True)
    ch._add_member(event.con, event.msg)
    self.reply(event, new_channel = n)

  def _exec_cmd_join_channel (self, event):
    """ Joins/creates a channel """
    temp = event.msg.get('temporary', True) # Default temporary!
    ch = self._nexus.get_channel(event.msg['channel'], temporary=temp)
    if ch is None: return
    ch._add_member(event.con, event.msg)

  def _exec_cmd_leave_channel (self, event):
    ch = self._nexus.get_channel(event.msg['channel'])
    if ch is None: return
    ch._remove_member(event.con)

  def _exec_test (self, event, value):
    log.info("Default channel got: " + str(value))
    self.reply(event, test = value.upper())

  def _exec_cmd_welcome (self, event):
    # We get this if we're connecting to another messenger.
    event.con._rx_welcome(event)


class MessengerNexus (EventMixin):
  """
  Transports, Channels, etc. are all associated with a MessengerNexus.
  Typically, there is only one, and it is registered as
  pox.core.MessengerNexus
  """

  _eventMixin_events = set([
    MissingChannel,     # When a msg arrives to nonexistent channel
    ChannelDestroy,
    ChannelDestroyed,
    ChannelCreate,
    ConnectionOpened,
  ])

  def __init__ (self):
    EventMixin.__init__(self)
    self._channels = {} # name -> Channel
    self.default_bot = DefaultChannelBot("", self)
    self._next_ses = 1
    self._session_salt = str(time.time())

  def generate_session (self):
    """
    Return a new session ID tuple (key, num)

    The key is a unique and not-trivial-to-guess alphanumeric value
    associated with the session.
    The num is a unique numerical value associated with the session.
    """
    r = self._next_ses
    self._next_ses += 1

    key = str(random.random()) + str(time.time()) + str(r)
    key += str(id(key)) + self._session_salt
    key = key.encode()

    key = b32encode(hashlib.md5(key).digest()).upper().replace(b'=',b'')

    def alphahex (r):
      """ base 16 on digits 'a' through 'p' """
      r=hex(r)[2:].lower()
      return bytes(((10 if x >= 97 else 49) + x) for x in r)

    key = alphahex(r) + key

    return key,r

  def register_session (self, session):
    self.raiseEventNoErrors(ConnectionOpened, session)

  def get_channel (self, name, create = True, temporary = False):
    if name is None: name = ""
    if name in self._channels:
      return self._channels[name]
    elif create:
      c = Channel(name, self, temporary = temporary)
      self.raiseEvent(ChannelCreate, c)
      return c
    else:
      return None

  def _rx_message (self, con, msg):
    """
    Dispatches messages to listeners of this nexus and to its Channels.
    Called by Connections.
    """
    ret = False
    assert isinstance(msg, dict)
    if isinstance(msg, dict):
      channels = msg.get('CHANNEL')
      if channels is None:
        channels = [""]
      if not isinstance(channels, list):
        channels = [channels]
      for cname in channels:
        channel = self.get_channel(cname, create=False)
        if channel is None:
          e = self.raiseEvent(MissingChannel, con, cname, msg)
          if e is not None: cname = e.channel_name
          channel = self.get_channel(cname, create=False)
        if channel is not None:
          #print "raise on", channel
          channel.raiseEvent(MessageReceived, con, channel, msg)
          ret = True
    return ret



def launch ():
  core.registerNew(MessengerNexus)
