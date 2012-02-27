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
Sometimes you'd like to be able to communicate with multiple messenger
services over the same connection.  You can use the mux messenger service
to do this.

If you send a "hello":"mux" message, the muxer will claim that connection.
Subsequent messages should include "_mux":<Key> pairs.  For each unique
Key, the muxer will create a new virtual connection -- subsequent messages
with the same "_mux":<Key> will be sent down that virtual connection, and
messages from that service will have the key tagged on.  Note this means
that messages to and from services you'd like muxed must be JSON objects
(dictionaries).  If this is a problem, let me know, because the muxer could
be extended.

An example:
(Assume we have created a MessengerExample("foo"))
-> {"hello":"mux"}
-> {"_mux":"logger1", "hello":"log"}
-> {"_mux":"logger2", "hello":"log"}
-> {"_mux":"logger1", "level":"ERROR"}
-> {"_mux":"bar", "hello":"foo"}
-> {"_mux":"bar", "echo":"hello world"}
<- {"_mux":"bar", "echo":"hello world"}

In this case, we have created two loggers, configured one of them
independent of the other, sent an echo request to a MessengerExample
object, and recieved the result.
"""

from pox.core import core
from pox.messenger.messenger import *

log = pox.core.getLogger()

class MuxConnection (MessengerConnection):
  def __init__ (self, source, channelName, con):
    MessengerConnection.__init__(self, source, ID=str(id(self)))
    self.channelName = channelName
    self.con = con

    claimed = False
    e = core.messenger.raiseEventNoErrors(ConnectionStarted, self)
    if e is not None:
      claimed = e._claimed

    if not claimed:
      # Unclaimed events get forwarded to here too
      self.addListener(MessageReceived, self._defaultMessageReceived, priority=-1) # Low priority

    self._newlines = False

  def send (self, whatever, **kw):
    whatever = dict(whatever)
    whatever['_mux'] = self.channelName
    print whatever
    MessengerConnection.send(self, whatever, **kw)

  def sendRaw (self, data):
    self.con.sendRaw(data)


class MuxSource (EventMixin):
  def __init__ (self, con):
    self.listenTo(con)
    self.channels = {}

  def _forget (self, connection):
    if connection in self.channels:
      del self.channels[connection.channelName]
    else:
      log.warn("Tried to forget a channel I didn't know")

  def _handle_MessageReceived (self, event, msg):
    if event.con.isReadable():
      r = event.con.read()
      if type(r) is dict:
        channelName = r.get("_mux", None)
        if channelName is not None:
          del r['_mux']
          if channelName not in self.channels:
            print self.__class__.__name__, "- creating channel", channelName
            # New channel
            channel = MuxConnection(self, channelName, event.con)
            self.channels[channelName] = channel
          else:
            channel = self.channels[channelName]
          channel._recv_msg(r)
        elif r.get("_mux_bye",False):
          event.con.close()
        else:
          log.warn("Message to demuxer didn't specify a channel or valid command")
      else:
        log.warn("Demuxer only handlers dictionaries")
    else:
      self._closeAll()

  def _handle_ConnectionClosed (self, event):
    self._closeAll()

  def _closeAll (self):
    channels = self.channels.values()
    for connection in channels:
      connection._close()


class MuxHub (object):
  """
  """
  def __init__ (self):
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived)#, weak=True)

  def _handle_global_MessageReceived (self, event, msg):
    try:
      if msg['hello'] == 'mux':
        # It's for me!
        event.claim()
        event.con.read()
        m = MuxSource(event.con)

        print self.__class__.__name__, "- started conversation with", event.con
    except:
      pass


def launch ():
  #  core.register("demux", MessengerHub())
  global hub
  hub = MuxHub()
