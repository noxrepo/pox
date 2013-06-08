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
Messenger can be used in many ways.  This shows a few of them.

Creates a channel called "time" which broadcasts the time.
Creates a channel called "chat" which relays messages to its members.
Listens for channels called "echo_..." and responds to message in them.
Listens for messages on a channel named "upper" and responds in upper case.
Creates a bot ("GreetBot") which can be invited to other channels.

Note that the echo and upper are really similar, but echo uses the channel
mechanism (e.g., clients join a channel), whereas upper keeps track of
members itself and clients are not expected to actually join the upper
channel -- it's just used like an address to send messages to.
This is just showing that there are multiple ways to go about doing things.
"""

from pox.core import core
from pox.messenger import *

log = core.getLogger()

class UpperService (object):
  def __init__ (self, parent, con, event):
    self.con = con
    self.parent = parent
    self.listeners = con.addListeners(self)
    self.count = 0

    # We only just added the listener, so dispatch the first
    # message manually.
    self._handle_MessageReceived(event, event.msg)

  def _handle_ConnectionClosed (self, event):
    self.con.removeListeners(self.listeners)
    self.parent.clients.pop(self.con, None)

  def _handle_MessageReceived (self, event, msg):
    self.count += 1
    self.con.send(reply(msg, count = self.count,
                        msg = str(msg.get('msg').upper())))


class UpperBot (ChannelBot):
  def _init (self, extra):
    self.clients = {}

  def _unhandled (self, event):
    connection = event.con
    if connection not in self.clients:
      self.clients[connection] = UpperService(self, connection, event)


class EchoBot (ChannelBot):
  count = 0
  def _exec_msg (self, event, value):
    self.count += 1
    self.reply(event, msg = "%i: %s" % (self.count, value))


class GreetBot (ChannelBot):
  def _join (self, event, connection, msg):
    from random import choice
    greet = choice(['hello','aloha','greeings','hi',"g'day"])
    greet += ", " + str(connection)
    self.send({'greeting':greet})


class MessengerExample (object):
  def __init__ (self):
    core.listen_to_dependencies(self)

  def _all_dependencies_met (self):
    # Set up the chat channel
    chat_channel = core.MessengerNexus.get_channel("chat")
    def handle_chat (event, msg):
      m = str(msg.get("msg"))
      chat_channel.send({"msg":str(event.con) + " says " + m})
    chat_channel.addListener(MessageReceived, handle_chat)

    # Set up the time channel...
    time_channel = core.MessengerNexus.get_channel("time")
    import time
    def timer ():
      time_channel.send({'msg':"It's " + time.strftime("%I:%M:%S %p")})
    from pox.lib.recoco import Timer
    Timer(10, timer, recurring=True)

    # Set up the "upper" service
    UpperBot(core.MessengerNexus.get_channel("upper"))

    # Make GreetBot invitable to other channels using "invite"
    core.MessengerNexus.default_bot.add_bot(GreetBot)

  def _handle_MessengerNexus_ChannelCreate (self, event):
    if event.channel.name.startswith("echo_"):
      # Ah, it's a new echo channel -- put in an EchoBot
      EchoBot(event.channel)


def launch ():
  MessengerExample()
