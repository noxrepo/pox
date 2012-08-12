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

from pox.core import core
from pox.messenger.messenger import *

class MessengerExample (object):
  """
  A demo of messenger.

  The idea is pretty simple. When you create a MessengerExample, you tell it a
  name you're interested in. It listens to core.messenger!MessageReceived. If
  it sees a message with a "hello" key where the value is the name you're
  interested in, it claims the connection that message came in on, and then
  listens to <thatConnection>!MessageReceived. It prints out messages on that
  connection from then on. If a message has a key named "bye" with the value
  True, it closes the connection

  To try it out, do the following in the POX interpreter:
  POX> import pox.messenger.messenger_example
  POX> pox.messenger.messenger_example.MessengerExample("foo")
  And then do the following from the commandline:
  bash$ echo '{"hello":"foo"}[1,2,3] "neat"' | nc localhost 7790
  """
  def __init__ (self, targetName):
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived, weak=True)
    self._targetName = targetName

  def _handle_global_MessageReceived (self, event, msg):
    try:
      n = msg['hello']
      if n == self._targetName:
        # It's for me!
        event.con.read() # Consume the message
        event.claim()
        event.con.addListener(MessageReceived, self._handle_MessageReceived, weak=True)
        print self._targetName, "- started conversation with", event.con
      else:
        print self._targetName, "- ignoring", n
    except:
      pass

  def _handle_MessageReceived (self, event, msg):
    if event.con.isReadable():
      r = event.con.read()
      print self._targetName, "-",r
      if type(r) is dict and r.get("bye",False):
        print self._targetName, "- GOODBYE!"
        event.con.close()
      if type(r) is dict and "echo" in r:
        event.con.send({"echo":r["echo"]})
    else:
      print self._targetName, "- conversation finished"

examples = {}
def launch (name = "example"):
  examples[name] = MessengerExample(name)
