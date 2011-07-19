from pox.core import core
from pox.messenger.messenger import *

class MessengerExample (object):
  """
  A demo of messenger.

  The idea is pretty simple. When you create a MessengerExample, you tell it a
  name you're interested in. It listens to core.messenger!MessageRecieved. If
  it sees a message with a "hello" key where the value is the name you're
  interested in, it claims the connection that message came in on, and then
  listens to <thatConnection>!MessageRecieved. It prints out messages on that
  connection from then on. If a message has a key named "bye" with the value
  True, it closes the connection

  To try it out, do the following in the POX interpreter:
  POX> pox.messenger.messenger.MessengerExample("foo")
  And then do the following from the commandline:
  bash$ echo '{"hello":"foo"}[1,2,3] "neat"' | nc localhost 7790
  """
  def __init__ (self, targetName):
    core.messenger.addListener(MessageRecieved, self._handle_global_MessageRecieved, weak=True)
    self._targetName = targetName

  def _handle_global_MessageRecieved (self, event):
    try:
      n = event.con.read()['hello']
      if n == self._targetName:
        # It's for me!
        event.claim()
        event.con.addListener(MessageRecieved, self._handle_MessageRecieved, weak=True)
        print self._targetName, "- started conversation with", event.con
      else:
        print self._targetName, "- ignoring", n
    except:
      pass

  def _handle_MessageRecieved (self, event):
    if event.con.isReadable():
      r = event.con.read()
      print self._targetName, "-",r
      if type(r) is dict and r.get("bye",False):
        print self._targetName, "- GOODBYE!"
        event.con.close()
    else:
      print self._targetName, "- conversation finished"

