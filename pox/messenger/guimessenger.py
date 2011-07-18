"""
Messenger works like this:

Somehow a connection to a client is started.  pox.messenger raises a
MessengerConnectEvent event.  If a listener wants the connection, it can call .claim()
on the event, which returns a Connection.
"""


#from pox.lib.revent.revent import *
#from pox.lib.recoco.recoco import *
#import pox.core
from pox.core import core as core
from pox.messenger.messenger import MessageRecieved
#import weakref
import json

log = core.getLogger()

class GuiMessenger (object):
  def __init__ (self):
    core.messenger.addListener(MessageRecieved, self._handle_global_MessageRecieved)
    self._targetName = "gui"
    log.info("Up!")

  def _handle_global_MessageRecieved (self, event):
    try:
      n = event.con.read()['hello']
      if n == self._targetName:
        # It's for me!
        event.claim()
        event.con.addListener(MessageRecieved, self._handle_MessageRecieved)
        log.info(self._targetName + " - started conversation with GUI")
    except:
      pass

  def _handle_MessageRecieved (self, event):
    if event.con.isReadable():
      r = event.con.read()
      log.info(self._targetName + " - " + str(r))
      if type(r) is dict:
        if r.get("bye",False):
          log.info(self._targetName + " - GOODBYE!")
          event.con.close()
        else:
          # Dispatch message
          if r["type"] == "lavi":
              log.info("got lavi")
          elif r["type"] == "monitoring":
              log.info("got monitoring")
          elif r["type"] == "spanning_tree":
              log.info("got spanning_tree")
          elif r["type"] == "sample_routing":
              log.info("got sample_routing")
          elif r["type"] == "flowtracer":
              log.info("got flowtracer")        
    else:
      log.info(self._targetName + " - conversation finished")
      

class GuiLogMessenger (object):
  def __init__ (self):
    core.messenger.addListener(MessageRecieved, self._handle_global_MessageRecieved)
    self._targetName = "guilog"
    print "guilogmessengerup!"

  def _handle_global_MessageRecieved (self, event):
    try:
      n = event.con.read()['hello']
      if n == self._targetName:
        # It's for me!
        event.claim()
        event.con.addListener(MessageRecieved, self._handle_MessageRecieved)
        log.info(self._targetName + " - started conversation with GUI log")
    except:
      pass

  def _handle_MessageRecieved (self, event):
    if event.con.isReadable():
      r = event.con.read()
      log.info(self._targetName + " - " + str(r))
      if type(r) is dict:
        if r.get("bye",False):
          log.info(self._targetName + " - GOODBYE!")
          event.con.close()
        else:
          # Dispatch message
          pass
    else:
      log.info(self._targetName + " - conversation finished")