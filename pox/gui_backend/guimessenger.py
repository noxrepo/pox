# Copyright 2011 James McCauley
# Copyright 2011 Kyriakos Zarifis
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

#from pox.lib.revent.revent import *
#from pox.lib.recoco.recoco import *
from pox.core import core as core
from pox.messenger.messenger import MessageReceived
#import weakref
import json

log = core.getLogger()


from pox.core import core
from pox.messenger.messenger import *
from pox.lib.revent.revent import *
import traceback

from pox.log_messenger.log_messenger import LogMessenger

log = core.getLogger()

class GuiMessengerService (EventMixin):
  def __init__ (self, connection, params):
    self.connection = connection
    connection._newlines = params.get("newlines", True) == True #HACK

    # Make LogMessenger always send back "source":"logger"
    params['opaque'] = {'type':'log'}
    self._logService = LogMessenger(connection, params) # Aggregate
    # Unhook its message received listener (we will pass it those events
    # manually ourselves...)
    connection.removeListener(dict(self._logService._listeners)[MessageReceived])

    self.listenTo(connection)

  def _handle_MessageReceived (self, event, msg):
    if event.con.isReadable():
      r = event.con.read()
      if type(r) is dict:
        if "bye" in r:
          event.con.close()
        else:
          if "type" in r:
            # Dispatch message
            if r["type"] == "topology":
              pass
            elif r["type"] == "monitoring":
              pass
            elif r["type"] == "spanning_tree":
              pass
            elif r["type"] == "sample_routing":
              pass
            elif r["type"] == "flowtracer":
              pass
            elif r["type"] == "log":
              self._logService._processParameters(r)
            else:
              log.warn("Unknown type for message: %s", r)
          else:
            log.warn("Missing type for message: %s", r)
 

class GuiMessengerServiceListener (object):
  def __init__ (self):
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived)

  def _handle_global_MessageReceived (self, event, msg):
    try:
      if msg['hello'] == 'gui':
        # It's for me!
        try:
          GuiMessengerService(event.con, msg)
          event.claim()
          return True
        except:
          traceback.print_exc()
    except:
      pass


def launch ():
  def realStart (event=None):
    if not core.hasComponent("messenger"):
      if event is None:
        # Only do this the first time
        log.warning("Deferring firing up GuiMessengerServiceListener because Messenger isn't up yet")
        core.addListenerByName("ComponentRegistered", realStart, once=True)
      return
    if not core.hasComponent(GuiMessengerServiceListener.__name__):
      core.registerNew(GuiMessengerServiceListener)
      log.info("Up...")

  realStart()
