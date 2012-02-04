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

"""
This is the communication interface between POX and the GUI.
The gui backend component acts as a proxy between other components and the GUI.

GUI --> POX component:
If we want to trigger component functionality through the GUI, the component
must exposes that functionality through its API. The "backend" should just call
that API when ith gets input from the GUI (for example, think monitoring).

POX component --> GUI
If the component wants to send something to the GUI, it just raises events.
The backend listens to those events and packs them up and sends them to the GUI.

Note: log messages are treated separately, and use their own communication
channel
"""

from pox.core import core
from pox.messenger.messenger import *
from pox.lib.revent import *
from pox.messenger.messenger import MessageReceived
import json
import traceback

log = core.getLogger()

"""
from pox.messenger.log_service import LogMessenger
"""

class MonitoringEvent (Event):
  def __init__ (self, msg):
    Event.__init__(self)
    self.msg = msg

class GuiMessengerService (EventMixin):
  
  _eventMixin_events = set([
    MonitoringEvent
    ])
  
  _core_name = "guimessenger"
  
  _wantComponents = set(['topology', 'openflow_discovery'])
  def __init__ (self, connection, params):
    core.listenToDependencies(self, self._wantComponents)
    self.addListeners(core.monitoring, prefix = "guimessenger")
    self.connection = connection
    """
    connection._newlines = params.get("newlines", True) == True #HACK
    
    # Make LogMessenger always send back "source":"logger"
    params['opaque'] = {'type':'log'}
    self._logService = LogMessenger(connection, params) # Aggregate
    # Unhook its message received listener (we will pass it those events
    # manually ourselves...)
    connection.removeListener(dict(self._logService._listeners)[MessageReceived])
    """
    self.listenTo(connection)
    
  def _handle_topology_SwitchJoin(self, event):
    msg = {}
    msg["type"] = "topology"
    msg["command"] = "add"
    msg["node_id"] = [event.switch.id]
    msg["node_type"] = "switch"
    self.connection.send(msg)
    
  def _handle_topology_HostJoin(self, event):
    msg = {}
    msg["type"] = "topology"
    msg["command"] = "add"
    msg["node_id"] = [event.host.id]
    msg["node_type"] = "host"
    self.connection.send(msg)
    
  def _handle_openflow_discovery_LinkEvent (self, event):
    msg = {}
    msg["type"] = "topology"
    msg["command"] = "add"
    msg["links"] = [{"src id":event.link.dpid1, "src port":event.link.port1,\
                    "dst id":event.link.dpid2, "dst port":event.link.port2 }]
    msg["node_type"] = "host"
    self.connection.send(msg)

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
              self.raiseEvent(MonitoringEvent(msg))
            elif r["type"] == "spanning_tree":
              pass
            elif r["type"] == "sample_routing":
              pass
            elif r["type"] == "flowtracer":
              pass
            elif r["type"] == "log":
              pass
              #self._logService._processParameters(r)
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
