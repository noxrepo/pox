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

from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
log = core.getLogger()

class Monitoring (EventMixin):
  
  _core_name = "monitoring"  
    
  _wantComponents = set(['guimessenger', 'topology'])
  def __init__ (self):
    core.listenToDependencies(self, self._wantComponents)
    
    pending_xids = set()
      
  def _handle_guimessenger_MonitoringEvent(self, event):
    #if event.xid in pending_gui_requests:
    print event.__dict__
    if "dpid" in event.msg:
      dpid = event.msg["dpid"]
      log.debug("Requesting stats from %s" %dpid)
      if event.msg["command"] == "flowstats":
        msg = of.ofp_flow_stats_request()
        core.openflow.sendToDPID(dpid, msg.pack())
      elif event.msg["command"] == "portsstats":
        pass
      elif event.msg["command"] == "tabletats":
        pass
      elif event.msg["command"] == "queuestats":
        pass
      elif event.msg["command"] == "aggregatestats":
        pass
      elif event.msg["command"] == "latestsnapshot":
        pass
      else:
        log.debug("Got unknown command from GUI")
      #self.connection.send(msg)
    
def launch ():
  if not core.hasComponent("monitoring"):
      core.registerNew(Monitoring)