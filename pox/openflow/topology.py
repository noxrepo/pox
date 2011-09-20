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

from pox.lib.revent.revent import *
import libopenflow_01 as of
from openflow import *
from pox.core import core
from pox.topology.topology import *
from pox.openflow.discovery import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import *


# After a switch disconnects, it has this many seconds to reconnect in
# order to reactivate the same OpenFlowSwitch object.  After this, if
# it reconnects, it will be a new switch object.
RECONNECT_TIMEOUT = 30

log = core.getLogger()


class OpenFlowTopology (EventMixin):
  """
  OpenFlow doesn't know anything about Topology, and Topology doesn't
  know anything about OpenFlow.  This class knows something about both,
  and hooks the two of them together
  """
  _wantComponents = set(['openflow','topology','openflow_discovery'])

  def _resolveComponents (self):
    if self._wantComponents == None or len(self._wantComponents) == 0:
      self._wantComponents = None
      return True
  
    got = set()
    for c in self._wantComponents:
      if core.hasComponent(c):
        setattr(self, c, getattr(core, c))
        self.listenTo(getattr(core, c), prefix=c)
        got.add(c)
      else:
        setattr(self, c, None)
    for c in got:
      self._wantComponents.remove(c)
    if len(self._wantComponents) == 0:
      self.wantComponents = None
      log.debug(self.__class__.__name__ + " ready")
      return True
    #log.debug(self.__class__.__name__ + " still wants: " + (', '.join(self._wantComponents)))
    return False

  def __init__ (self):
    super(EventMixin, self).__init__()
    if not self._resolveComponents():
      self.listenTo(core)
  
  def _handle_openflow_discovery_LinkEvent (self, event):
    if self.topology is None: return
    link = event.link
    sw1 = self.topology.getEntityByID(link.dpid1)
    sw2 = self.topology.getEntityByID(link.dpid2)
    if sw1 is None or sw2 is None: return
    if link.port1 not in sw1.ports or link.port2 not in sw2.ports: return
    if event.added:
      sw1.ports[link.port1].addEntity(sw2, single=True)
      sw2.ports[link.port2].addEntity(sw1, single=True)
    elif event.removed:
      sw1.ports[link.port1].entities.remove(sw2)
      sw2.ports[link.port2].entities.remove(sw1)

  def _handle_ComponentRegistered (self, event):
    if self._resolveComponents():
      return EventRemove

  def _handle_openflow_ConnectionUp (self, event):
    sw = self.topology.getEntityByID(event.dpid)
    add = False
    if sw is None:
      sw = OpenFlowSwitch(event.dpid)
      add = True
    else:
      if sw.connection is not None:
        log.warn("Switch %s connected, but... it's already connected!" %
                 (dpidToStr(event.dpid),))
    sw._setConnection(event.connection, event.ofp)
    log.info("Switch " + dpidToStr(event.dpid) + " connected")
    if add:
      self.topology.addEntity(sw)
      sw.raiseEvent(SwitchJoin, sw)

  def _handle_openflow_ConnectionDown (self, event):
    sw = self.topology.getEntityByID(event.dpid)
    if sw is None:
      log.warn("Switch %s disconnected, but... it doesn't exist!" %
               (dpidToStr(event.dpid),))
    else:
      if sw.connection is None:
        log.warn("Switch %s disconnected, but... it's wasn't connected!" %
                 (dpidToStr(event.dpid),))
      sw.connection = None
      log.info("Switch " + str(event.dpid) + " disconnected")


class OpenFlowPort (Port):
  def __init__ (self, ofp):
    # Passed an ofp_phy_port
    Port.__init__(self, ofp.port_no, ofp.hw_addr, ofp.name)
    self.isController = self.number == of.OFPP_CONTROLLER
    self._update(ofp)
    self.exists = True
    self.entities = set()

  def _update (self, ofp):
    assert self.name == ofp.name
    assert self.number == ofp.port_no
    self.hwAddr = EthAddr(ofp.hw_addr)
    self._config = ofp.config
    self._state = ofp.state

  def __contains__ (self, item):
    """ True if this port connects to the specified entity """
    return item in self.entities

  def addEntity (self, entity, single = False):
    if single:
      self.entities = set([entity])
    else:
      self.entities.add(entity)

  def __repr__ (self):
    return "<Port #" + str(self.number) + ">"

class OpenFlowSwitch (EventMixin, Switch):
  _eventMixin_events = set([
    SwitchJoin,
    SwitchLeave,

    PortStatus,
    FlowRemoved,
    PacketIn,
    BarrierIn,
  ])
  def __init__ (self, dpid):
    super(Switch, self).__init__(dpid)
    EventMixin.__init__(self)
    self.dpid = dpid
    self.ports = {}
    self.capabilities = 0
    self.connection = None
    self._listeners = []
    self._reconnectTimeout = None # Timer for reconnection

  def _setConnection (self, connection, ofp=None):
    if self.connection: self.connection.removeListeners(self._listeners)
    self._listeners = []
    self.connection = connection
    if self._reconnectTimeout is not None:
      self._reconnectTimeout.cancel()
      self._reconnectTimeout = None
    if connection is None:
      self._reconnectTimeout = Timer(RECONNECT_TIMEOUT, self._timer_ReconnectTimeout)
    if ofp is not None:
      self.capabilities = ofp.capabilities
      untouched = set(self.ports.keys())
      for p in ofp.ports:
        if p.port_no in self.ports:
          self.ports[p.port_no]._update(p)
          untouched.remove(p.port_no)
        else:
          self.ports[p.port_no] = OpenFlowPort(p)
      for p in untouched:
        self.ports[p].exists = False
        del self.ports[p]
    if connection is not None:
      self._listeners = self.listenTo(connection, prefix="con")

  def _timer_ReconnectTimeout (self):
    """ Called if we've been disconnected for RECONNECT_TIMEOUT seconds """
    self._reconnectTimeout = None
    core.topology.removeEntity(self)
    self.raiseEvent(SwitchLeave, self)

  def _handle_con_PortStatus (self, event):
    p = event.ofp.desc
    if event.ofp.reason == of.OFPPR_DELETE:
      if p.port_no in self.ports:
        self.ports[p.port_no].exists = False
        del self.ports[p.port_no]
    elif event.ofp.reason == of.OFPPR_MODIFY:
      self.ports[p.port_no]._update(p)
    else:
      assert event.ofp.reason == of.OFPPR_ADD
      assert p.port_no not in self.ports
      self.ports[p.port_no] = OpenFlowPort(p)
    self.raiseEvent(event)
    event.halt = False

  def _handle_con_ConnectionDown (self, event):
    self._setConnection(None)

  def _handle_con_PacketIn (self, event):
    self.raiseEvent(event)
    event.halt = False

  def _handle_con_BarrierIn (self, event):
    self.raiseEvent(event)
    event.halt = False

  def _handle_con_FlowRemoved (self, event):
    self.raiseEvent(event)
    event.halt = False

  def findPortForEntity (self, entity):
    for p in self.ports.itervalues():
      if entity in p:
        return p
    return None

  def __repr__ (self):
    return "<%s %s>" % (self.__class__.__name__, dpidToStr(self.dpid))

def launch ():
  if not core.hasComponent("openflow_topology"):
    core.register("openflow_topology", OpenFlowTopology())
