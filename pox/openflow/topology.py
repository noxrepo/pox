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
OpenFlow doesn't know anything about Topology, and Topology doesn't
know anything about OpenFlow.  This module knows something about both,
and hooks the two of them together.

Specifically, this module is somewhat like an adapter that listens to
events from other parts of the openflow substem (such as discovery), and
uses them to populate and manipulate Topology.
"""

import itertools

from pox.lib.revent.revent import *
import libopenflow_01 as of
from pox.openflow import *
from pox.core import core
from pox.topology.topology import *
from pox.openflow.discovery import *
from pox.openflow.libopenflow_01 import xid_generator
from pox.openflow.flow_table import NOMFlowTable
from pox.lib.util import dpidToStr
from pox.lib.addresses import *

import pickle
import itertools

# After a switch disconnects, it has this many seconds to reconnect in
# order to reactivate the same OpenFlowSwitch object.  After this, if
# it reconnects, it will be a new switch object.
RECONNECT_TIMEOUT = 30

log = core.getLogger()

class OpenFlowTopology (EventMixin):
  """
  Listens to various OpenFlow-specific events and uses those to manipulate
  Topology accordingly.
  """
  
  # Won't boot up OpenFlowTopology until all of these components are loaded
  # into pox.core. Note though that these components won't be loaded
  # proactively; they must be specified on the command line (with the
  # exception of openflow which usally loads automatically)
  _wantComponents = set(['openflow','topology','openflow_discovery'])

  def __init__ (self):
    """ Note that self.topology is initialized in _resolveComponents """
    super(EventMixin, self).__init__()
    if not core.listenToDependencies(self, self._wantComponents):
      self.listenTo(core)
  
  def _handle_openflow_discovery_LinkEvent (self, event):
    """
    The discovery module simply sends out LLDP packets, and triggers LinkEvents
    for discovered switches. It's our job to take these LinkEvents and update
    pox.topology.
    """
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
      sw1.ports[link.port1].entities.discard(sw2)
      sw2.ports[link.port2].entities.discard(sw1)

  def _handle_ComponentRegistered (self, event):
    """
    A component was registered with pox.core. If we were dependent on it, 
    check again if all of our dependencies are now satisfied so we can boot.
    """
    if core.listenToDependencies(self, self._wantComponents):
      return EventRemove

  def _handle_openflow_ConnectionUp (self, event):
    sw = self.topology.getEntityByID(event.dpid)
    add = False
    if sw is None:
      sw = OpenFlowSwitch(event.dpid)
      add = True
    else:
      if sw._connection is not None:
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
      if sw._connection is None:
        log.warn("Switch %s disconnected, but... it's wasn't connected!" %
                 (dpidToStr(event.dpid),))
      sw._connection = None
      log.info("Switch " + str(event.dpid) + " disconnected")


class OpenFlowPort (Port):
  """
  A subclass of topology.Port for OpenFlow switch ports.
  
  Adds the notion of "connected entities", which the default
  ofp_phy_port class does not have.

  Note: Not presently used.
  """
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
    # Invariant (not currently enforced?): 
    #   len(self.entities) <= 2  ?
    if single:
      self.entities = set([entity])
    else:
      self.entities.add(entity)

  def to_ofp_phy_port(self):
    return of.ofp_phy_port(port_no = self.number, hw_addr = self.hwAddr,
                           name = self.name, config = self._config, 
                           state = self._state)

  def __repr__ (self):
    return "<Port #" + str(self.number) + ">"

class OpenFlowSwitch (EventMixin, Switch):
  """
  OpenFlowSwitches are Topology entities (inheriting from topology.Switch)
  
  OpenFlowSwitches are persistent; that is, if a switch reconnects, the
  Connection field of the original OpenFlowSwitch object will simply be
  reset to refer to the new connection.
  
  For now, OpenFlowSwitch is primarily a proxy to its underlying connection
  object. Later, we'll possibly add more explicit operations the client can
  perform.
  
  Note that for the purposes of the debugger, we can interpose on
  a switch entity by enumerating all listeners for the events listed
  below, and triggering mock events for those listeners.
  """
  _eventMixin_events = set([
    SwitchJoin, # Defined in pox.topology
    SwitchLeave,
    SwitchConnectionUp,
    SwitchConnectionDown,

    PortStatus, # Defined in libopenflow_01
    FlowRemoved,
    PacketIn,
    BarrierIn,
  ])

  def __init__ (self, dpid):
    if not dpid:
      raise AssertionError("OpenFlowSwitch should have dpid")

    Switch.__init__(self, id=dpid)
    EventMixin.__init__(self)
    self.dpid = dpid
    self.ports = {}
    self.flow_table = NOMFlowTable(self)
    self.capabilities = 0
    self._connection = None
    self._listeners = []
    self._reconnectTimeout = None # Timer for reconnection
    self.xid_generator = xid_generator( ((dpid & 0x7FFF) << 16) + 1)

  def _setConnection (self, connection, ofp=None):
    ''' ofp - a FeaturesReply message '''
    if self._connection: self._connection.removeListeners(self._listeners)
    self._listeners = []
    self._connection = connection
    if self._reconnectTimeout is not None:
      self._reconnectTimeout.cancel()
      self._reconnectTimeout = None
    if connection is None:
      self._reconnectTimeout = Timer(RECONNECT_TIMEOUT,
                                     self._timer_ReconnectTimeout)
    if ofp is not None:
      # update capabilities
      self.capabilities = ofp.capabilities
      # update all ports 
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
      self.raiseEvent(SwitchConnectionUp(switch=self, connection = connection))
    else:
      self.raiseEvent(SwitchConnectionDown(switch=self))


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
    self.flowTable.removeFlow(event)
    event.halt = False

  def findPortForEntity (self, entity):
    for p in self.ports.itervalues():
      if entity in p:
        return p
    return None

  @property
  def connected(self):
    return self._connection != None

  def installFlow(self, **kw):
    """ install a flow in the local flow table as well as into the associated switch """
    self.flow_table.install(TableEntry(**kw))

  def serialize (self):
    # Skip over non-serializable data, e.g. sockets
    serializable = OpenFlowSwitch(self.dpid)
    return pickle.dumps(serializable, protocol = 0)

  def send(self, *args, **kw):
    return self._connection.send(*args, **kw)

  def read(self, *args, **kw):
   return self._connection.read(*args, **kw)

  def __repr__ (self):
    return "<%s %s>" % (self.__class__.__name__, dpidToStr(self.dpid))

  @property
  def name(self):
    return repr(self)


def launch ():
  if not core.hasComponent("openflow_topology"):
    core.register("openflow_topology", OpenFlowTopology())
