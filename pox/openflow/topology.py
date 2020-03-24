# Copyright 2011 James McCauley
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
OpenFlow doesn't know anything about Topology, and Topology doesn't
know anything about OpenFlow.  This module knows something about both,
and hooks the two of them together.

Specifically, this module is somewhat like an adapter that listens to
events from other parts of the openflow substem (such as discovery), and
uses them to populate and manipulate Topology.
"""

import itertools

from pox.lib.revent import *
from . import libopenflow_01 as of
from pox.openflow import *
from pox.core import core
from pox.topology.topology import *
from pox.openflow.discovery import *
from pox.openflow.libopenflow_01 import xid_generator
from pox.openflow.flow_table import FlowTable,FlowTableModification,TableEntry
from pox.lib.util import dpidToStr
from pox.lib.addresses import *

import pickle
import itertools

# After a switch disconnects, it has this many seconds to reconnect in
# order to reactivate the same OpenFlowSwitch object.  After this, if
# it reconnects, it will be a new switch object.
RECONNECT_TIMEOUT = 30

log = core.getLogger()

class OpenFlowTopology (object):
  """
  Listens to various OpenFlow-specific events and uses those to manipulate
  Topology accordingly.
  """

  def __init__ (self):
    core.listen_to_dependencies(self, ['topology'], short_attrs=True)

  def _handle_openflow_discovery_LinkEvent (self, event):
    """
    The discovery module simply sends out LLDP packets, and triggers
    LinkEvents for discovered switches. It's our job to take these
    LinkEvents and update pox.topology.
    """
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
    self.flow_table = OFSyncFlowTable(self)
    self.capabilities = 0
    self._connection = None
    self._listeners = []
    self._reconnectTimeout = None # Timer for reconnection
    self._xid_generator = xid_generator( ((dpid & 0x7FFF) << 16) + 1)

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
      self.raiseEvent(SwitchConnectionUp(switch = self,
                                         connection = connection))
    else:
      self.raiseEvent(SwitchConnectionDown(self))


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
    for p in self.ports.values():
      if entity in p:
        return p
    return None

  @property
  def connected(self):
    return self._connection != None

  def installFlow(self, **kw):
    """ install flow in the local table and the associated switch """
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


class OFSyncFlowTable (EventMixin):
  _eventMixin_events = set([FlowTableModification])
  """
  A flow table that keeps in sync with a switch
  """
  ADD = of.OFPFC_ADD
  REMOVE = of.OFPFC_DELETE
  REMOVE_STRICT = of.OFPFC_DELETE_STRICT
  TIME_OUT = 2

  def __init__ (self, switch=None, **kw):
    EventMixin.__init__(self)
    self.flow_table = FlowTable()
    self.switch = switch

    # a list of pending flow table entries : tuples (ADD|REMOVE, entry)
    self._pending = []

    # a map of pending barriers barrier_xid-> ([entry1,entry2])
    self._pending_barrier_to_ops = {}
    # a map of pending barriers per request entry -> (barrier_xid, time)
    self._pending_op_to_barrier = {}

    self.listenTo(switch)

  def install (self, entries=[]):
    """
    asynchronously install entries in the flow table

    will raise a FlowTableModification event when the change has been
    processed by the switch
    """
    self._mod(entries, OFSyncFlowTable.ADD)

  def remove_with_wildcards (self, entries=[]):
    """
    asynchronously remove entries in the flow table

    will raise a FlowTableModification event when the change has been
    processed by the switch
    """
    self._mod(entries, OFSyncFlowTable.REMOVE)

  def remove_strict (self, entries=[]):
    """
    asynchronously remove entries in the flow table.

    will raise a FlowTableModification event when the change has been
    processed by the switch
    """
    self._mod(entries, OFSyncFlowTable.REMOVE_STRICT)

  @property
  def entries (self):
    return self.flow_table.entries

  @property
  def num_pending (self):
    return len(self._pending)

  def __len__ (self):
    return len(self.flow_table)

  def _mod (self, entries, command):
    if isinstance(entries, TableEntry):
      entries = [ entries ]

    for entry in entries:
      if(command == OFSyncFlowTable.REMOVE):
        self._pending = [(cmd,pentry) for cmd,pentry in self._pending
                         if not (cmd == OFSyncFlowTable.ADD
                                 and entry.matches_with_wildcards(pentry))]
      elif(command == OFSyncFlowTable.REMOVE_STRICT):
        self._pending = [(cmd,pentry) for cmd,pentry in self._pending
                         if not (cmd == OFSyncFlowTable.ADD
                                 and entry == pentry)]

      self._pending.append( (command, entry) )

    self._sync_pending()

  def _sync_pending (self, clear=False):
    if not self.switch.connected:
      return False

    # resync the switch
    if clear:
      self._pending_barrier_to_ops = {}
      self._pending_op_to_barrier = {}
      self._pending = [op for op in self._pending
                       if op[0] == OFSyncFlowTable.ADD]

      self.switch.send(of.ofp_flow_mod(command=of.OFPFC_DELETE,
                                       match=of.ofp_match()))
      self.switch.send(of.ofp_barrier_request())

      todo = [(OFSyncFlowTable.ADD, e)
              for e in self.flow_table.entries] + self._pending
    else:
      todo = [op for op in self._pending
              if op not in self._pending_op_to_barrier
              or (self._pending_op_to_barrier[op][1]
                  + OFSyncFlowTable.TIME_OUT) < time.time() ]

    for op in todo:
      fmod_xid = self.switch._xid_generator()
      flow_mod = op[1].to_flow_mod(xid=fmod_xid, command=op[0],
                                   flags=op[1].flags | of.OFPFF_SEND_FLOW_REM)
      self.switch.send(flow_mod)

    barrier_xid = self.switch._xid_generator()
    self.switch.send(of.ofp_barrier_request(xid=barrier_xid))
    now = time.time()
    self._pending_barrier_to_ops[barrier_xid] = todo

    for op in todo:
      self._pending_op_to_barrier[op] = (barrier_xid, now)

  def _handle_SwitchConnectionUp (self, event):
    # sync all_flows
    self._sync_pending(clear=True)

  def _handle_SwitchConnectionDown (self, event):
    # connection down. too bad for our unconfirmed entries
    self._pending_barrier_to_ops = {}
    self._pending_op_to_barrier = {}

  def _handle_BarrierIn (self, barrier):
    # yeah. barrier in. time to sync some of these flows
    if barrier.xid in self._pending_barrier_to_ops:
      added = []
      removed = []
      #print "barrier in: pending for barrier: %d: %s" % (barrier.xid,
      #    self._pending_barrier_to_ops[barrier.xid])
      for op in self._pending_barrier_to_ops[barrier.xid]:
        (command, entry) = op
        if(command == OFSyncFlowTable.ADD):
          self.flow_table.add_entry(entry)
          added.append(entry)
        else:
          removed.extend(self.flow_table.remove_matching_entries(entry.match,
              entry.priority, strict=command == OFSyncFlowTable.REMOVE_STRICT))
        #print "op: %s, pending: %s" % (op, self._pending)
        if op in self._pending: self._pending.remove(op)
        self._pending_op_to_barrier.pop(op, None)
      del self._pending_barrier_to_ops[barrier.xid]
      self.raiseEvent(FlowTableModification(added = added, removed=removed))
      return EventHalt
    else:
      return EventContinue

  def _handle_FlowRemoved (self, event):
    """
    process a flow removed event -- remove the matching flow from the table.
    """
    flow_removed = event.ofp
    for entry in self.flow_table.entries:
      if (flow_removed.match == entry.match
          and flow_removed.priority == entry.priority):
        self.flow_table.remove_entry(entry)
        self.raiseEvent(FlowTableModification(removed=[entry]))
        return EventHalt
    return EventContinue


def launch ():
  if not core.hasComponent("openflow_topology"):
    core.register("openflow_topology", OpenFlowTopology())
