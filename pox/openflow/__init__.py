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
This is the main OpenFlow module.

Along with libopenflow, this is the major part of the OpenFlow API in POX.
There are a number of Events, which are generally raised on core.openflow
as well as on individual switch Connections.  Many of these events have at
least some of the following properties:
 .connection - a reference to the switch connection that caused the event
 .dpid - the DPID of the switch that caused the event
 .ofp - the OpenFlow message that caused the event (from libopenflow)

One of the more complicated aspects of OpenFlow is dealing with stats
replies, which may come in multiple parts (it shouldn't be that that
difficult, really, but that hasn't stopped it from beind handled wrong
wrong more than once).  In POX, the raw events are available, but you will
generally just want to listen to the aggregate stats events which take
care of this for you and are only fired when all data is available.

NOTE: This module is usually automatically loaded by pox.py
"""

from pox.lib.revent import *
from pox.lib.util import dpidToStr
from . import libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet


class ConnectionHandshakeComplete (Event):
  """
  Event when a switch handshake completes

  Fired immediately before ConnectionUp
  """
  def __init__ (self, connection):
    self.connection = connection
    self.dpid = connection.dpid

class ConnectionUp (Event):
  """
  Raised when a connection to a switch has been established.
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp

class FeaturesReceived (Event):
  """
  Raised upon receipt of an ofp_switch_features message

  This generally happens as part of a connection automatically.
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp

class ConnectionDown (Event):
  """
  Raised when a connection to switch has been lost.
  """
  def __init__ (self, connection):
    self.connection = connection
    self.dpid = connection.dpid

class PortStatus (Event):
  """
  Fired in response to port status changes.

  added (bool) - True if fired because a port was added
  deleted (bool) - True if fired because a port was deleted
  modified (bool) - True if fired because a port was modified
  port (int) - number of port in question
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp
    self.modified = ofp.reason == of.OFPPR_MODIFY
    self.added = ofp.reason == of.OFPPR_ADD
    self.deleted = ofp.reason == of.OFPPR_DELETE
    self.port = ofp.desc.port_no

class FlowRemoved (Event):
  """
  Raised when a flow entry has been removed from a flow table.

  This may either be because of a timeout or because it was removed
  explicitly.
  Properties:
  idleTimeout (bool) - True if expired because of idleness
  hardTimeout (bool) - True if expired because of hard timeout
  timeout (bool) - True if either of the above is true
  deleted (bool) - True if deleted explicitly
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp
    self.idleTimeout = False
    self.hardTimeout = False
    self.deleted = False
    self.timeout = False
    if ofp.reason == of.OFPRR_IDLE_TIMEOUT:
      self.timeout = True
      self.idleTimeout = True
    elif ofp.reason == of.OFPRR_HARD_TIMEOUT:
      self.timeout = True
      self.hardTimeout = True
    elif ofp.reason == of.OFPRR_DELETE:
      self.deleted = True

class RawStatsReply (Event):
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.ofp = ofp     # Raw ofp message(s)

  @property
  def dpid (self):
    return self.connection.dpid

class StatsReply (Event):
  """
  Abstract superclass for all stats replies
  """
  def __init__ (self, connection, ofp, stats):
    self.connection = connection
    self.ofp = ofp     # Raw ofp message(s)
    self.stats = stats # Processed

  @property
  def dpid (self):
    return self.connection.dpid

class SwitchDescReceived (StatsReply):
  pass

class FlowStatsReceived (StatsReply):
  pass

class AggregateFlowStatsReceived (StatsReply):
  pass

class TableStatsReceived (StatsReply):
  pass

class PortStatsReceived (StatsReply):
  pass

class QueueStatsReceived (StatsReply):
  pass

class PacketIn (Event):
  """
  Fired in response to PacketIn events

  port (int) - number of port the packet came in on
  data (bytes) - raw packet data
  parsed (packet subclasses) - pox.lib.packet's parsed version
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.ofp = ofp
    self.port = ofp.in_port
    self.data = ofp.data
    self._parsed = None
    self.dpid = connection.dpid

  def parse (self):
    if self._parsed is None:
      self._parsed = ethernet(self.data)
    return self._parsed

  @property
  def parsed (self):
    """
    The packet as parsed by pox.lib.packet
    """
    return self.parse()

class ErrorIn (Event):
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.ofp = ofp
    self.xid = ofp.xid
    self.dpid = connection.dpid
    self.should_log = True # If this remains True, an error will be logged

  def asString (self):
    return self.ofp.show()

#    def lookup (m, v):
#      if v in m:
#        return str(m[v])
#      else:
#        return "Unknown/" + str(v)
#
#    #TODO: The show() in ofp_error actually does some clever
#    #      stuff now to stringize error messages.  Refactor that and the
#    #      (less clever) code below.
#    s = 'Type: ' + lookup(of.ofp_error_type_map, self.ofp.type)
#    s += ' Code: '
#
#    responses = {
#      of.OFPET_HELLO_FAILED    : of.ofp_hello_failed_code,
#      of.OFPET_BAD_REQUEST     : of.ofp_bad_request_code,
#      of.OFPET_BAD_ACTION      : of.ofp_bad_action_code,
#      of.OFPET_FLOW_MOD_FAILED : of.ofp_flow_mod_failed_code,
#      of.OFPET_PORT_MOD_FAILED : of.ofp_port_mod_failed_code,
#      of.OFPET_QUEUE_OP_FAILED : of.ofp_queue_op_failed_code,
#    }
#
#    if self.ofp.type in responses:
#      s += lookup(responses[self.ofp.type],self.ofp.code)
#    else:
#      s += "Unknown/" + str(self.ofp.code)
#    if self.ofp.type == of.OFPET_HELLO_FAILED:
#      s += lookup(of.ofp_hello_failed_code, self.ofp.type)
#
#    return s

class BarrierIn (Event):
  """
  Fired in response to a barrier reply

  xid (int) - XID of barrier request
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.ofp = ofp
    self.dpid = connection.dpid
    self.xid = ofp.xid

class ConnectionIn (Event):
  def __init__ (self, connection):
    super(ConnectionIn,self).__init__()
    self.connection = connection
    self.dpid = connection.dpid
    self.nexus = None

class ConfigurationReceived (Event):
  """
  Fired in response to OFPT_GET_CONFIG_REPLY
  """
  def __init__ (self, connection, ofp):
    self.connection = connection
    self.ofp = ofp
    self.dpid = connection.dpid
    self.xid = ofp.xid

  @property
  def flags (self):
    return self.ofp.flags

  @property
  def miss_send_len (self):
    return self.ofp.miss_send_len

  @property
  def drop_fragments (self):
    return (self.ofp.flags & of.OFPC_FRAG_MASK) == of.OFPC_FRAG_DROP

  @property
  def reassemble_fragments (self):
    return (self.ofp.flags & of.OFPC_FRAG_MASK) == of.OFPC_FRAG_REASM


class OpenFlowConnectionArbiter (EventMixin):
  """
  Determines which OpenFlowNexus gets the switch.
  Default implementation always just gives it to core.openflow
  """
  _eventMixin_events = set([
    ConnectionIn,
  ])
  def __init__ (self, default = False):
    """ default as False causes it to always use core.openflow """
    self._default = default
    self._fallback = None

  def getNexus (self, connection):
    e = ConnectionIn(connection)
    self.raiseEventNoErrors(e)
    if e.nexus is None:
      e.nexus = self._default
    if e.nexus is False:
      if self._fallback is None:
        try:
          from pox.core import core
          self._fallback = core.openflow
        except:
          raise RuntimeError("No OpenFlow nexus for new connection")
      e.nexus = self._fallback
    return e.nexus


class ConnectionDict (dict):
  def __iter__ (self):
    return iter(self.values())

  def __contains__ (self, item):
    v = dict.__contains__(self, item)
    if v: return v
    return item in self.values()

  @property
  def dpids (self):
    return list(self.keys())

  def iter_dpids (self):
    return iter(self.keys())


class OpenFlowNexus (EventMixin):
  """
  Main point of OpenFlow interaction.

  There is usually just one instance of this class, registered as
  core.openflow.  Most OpenFlow events fire here in addition to on their
  specific connections.
  """
  _eventMixin_events = set([
    ConnectionHandshakeComplete,
    ConnectionUp,
    ConnectionDown,
    FeaturesReceived,
    PortStatus,
    PacketIn,
    BarrierIn,
    ErrorIn,
    RawStatsReply,
    SwitchDescReceived,
    FlowStatsReceived,
    AggregateFlowStatsReceived,
    TableStatsReceived,
    PortStatsReceived,
    QueueStatsReceived,
    FlowRemoved,
    ConfigurationReceived,
  ])

  # Bytes to send to controller when a packet misses all flows
  miss_send_len = of.OFP_DEFAULT_MISS_SEND_LEN

  # Enable/Disable clearing of flows on switch connect
  clear_flows_on_connect = True

  def __init__ (self):
    self._connections = ConnectionDict() # DPID -> Connection

    from pox.core import core

    self.listenTo(core)

  @property
  def connections (self):
    return self._connections

  def getConnection (self, dpid):
    """
    Get the Connection object associated with a DPID.
    """
    return self._connections.get(dpid, None)

  def sendToDPID (self, dpid, data):
    """
    Send data to a specific DPID.
    """
    if dpid in self._connections:
      self._connections[dpid].send(data)
      return True
    else:
      import logging
      log = logging.getLogger("openflow")
      log.warn("Couldn't send to %s because we're not connected to it!" %
               (dpidToStr(dpid),))
      return False

  def _handle_DownEvent (self, event):
    for c in list(self._connections.values()):
      try:
        c.disconnect()
      except:
        pass

  def _connect (self, con):
    self._connections[con.dpid] = con
  def _disconnect (self, dpid):
    if dpid in self._connections:
      del self._connections[dpid]
      return True
    return False

def _launch (default_arbiter=True):
  from pox.core import core
  if default_arbiter:
    core.registerNew(OpenFlowConnectionArbiter)
  core.register("openflow", OpenFlowNexus())

def launch (default_arbiter=True):
  from pox.core import core
  if core.hasComponent("openflow"):
    return
  return _launch(default_arbiter)
