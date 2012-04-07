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

NOTE: this module is automatically loaded by pox.py
"""
from pox.lib.revent import *
import libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

class ConnectionUp (Event):
  """
  Connection raised when the connection to an OpenFlow switch has been
  established.
  """
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp

class ConnectionDown (Event):
  """
  Connection raised when the connection to an OpenFlow switch has been
  lost.
  """
  def __init__ (self, connection):
    Event.__init__(self)
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
    Event.__init__(self)
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
    Event.__init__(self)
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
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp     # Raw ofp message(s)

class StatsReply (Event):
  """ Abstract superclass for all stats replies """
  def __init__ (self, connection, ofp, stats):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp     # Raw ofp message(s)
    self.stats = stats # Processed

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
    Event.__init__(self)
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
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp
    self.xid = ofp.xid

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
    Event.__init__(self)
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

