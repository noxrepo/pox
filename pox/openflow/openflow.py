from pox.lib.revent.revent import *
import libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.core import core

class ConnectionUp (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp

class ConnectionDown (Event):
  def __init__ (self, connection):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid

class PortStatus (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp
    self.modified = ofp.reason == of.OFPPR_MODIFY
    self.added = ofp.reason == of.OFPPR_ADD
    self.deleted = ofp.reason == of.OFPPR_DELETE
    self.port = ofp.desc.port_no

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

class FlowRemoved (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp

class PacketIn (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp
    self.port = ofp.in_port
    self.data = ofp.data
    self.parsed = None
    self.dpid = connection.dpid

  def parse (self):
    if self.parsed is None:
      self.parsed = ethernet(self.data)
    return self.parsed

class ErrorIn (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp

  def asString (self):
    def lookup (m, v):
      if v in m:
        return m[v]
      else:
        return "Unknown/" + str(v)

    #TODO: The show() or something in ofp_error actually does some clever
    #      stuff now to stringize error messages.  Refactor that and the
    #      (less clever) code below.
    s = 'Type: ' + lookup(of.ofp_error_type_map, self.ofp.type)
    s += ' Code: '

    responses = {
      of.OFPET_HELLO_FAILED    : of.ofp_hello_failed_code,
      of.OFPET_BAD_REQUEST     : of.ofp_bad_request_code,
      of.OFPET_BAD_ACTION      : of.ofp_bad_action_code,
      of.OFPET_FLOW_MOD_FAILED : of.ofp_flow_mod_failed_code,
      of.OFPET_PORT_MOD_FAILED : of.ofp_port_mod_failed_code,
      of.OFPET_QUEUE_OP_FAILED : of.ofp_queue_op_failed_code,
    }

    if self.ofp.type in responses:
      s += lookup(responses[self.ofp.type],self.ofp.code)
    else:
      s += "Unknown/" + str(self.ofp.code)
    if self.ofp.type == of.OFPET_HELLO_FAILED:
      s += lookup(of.ofp_hello_failed_code, self.ofp.type)

    return s

class FlowRemoved (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp
    self.dpid = connection.dpid

class BarrierIn (Event):
  def __init__ (self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.ofp = ofp
    self.dpid = connection.dpid
    self.xid = ofp.header.xid


class OpenFlowHub (EventMixin):
  _eventMixin_events = set([
    ConnectionUp,
    ConnectionDown,
    PortStatus,
    FlowRemoved,
    PacketIn,
    BarrierIn,
    RawStatsReply,
    SwitchDescReceived,
    FlowStatsReceived,
    AggregateFlowStatsReceived,
    TableStatsReceived,
    PortStatsReceived,
    QueueStatsReceived,
  ])
  def __init__ (self):
    self._connections = {}#weakref.WeakValueDictionary() # DPID -> Connection

  def getConnection (self, dpid):
    return self._connections.get(dpid, None)

  def sendToDPID (self, dpid, data):
    if dpid in self._connections:
      self._connections[dpid].send(data)
      return True
    else:
      print "Couldn't send to", dpid, "because we're not connected to it!"
      return False

def launch ():
  if core.hasComponent("openflow"):
    return
  core.register("openflow", OpenFlowHub())
