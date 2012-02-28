'''
Created on Feb 27, 2012

@author: rcs
'''
from pox.core import core
from pox.lib.revent import EventMixin
from pox.openflow import *

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

  def getNexus (self, connection):
    e = ConnectionIn(connection)
    self.raiseEventNoErrors(e)
    if e.nexus is None:
      e.nexus = self._default
    if e.nexus is False:
      e.nexus = core.openflow
    return e.nexus

class OpenFlowNexus (EventMixin):
  """
  Main point of OpenFlow interaction.

  There is usually just one instance of this class, registered as
  core.openflow.  Most OpenFlow events fire here in addition to on their
  specific connections.
  """
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
    FlowRemoved,
  ])

  # Bytes to send to controller when a packet misses all flows
  miss_send_len = of.OFP_DEFAULT_MISS_SEND_LEN

  # Enable/Disable clearing of flows on switch connect
  clear_flows_on_connect = True

  def __init__ (self):
    self._connections = {}#weakref.WeakValueDictionary() # DPID -> Connection
    self.listenTo(core)

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
      print "Couldn't send to", dpid, "because we're not connected to it!"
      return False

  def _handle_DownEvent (self, event):
    for c in self._connections.values():
      try:
        c.disconnect()
      except:
        pass

  def _connect (self, con):
    self._connections[con.dpid] = con
  def _disconnect (self, dpid):
    del self._connections[dpid]

def launch (default_arbiter=True):
  if core.hasComponent("openflow"):
    return
  if default_arbiter:
    core.registerNew(OpenFlowConnectionArbiter)
  core.register("openflow", OpenFlowNexus())

#from pox.core import core
