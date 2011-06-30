from pox.lib.revent.revent import *
from pox.core import core

log = core.getLogger()

class DatapathEvent (Event):
  def __init__ (datapath):
    self.datapath = datapath

class SwitchJoin (DatapathEvent): pass
class SwitchLeave (DatapathEvent): pass

class HostEvent (Event):
  def __init__ (host):
    self.host = host

class HostJoin (HostEvent): pass
class HostLeave (HostEvent): pass





class Topology (EventMixin):
  _eventMixin_events = [
    SwitchJoin,
    SwitchLeave,
    HostJoin,
    HostLeave,
  ]

  def __init__ (self):
    #EventMixin.__init__(self)
    self.listenTo(core)
    self.switches = {}
    
  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow, prefix="OF01")
    
  def _handle_OF01_ConnectionUp (self, event):
    if event.dpid in self.switches:
      log.warn("Ignoring switch connection for %i because it's already connected" % (event.dpid,))
      return EventHalt
    self.switches[event.dpid] = event.connection
    log.info("Switch " + str(event.dpid) + " connected")
    
  def _handle_OF01_ConnectionDown (self, event):
    log.info("Switch " + str(event.dpid) + " disconnected")
    del self.switches[event.dpid]
    