from pox.lib.revent               import *
from discovery import LinkEvent, Discovery
from pox.core import core
from collections import *
from pox.lib.util                 import dpidToStr

log = core.getLogger()

class MockDiscovery (EventMixin):
  _eventMixin_events = set([
    LinkEvent,
  ])

  _core_name = "openflow_discovery" # we want to be core.openflow_discovery

  def __init__ (self):
    self._dps = set()
    self.adjacency = {} # From Link to None (used to be time.time() timestamp)

    if core.hasComponent("openflow"):
      self.listenTo(core.openflow)
    else:
      # We'll wait for openflow to come up
      self.listenTo(core)

  def _handle_ComponentRegistered (self, event):
    if event.name == "openflow":
      self.listenTo(core.openflow)
      return EventRemove # We don't need this listener anymore

  def _handle_ConnectionUp (self, event):
    """ On datapath join, create a new LLDP packet per port """
    assert event.dpid not in self._dps
    self._dps.add(event.dpid)

  def _handle_ConnectionDown (self, event):
    """ On datapath leave, delete all associated links """
    assert event.dpid in self._dps

    self._dps.remove(event.dpid)

    deleteme = []
    for link in self.adjacency:
      if link.dpid1 == event.dpid or link.dpid2 == event.dpid:
        deleteme.append(link)

    self._deleteLinks(deleteme)

  def install_link(self, dpid1, port1, dpid2, port2):
    ''' Called by STS sync proto '''
    link = Discovery.Link(dpid1, port1, dpid2, port2)

    if link not in self.adjacency:
      self.adjacency[link] = None
      log.info('link detected: %s.%i -> %s.%i' %
               (dpidToStr(link.dpid1), link.port1,
                dpidToStr(link.dpid2), link.port2))
      self.raiseEventNoErrors(LinkEvent, True, link)

    return EventHalt # Probably nobody else needs this event

  def _deleteLinks (self, links):
    for link in links:
      del self.adjacency[link]
      self.raiseEvent(LinkEvent, False, link)

  def isSwitchOnlyPort (self, dpid, port):
    """ Returns True if (dpid, port) designates a port that has any
    neighbor switches"""
    for link in self.adjacency:
      if link.dpid1 == dpid and link.port1 == port:
        return True
      if link.dpid2 == dpid and link.port2 == port:
        return True
    return False

def launch (explicit_drop = False, install_flow = True):
  core.registerNew(MockDiscovery)
