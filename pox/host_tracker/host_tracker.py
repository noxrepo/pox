# Copyright 2011 Dorgival Guedes
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
Keep track of hosts in the network, where they are and how they are
configured (at least MAC/IP addresses)

For the time being, it keeps tables with the information; later, it should
transfer that information to Topology and handle just the actual
discovery/update of host information.
"""

from pox.core import core
import pox
log = core.getLogger()

import logging
log.setLevel(logging.DEBUG)

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp

from pox.lib.recoco.recoco import Timer

import pox.openflow.libopenflow_01 as of

import pox.openflow.discovery as discovery

from pox.lib.revent.revent import *

import time

# Timeout to ping ARP-responding entries that sent no packets
ARP_AWARE_TIMEOUT = 20 # Reasonable for testing, increase later (e.g., 60*2)

# Timeout for ARP-silent entries (those which do not answer to ARP pings)
ARP_SILENT_TIMEOUT = 60 # Reasonable for testing, increase later (e.g., 60*20)

# Timeout to wait for an ARP ping reply (very short)
ARP_REPLY_TIMEOUT = 1

# Number of ARP ping attemps before quitting
ARP_PING_CNT = 2

# Interval that defines the timer period (timer granularity)
TIMER_INTERVAL = 5

class PingInfo (object):
  """ Holds information for handling ARP pings for hosts
  """
  def __init__ (self):
    self.answeredBefore = False
    self.pending = 0
    self.expireTime = 0 # to be set when a ping is sent
    self.waitTime = ARP_SILENT_TIMEOUT

  def timedOut (self):
    return self.expireTime > 0 and time.time() > self.expireTime

  def mustSend (self):
    if self.answeredBefore: 
      return self.timedOut() and self.pending < ARP_PING_CNT 
    else:
      # if we don't know if it answers, we try a few times at first
      return ( 0 < self.pending < ARP_PING_CNT ) 

  def sent (self):
    self.pending += 1
    self.expireTime = time.time() + self.waitTime

  def failed (self):
    return self.pending > ARP_PING_CNT

  def received (self):
    # Clear any pending timeouts related to ARP pings
    self.answeredBefore = True
    self.pending = 0
    self.waitTime = ARP_AWARE_TIMEOUT
    self.expireTime = 0 # to be set when a ping is sent

class Alive (object):
  """ Holds liveliness information for entries and IP info
  """
  def __init__ (self, hasARP):
    self.lastTimeSeen = time.time()
    if hasARP:
      self.interval = ARP_AWARE_TIMEOUT
    else: 
      self.interval = ARP_SILENT_TIMEOUT
  
  def expired (self):
    return time.time() > self.lastTimeSeen + self.interval

  def refresh (self):
    self.lastTimeSeen = time.time()

class Entry (object):
  """
  Not strictly an ARP entry.
  When it gets moved to Topology, may include other host info, like
  services, and it may replace dpid by a general switch object reference
  We use the port to determine which port to forward traffic out of.
  We use the ARP_AWARE_TIMEOUT to query hosts that answer pings and that have
  been silent for a while. On the other hand, if a host does not answer ARP
  pings, we wait longer (ARP_SILENT_TIMEOUT) before we remove them.
  """
  def __init__ (self, dpid, port, macaddr):
    self.dpid = dpid
    self.port = port
    self.macaddr = macaddr
    self.ipAddrs = {}
    self.liveliness = Alive(hasARP=False)

  def __eq__ (self, other):
    if type(other) == type(None):
      return type(self) == type(None)
    elif type(other) == tuple:
      return (self.dpid,self.port,self.macaddr)==other
    else:
      return (self.dpid,self.port,self.macaddr)==(other.dpid,other.port,other.macaddr)

  def __ne__ (self, other):
    return not self.__eq__(other)

class host_tracker (EventMixin):
  def __init__ (self):
    
    # The following tables should go to Topology later
    self.entryByMAC = {}
    self.entryByIP = {}

    self._t = Timer(TIMER_INTERVAL, self._check_timeouts, recurring=True)

    self.listenTo(core)

  # The following two functions should go to Topology also
  def getEntryByMAC(self, macaddr):
    try:
      result = self.entryByMAC[macaddr]
    except KeyError as e:
      result = None
    return result

  def sendPing(self, entry, ipAddr):
    r = arp() # Builds an "ETH/IP any-to-any ARP packet
    r.opcode = arp.REQUEST
    r.hwdst = entry.macaddr
    r.protodst = ipAddr
    # src is ETHER_ANY, IP_ANY
    e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.set_payload(r)
    log.debug("%i %i sending ARP REQ to %s %s",
            entry.dpid, entry.port, str(r.hwdst), str(r.protodst))
    msg = of.ofp_packet_out(data = e.pack(),
                           action = of.ofp_action_output(port = entry.port))
    if core.openflow.sendToDPID(entry.dpid, msg.pack()):
      liveliness, pings = entry.ipAddrs[ipAddr]
      pings.sent()
    else:
      # entry is stale, remove it.
      log.debug("%i %i ERROR sending ARP REQ to %s %s",
                entry.dpid, entry.port, str(r.hwdst), str(r.protodst))
      del entry.ipAddrs[ipAddr]
    return

  def getSrcIPandARP(self, packet):
    """
    This auxiliary function returns the source IPv4 address for packets that
    have one (IPv4, ARPv4). Returns None otherwise.
    """
    if isinstance(packet, ipv4):
      log.debug("IP %s => %s",str(packet.srcip),str(packet.dstip))
      return ( packet.srcip, False )

    elif isinstance(packet, arp):
      log.debug("ARP %s %s => %s", 
               {arp.REQUEST:"request",arp.REPLY:"reply"}.get(packet.opcode,
                   'op:%i' % (packet.opcode,)),
               str(packet.protosrc), str(packet.protodst))

      if packet.hwtype == arp.HW_TYPE_ETHERNET and \
         packet.prototype == arp.PROTO_TYPE_IP and \
         packet.protosrc != 0:
        return ( packet.protosrc, True )

    return ( None, False )

  def updateIPInfo(self, pckt_srcip, entry, hasARP):
    """ If there is IP info in the incoming packet, update the entry
    accordingly. In the past we assumed a 1:1 mapping between MAC and IP
    addresses, but removed that restriction later to accomodate cases 
    like virtual interfaces (1:n) and distributed packet rewriting (n:1)
    """

    if pckt_srcip in entry.ipAddrs:
      # that entry already has that IP
      (liveliness, pings) = entry.ipAddrs[pckt_srcip]
      liveliness.refresh()
      log.debug("%i %i %s already has IP %s, refreshing",
              entry.dpid,entry.port,str(entry.macaddr),str(pckt_srcip) )
    else:
      # new mapping
      pings = PingInfo();
      liveliness = Alive(hasARP)
      entry.ipAddrs[pckt_srcip] = (liveliness, pings) 
      log.debug("%i %i %s got IP %s",
              entry.dpid,entry.port,str(entry.macaddr),str(pckt_srcip) )

    if hasARP:
      pings.received()

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    """
    Populate MAC and IP tables based on incoming packets.
    Handles only packets from ports identified as not switch-only.
    If a MAC was not seen before, insert it in the MAC table;
    otherwise, update table and enry.
    If packet has a source IP, update that info for the entry (may require
    removing the info from antoher entry previously with that IP address).
    It does not forward any packets, just extract info from them.
    """
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parse()
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    # This should use Topology later 
    if core.openflow_discovery.isSwitchOnlyPort(dpid, inport):
      # No host should be right behind a switch-only port
      log.debug("%i %i ignoring packetIn at switch-only port", dpid, inport)
      return

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    log.debug("PacketIn: %i %i ETH %s => %s",
            dpid, inport, str(packet.src), str(packet.dst))

    # Learn or update dpid/port/MAC info
    entry = self.getEntryByMAC(packet.src)
    if entry == None:
      # there is no known host by that MAC
      # should we raise a NewHostFound event (at the end)?
      entry = Entry(dpid,inport,packet.src)
      self.entryByMAC[packet.src] = entry
      log.debug("Learned %s is at %i %i",
               str(entry.macaddr), entry.dpid, entry.port)
    else:
      # there is already an entry of host with that MAC
      entry.liveliness.refresh()
      if entry != (dpid, inport, packet.src):
        # ... but host has moved
        # should we raise a HostMoved event (at the end)?
        log.info("Learned %s (%i %i) moved to %i %i", str(entry.macaddr),
                entry.dpid, entry.port, dpid, inport)
        entry.dpid = dpid
        entry.inport = inport
        # should we create a whole new entry, or keep the previous host info?
        # for now, we keep it: IP info, answers pings, etc.

    (pckt_srcip, hasARP) = self.getSrcIPandARP(packet.next)

    if pckt_srcip != None:
      # will update the IP mappings for this entry, if needed
      self.updateIPInfo(pckt_srcip,entry,hasARP)

    if hasARP:
      # at least one of the IPs for this entry has ARP, so use that
      # (this is a little agressive, but reasonable)
      entry.liveliness.interval = ARP_AWARE_TIMEOUT

    return

  def _check_timeouts(self):
    log.debug("Checking timeouts at %i", time.time())
    for entry in self.entryByMAC.values():
      pingsSent = 0
      log.debug("Checking %i %i %s (scheduled for %i)",
              entry.dpid, entry.port, str(entry.macaddr), 
              entry.liveliness.lastTimeSeen + entry.liveliness.interval )
      for ip_addr, [liveliness, pings] in entry.ipAddrs.items():
        if liveliness.expired():
          if pings.failed():
            del entry.ipAddrs[addr]
            log.info("Entry %i %i %s: IP address %s expired",
                    entry.dpid, entry.port, str(entry.macaddr), str(ip_addr) )
          else: 
            self.sendPing(entry,ip_addr)
            pings.sent()
            pingsSent += 1
      if entry.liveliness.expired() and pingsSent == 0:
        log.info("Entry %i %i %s expired", entry.dpid, entry.port,
                str(entry.macaddr))
        # sanity check: there should be no IP addresses left
        if len(entry.ipAddrs) > 0:
          for ip in entry.ipAddrs.keys():
            log.warning("Entry %i %i %s still had IP address %s",
                        entry.dpid, entry.port, str(entry.macaddr),
                        str(ip_addr) )
            del entry.ipAddrs[ip_addr]
        del self.entryByMAC[entry.macaddr]
