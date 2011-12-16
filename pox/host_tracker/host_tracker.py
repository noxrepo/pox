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
ARP_AWARE_TIMEOUT = 20 # 60 * 2

# Timeout for ARP-silent entries (those which do not answer to ARP pings)
ARP_SILENT_TIMEOUT = 60 # 60 * 20

# Timeout to wait for an ARP ping reply (very short)
ARP_REPLY_TIMEOUT = 1

# Number of ARP ping attemps before quitting
ARP_PING_CNT = 2

# Interval that defines the timer period
TIMER_INTERVAL = 5



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
  def __init__ (self, connection, dpid, port, mac):
    self.connection = connection
    self.dpid = dpid
    self.port = port
    self.mac = mac
    self.ip = None
    self.keepAliveTime = ARP_SILENT_TIMEOUT
    self.lastTimeSeen = time.time()
    self.answersPings = False # actually, we are not sure yet
    self.pendingPings = 0
    self.pingTimeout = 0 # will be set by sendPing

  def __eq__ (self, other):
    if type(other) == type(None):
      return type(self) == type(None)
    elif type(other) == tuple:
      return (self.dpid,self.port,self.mac)==other
    else:
      return (self.dpid,self.port,self.mac)==(other.dpid,other.port,other.mac)

  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    return time.time() > (self.lastTimeSeen + self.keepAliveTime)

  def mustBePinged (self):
    if self.answersPings: 
      return self.isExpired() and self.pendingPings < ARP_PING_CNT 
    else:
      return ( 0 < self.pendingPings < ARP_PING_CNT ) 

class host_tracker (EventMixin):
  def __init__ (self):
    
    # The following tables should go to Topology later
    self.hostMACTable = {}
    self.hostIPTable = {}

    self._t = Timer(TIMER_INTERVAL, self._check_timeouts, recurring=True)

    self.listenTo(core)

  # The following two functions should go to Topology also
  def getHostByMAC(self, mac):
    try:
      result = self.hostMACTable[mac]
    except KeyError as e:
      result = None
    return result

  def getHostByIP(self, ip):
    try:
      result = self.hostIPTable[ip]
    except KeyError as e:
      result = None
    return result

  def sendPing(self, entry):
    r = arp() # Builds an "ETH/IP any-to-any ARP packet
    r.opcode = arp.REQUEST
    r.hwdst = entry.mac
    r.protodst = entry.ip
    # src is ETHER_ANY, IP_ANY
    e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.set_payload(r)
    log.debug("%i %i sending ARP REQ to %s %s",
            entry.dpid, entry.port, str(r.hwdst), str(r.protodst))
    msg = of.ofp_packet_out(data = e.pack(),
                           action = of.ofp_action_output(port = entry.port))
    entry.connection.send(msg.pack())
    entry.pendingPings += 1
    entry.pingTimeout = time.time() + ARP_REPLY_TIMEOUT
    return

  def getSrcIP(self, packet):
    """
    This auxiliary function returns the source IPv4 address for packets that
    have one (IPv4, ARPv4). Returns None otherwise.
    """
    if isinstance(packet, ipv4):
      log.debug("IP %s => %s",str(packet.srcip),str(packet.dstip))
      return packet.srcip

    elif isinstance(packet, arp):
      log.debug("ARP %s %s => %s", 
               {arp.REQUEST:"request",arp.REPLY:"reply"}.get(packet.opcode,
                   'op:%i' % (packet.opcode,)),
               str(packet.protosrc), str(packet.protodst))

      if packet.hwtype == arp.HW_TYPE_ETHERNET and \
         packet.prototype == arp.PROTO_TYPE_IP and \
         packet.protosrc != 0:
        return packet.protosrc

    return None

  def updateIPInfo(self, pckt_srcip, entry):
    """ If there is IP info in the incoming packet, update the entry
    accordingly. This affects both the entry and the IP -> entry mapping.
    Right now, it assumes mappings are all 1:1 - not always the case in
    practice.
    """
    hostByIP = self.getHostByIP(pckt_srcip)
    if hostByIP == entry:
      # The current IP for the entry is already equal to pckt_srcip, we're done
      log.debug("%i %i %s (%s) already has IP %s",
              entry.dpid,entry.port,str(entry.mac),str(entry.ip),str(pckt_srcip) )
      return
    
    # Otherwise, we must update the entry - and possibly the entry HostByIP

    if hostByIP != None:
      # Some other host currently has that IP
      # For now, we remove the information from the previous host
      log.warning("%s was previously %i %i %s (%s)",
                  str(pckt_srcip),
                  hostByIP.dpid, hostByIP.port, str(hostByIP.mac),
                  str(hostByIP.ip) )
      del self.hostIPTable[hostByIP.ip]
      hostByIP.ip = None

    if entry.ip != None:
      # Host had some other previous IP
      log.info("%i %i %s changed IP from %s to %s", 
              entry.dpid,entry.port,str(entry.mac),
              str(entry.ip), str(pckt_srcip) )
    else:
      log.debug("%i %i %s got IP %s",
              entry.dpid,entry.port,str(entry.mac),
              str(pckt_srcip) )

    entry.ip = pckt_srcip
    self.hostIPTable[pckt_srcip] = entry
    return

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
    entry = self.getHostByMAC(packet.src)
    if entry == None:
      newEntry = True
      # there is no previous host by that MAC
      # should we raise a NewHostFound event (at the end)?
      entry = Entry(event.connection,dpid,inport,packet.src)
      self.hostMACTable[packet.src] = entry
      log.debug("Learned %s is at %i %i",
               str(entry.mac), entry.dpid, entry.port)
    else:
      newEntry = False
      # there is already an entry of host with that MAC
      entry.lastTimeSeen = time.time()
      if entry != (dpid, inport, packet.src):
        # ... but host has moved
        # should we raise a HostMoved event (at the end)?
        log.info("Learned %s (%i %i) moved to %i %i", str(entry.mac),
                entry.dpid, entry.port, dpid, inport)
        # update host location
        entry.dpid = dpid
        entry.inport = inport
        # should we create a whole new entry, or keep the previous host info?
        # for now, we keep it: IP address, answers pings, etc.

    pckt_srcip = self.getSrcIP(packet.next)
    if pckt_srcip == None:
      # Can't learn IP from this packet, there is nothing else to do
      return
    else:
      self.updateIPInfo(pckt_srcip,entry)

    if isinstance(packet.next, arp):
      # If it sends an ARP packet, it should answer pings, RIGHT?
      entry.answersPings = True
      # Clear any pending timeouts related to ARP pings
      entry.keepAliveTime = ARP_AWARE_TIMEOUT
      entry.pendingPings = 0
      entry.pingTimeout = 0
    elif newEntry:
      # If it is a new host and packet was not arp
      self.sendPing(entry)

    return

  def _check_timeouts(self):
    log.debug("Checking timeouts at %i", time.time())
    for host in self.hostMACTable.values():
      log.debug("Checking %i %i %s %s (scheduled for %i)",
              host.dpid, host.port,
              str(host.mac), str(host.ip),
              host.lastTimeSeen + host.keepAliveTime )
      if host.mustBePinged():
        self.sendPing(host)
      elif host.isExpired():
        log.info("Entry %i %i %s expired", host.dpid, host.port, str(host.mac))
        del self.hostMACTable[host.mac]
        if host.ip != None:
          del self.hostIPTable[host.ip]

