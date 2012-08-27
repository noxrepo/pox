# Copyright 2011
# 
# Author: Dorgival Guedes
# Author: Kyriakos Zarifis
#
# This file is part of POX.
# Some of the arp/openflow-related code was borrowed from dumb_l3_switch.
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

Timer configuration can be changed when needed (e.g., for debugging) using
the launch facility (check timeoutSec dict and PingCtrl.pingLim).
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.graph.nom import *
from pox.lib.recoco.recoco import Timer
from pox.lib.addresses import EthAddr, IPAddr

import pox.openflow.libopenflow_01 as of

import pox.openflow.discovery as discovery

from pox.lib.revent.revent import *

import time

import string

# Times (in seconds) to use for differente timouts:
timeoutSec = dict(
  arpAware=60*2,   # Quiet ARP-responding entries are pinged after this
  arpSilent=60*20, # This is for uiet entries not known to answer ARP
  arpReply=4,      # Time to wait for an ARP reply before retrial
  timerInterval=5, # Seconds between timer routine activations
  entryMove=60     # Minimum expected time to move a physical entry
  )
# Good values for testing:
#  --arpAware=15 --arpSilent=45 --arpReply=1 --entryMove=4
# Another parameter that may be used:
# --pingLim=2

class Alive (object):
  """ Holds liveliness information for MAC and IP entries
  """
  def __init__ (self, livelinessInterval=timeoutSec['arpAware']):
    self.lastTimeSeen = time.time()
    self.interval=livelinessInterval
  
  def expired (self):
    return time.time() > self.lastTimeSeen + self.interval

  def refresh (self):
    self.lastTimeSeen = time.time()


class PingCtrl (Alive):
  """ Holds information for handling ARP pings for hosts
  """
  # Number of ARP ping attemps before deciding it failed
  pingLim=3

  def __init__ (self):
    Alive.__init__(self, timeoutSec['arpReply'])
    self.pending = 0

  def sent (self):
    self.refresh()
    self.pending += 1

  def failed (self):
    return self.pending > PingCtrl.pingLim

  def received (self):
    # Clear any pending timeouts related to ARP pings
    self.pending = 0


class IpEntry (Alive):
  """
  This entry keeps track of IP addresses seen from each MAC entry and will
  be kept in the macEntry object's ipAddrs dictionary. At least for now,
  there is no need to refer to the original macEntry as the code is organized.
  """
  def __init__ (self, hasARP):
    if hasARP:
      Alive.__init__(self,timeoutSec['arpAware'])
    else:
      Alive.__init__(self,timeoutSec['arpSilent'])
    self.hasARP = hasARP
    self.pings = PingCtrl()

  def setHasARP (self):
    if not self.hasARP:
      self.hasARP = True
      self.interval = timeoutSec['arpAware']


class HostTracker (EventMixin):
    
  _eventMixin_events = set([
    HostJoin, # Defined in pox.lib.graph
    HostLeave,
  ])
    
  def __init__ (self):
    #self._t = Timer(timeoutSec['timerInterval'],
    #               self._check_timeouts, recurring=True)
    self.topology = core.topology
    self.listenTo(core)
    log.info("HostTracker ready")
  
  def sendPing(self, macEntry, ipAddr):
    r = arp() # Builds an "ETH/IP any-to-any ARP packet
    r.opcode = arp.REQUEST
    r.hwdst = macEntry.macaddr
    r.protodst = ipAddr
    # src is ETHER_ANY, IP_ANY
    e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.set_payload(r)
    log.debug("%i %i sending ARP REQ to %s %s",
            macEntry.dpid, macEntry.port, str(r.hwdst), str(r.protodst))
    msg = of.ofp_packet_out(data = e.pack(),
                           action = of.ofp_action_output(port = macEntry.port))
    if core.openflow.sendToDPID(macEntry.dpid, msg.pack()):
      ipEntry = macEntry.ipAddrs[ipAddr]
      ipEntry.pings.sent()
    else:
      # macEntry is stale, remove it.
      log.debug("%i %i ERROR sending ARP REQ to %s %s",
                macEntry.dpid, macEntry.port, str(r.hwdst), str(r.protodst))
      del macEntry.ipAddrs[ipAddr]
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

  def updateIPInfo(self, pckt_srcip, macEntry, hasARP):
    """ If there is IP info in the incoming packet, update the macEntry
    accordingly. In the past we assumed a 1:1 mapping between MAC and IP
    addresses, but removed that restriction later to accomodate cases 
    like virtual interfaces (1:n) and distributed packet rewriting (n:1)
    """
    if pckt_srcip in macEntry.ipAddrs:
      # that entry already has that IP
      ipEntry = macEntry.ipAddrs[pckt_srcip]
      ipEntry.refresh()
      log.debug("%s already has IP %s, refreshing",
              str(macEntry), str(pckt_srcip) )
    else:
      # new mapping
      ipEntry = IpEntry(hasARP)
      macEntry.ipAddrs[pckt_srcip] = ipEntry
      log.info("Learned %s got IP %s", str(macEntry), str(pckt_srcip) )
    if hasARP:
      ipEntry.pings.received()

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)

  def _handle_PacketIn (self, event):
    """
    Populate MAC and IP tables based on incoming packets.
    Handles only packets from ports identified as not switch-only.
    If a MAC was not seen before, insert it in the MAC table;
    otherwise, update table and enry.
    If packet has a source IP, update that info for the macEntry (may require
    removing the info from antoher entry previously with that IP address).
    It does not forward any packets, just extract info from them.
    """
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parse()
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if packet.type == ethernet.LLDP_TYPE:    # Ignore LLDP packets
      return
    
    if core.openflow_discovery.isSwitchOnlyPort(dpid, inport):
      # No host should be right behind a switch-only port
      log.debug("Ignoring packetIn at switch-only port (%i, %i)", dpid, inport)
      return

    log.debug("PacketIn: %i %i ETH %s => %s",
            dpid, inport, str(packet.src), str(packet.dst))

    mac = packet.src
    
    # Learn or update dpid/port/MAC info
    host = core.topology.find(IsInstance(Host), macstr=mac.toStr())#, one=True)
    
    """
    This should be unnecessary. Check if find()'s 'one=True' works
    """
    if host:
      host = host[0]
    
    if not host:
      # there is no known host by that MAC
      log.info("Learned %s", packet.src)
      (pckt_srcip, hasARP) = self.getSrcIPandARP(packet.next)
      if pckt_srcip:
        newHost = Host(mac.toStr(), pckt_srcip, (dpid, inport))
      else:
        newHost = Host(mac.toStr(), None, (dpid, inport))
      self.topology.addEntity(newHost)
      self.raiseEventNoErrors(HostJoin, newHost)
      
      # Create new access link and add it on the NOM
      newLink = AccessLink(dpid, inport, newHost.macstr)
      self.topology.addEntity(newLink)
      self.raiseEventNoErrors(LinkEvent, True, newLink)
      
    elif host.location != (dpid, inport):    
      # there is already an entry of host with that MAC, but host has moved
      # should we raise a HostMoved event (at the end)?
      log.info("Learned %s moved to %i %i", host.mac, dpid, inport)
      """
      # if there has not been long since heard from it...
      if time.time() - macEntry.lastTimeSeen < timeoutSec['entryMove']:
        log.warning("Possible duplicate: %s at time %i, now (%i %i), time %i",
                    str(macEntry), macEntry.lastTimeSeen(),
                    dpid, inport, time.time())
      # should we create a whole new entry, or keep the previous host info?
      # for now, we keep it: IP info, answers pings, etc.
      """
      switch = core.topology.getEntityByID(dpid)
      port = inport
      host.location = (switch, port)
      
      # TODO, remove old access link from NOM and add new one
    
    return

  def _check_timeouts(self):
    for macEntry in self.entryByMAC.values():
      entryPinged = False
      for ip_addr, ipEntry in macEntry.ipAddrs.items():
        if ipEntry.expired():
          if ipEntry.pings.failed():
            del macEntry.ipAddrs[ip_addr]
            log.info("Entry %s: IP address %s expired",
                    str(macEntry), str(ip_addr) )
          else: 
            self.sendPing(macEntry,ip_addr)
            ipEntry.pings.sent()
            entryPinged = True
      if macEntry.expired() and not entryPinged:
        log.info("Entry %s expired", str(macEntry))
        # sanity check: there should be no IP addresses left
        if len(macEntry.ipAddrs) > 0:
          for ip in macEntry.ipAddrs.keys():
            log.warning("Entry %s expired but still had IP address %s",
                        str(macEntry), str(ip_addr) )
            del macEntry.ipAddrs[ip_addr]
        del self.entryByMAC[macEntry.macaddr]
