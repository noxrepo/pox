# Copyright 2017 James McCauley
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
A RIP v2 routing daemon for OpenFlow

This component turns OpenFlow switches into RIP v2 routers.  The
switches must support Open vSwitch / Nicira extensions.

You must run this component once for each switch you want to act as
a RIP router, passing it the DPID of the switch.  You also configure
each interface you want active.  Each interface to be involved in
RIP must be given an IP address, and can also be given a prefix size.
Multiple such IPs/prefixes for each interface can be given separated
by commas.  As well as defining the interface IPs (the sources for
RIP announcements), these define static local routes which will be
spread by RIP.

An example config file (for pox.config) might look like:
  [proto.rip.ovs_rip]
  dpid=10
  eth0=192.168.1.1/24
  4=10.1.0.1/16,10.2.0.1/16

This configures RIP for the switch with DPID 10 (you could also use
POX's canonical DPID format, e.g., 00-00-00-00-00-0a).  The port on
the switch with the name "eth0" will be configured to have IP
192.168.1.1, and the subnet 192.168.1.0/24 should be directly
reachable on this port.  Aside from using port names, one can use
port numbers, as is the case with the next line, which configures
port 4 of the switch to have two IPs and two directly reachable
subnets (if you have port names which are just numbers, this may
be problematic).

You may specify static non-local routes as follows:
  [proto.rip.ovs_rip:static]
  dpid=10
  10.3.0.0/16=192.168.1.3,metric:3

This specifies that the 10.3.0.0/16 subnet should be reachable via
192.168.1.3.  In this case, 192.168.1.3 is reachable directly via
eth0 as seen in the previous config section, but this needn't
actually be the case (though it needs to be reachable somehow when
a packet destined for 10.3.0.0/16 actually arrives!).

See the source comments for info on what the various OpenFlow
tables are used for.
"""

#TODO: Factor out the basic L3 router stuff from the RIP-specific stuff so
#      that the former can be reused for other components.

from pox.core import core
from pox.lib.addresses import IPAddr, parse_cidr
import pox.lib.packet.rip as RIP
import pox.lib.packet as pkt
from pox.lib.recoco import Timer, Task
import socket
from .rip_core import *
from pox.proto.arp_helper import send_arp_reply
from pox.proto.arp_table import ARPTable
from pox.lib.util import dpid_to_str
import pox.openflow.nicira as ovs
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


ARP_IDLE_TIMEOUT = 20
ARP_HARD_TIMEOUT = 60 #TODO: Send periodic ARPs from our side


# We use some packet metadata
DST_IP_REGISTER = ovs.NXM_NX_REG2
OUT_PORT_REGISTER = ovs.NXM_NX_REG3


# Cookies for various table entries
PING_COOKIE = 1
ARP_REPLY_COOKIE = 2
ARP_REQUEST_COOKIE = 3
ARP_TABLE_COOKIE = 4
RIP_PACKET_COOKIE = 5
DHCP_COOKIE = 6


# Table numbers
INGRESS_TABLE = 0
RIP_NET_TABLE = 1
RIP_PORT_TABLE = 2
ARP_TABLE = 3


# The INGRESS table sends various things (ARP) to the controller.
# IP packets, it passes along to RIP_NET after copying the dst
# IP address into DST_IP_REGISTER and decrementing the TTL.

# RIP_NET is one part of the "routing table".  For entries that
# have a gateway, it stores the gateway.  After any lookup,
# RIP_NET resubmits to RIP_PORT, but if the route has a gateway,
# it first rewrites the dst IP to be the IP of the gateway.
# This will then get written back again later.

# RIP_PORT is the second part of the "routing table".  In
# RIP_PORT, the dst IP should be directly attached (either
# because the packet is to a directly attached network or
# because RIP_NET rewrote the destination to be the next
# hop gateway, which should be directly attached), so we
# are using that IP to look up the egress port, which is loaded
# into OUT_PORT_REGISTER.  We also set the source MAC address,
# and finally resubmit to ARP.

# ARP looks up the dst IP, and matching entries set the dst
# Ethernet address, rewrite the dst IP back to the stored
# value in DST_IP_REGISTER, and output to OUT_PORT_REGISTER.
# On a table miss, the packet is sent to the controller with
# ARP_TABLE_COOKIE.  The controller will send an ARP.



class Port (object):
  def __init__ (self):
    self.ips = set()
    self.arp_table = ARPTable()

  @property
  def any_ip (self):
    return next(iter(self.ips))



class OVSRIPRouter (RIPRouter):
  def __init__ (self, dpid):
    self.dpid = dpid

    super(OVSRIPRouter,self).__init__()

    self._ports = {} # portno -> Port
    self._port_cache = {}

    self._deferred_sync_table_pending = 0

    # Caches of switch tables
    self._cur = {RIP_NET_TABLE:{}, RIP_PORT_TABLE:{}}

    # For sloppy duplicate-installation prevention
    #TODO: Do this better
    self._prev = None

    self.log = log

    self.log.info("OVS RIP Router on %s", dpid_to_str(self.dpid))

    core.listen_to_dependencies(self)

  def _handle_core_UpEvent (self, e):
    self.send_timer = Timer(self.SEND_TIMER, self._on_send, recurring=True)

  def _on_send (self):
    #self.log.debug("Sending timed update")
    self.send_updates(force=True)

  def _deferred_sync_table (self):
    self._deferred_sync_table_pending += 1
    if self._deferred_sync_table_pending > 1: return
    def do_it ():
      self.log.debug("Syncing table after %s deferrals",
                     self._deferred_sync_table_pending)
      self._deferred_sync_table_pending = 0
      self.sync_table()
    core.call_later(do_it)

  def _add_entry (self, e):
    self.table[e.key] = e
    self._deferred_sync_table()

  def add_static_route (self, prefix, next_hop, metric=1):
    """
    Adds a static route
    """
    e = self._new_entry(static=True, origin=next_hop)
    e.ip = prefix[0]
    e.size = prefix[1]
    e.metric = metric
    self.table[e.key] = e

  def add_direct_network (self, iface, ip, prefix):
    """
    Adds a directly attached network (and, implicitly, a network interface)

    iface can either be a port number (int) or port name (string)
    ip is the IP address of the interface (on network 'prefix')
    prefix is the network (IPAddr,prefix_size) of the attached network

    You may call this more than once if the interface has multiple directly
    reachable subnets.
    """
    assert ip.in_network(prefix)
    if iface not in self._port_cache:
      self._port_cache[iface] = set()
    self._port_cache[iface].add((ip,prefix))
    self._refresh_ports()

  def _refresh_ports (self):
    """
    Tries to resolve entries in _port_cache
    """
    #TODO: Are there other places this needs to be called?

    if not self._conn: return # Nothing to do now
    ports = {}
    self._ports = ports
    for name,ip_prefix_pairs in self._port_cache.items():
      if name not in self._conn.ports: continue
      ofport = self._conn.ports[name]
      if ofport.port_no not in ports:
        ports[ofport.port_no] = Port()
      port = ports[ofport.port_no]
      for ip,prefix in ip_prefix_pairs:
        port.ips.add(ip)

        e = self._new_entry(static=True)
        e.ip = prefix[0]
        e.size = prefix[1]
        e.dev = ofport.port_no
        e.metric = 0 #NOTE: Or is this 1?
        self._add_entry(e)

    # The ingress table has port-specific stuff on it, so we may need
    # to update it now.
    #TODO: Check if anything has changed instead of always updating
    if self._conn:
      self._init_ingress_table()

  @property
  def all_ips (self):
    all_ips = set()
    for portobj in self._ports.values():
      all_ips.update(portobj.ips)
    return all_ips

  def _clear_table (self, tid):
    if not self._conn: return
    self._invalidate()
    fm = ovs.ofp_flow_mod_table_id()
    fm.command = of.OFPFC_DELETE
    fm.table_id = tid
    self._conn.send(fm)

  def _invalidate (self):
    self._prev = None

  def _init_tables (self):
    if not self._conn:
      self.log.warn("Can't init tables -- no connection")
      return

    self._clear_table(INGRESS_TABLE)
    self._clear_table(RIP_NET_TABLE)
    self._clear_table(RIP_PORT_TABLE)
    self._clear_table(ARP_TABLE)

    self._init_ingress_table()
    self._init_rip_net_table()
    self._init_rip_port_table()
    self._init_arp_table()

  def _init_ingress_table (self):
    self._clear_table(INGRESS_TABLE)

    # INGRESS_TABLE: Send RIP to controller
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = INGRESS_TABLE
    fm.cookie = RIP_PACKET_COOKIE
    fm.match.dl_type = pkt.ethernet.IP_TYPE
    fm.match.dl_dst = RIP.RIP2_ADDRESS.multicast_ethernet_address
    fm.match.nw_dst = RIP.RIP2_ADDRESS
    fm.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    fm.match.tp_dst = RIP.RIP_PORT
    fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self._conn.send(fm)

    #TODO: Add RIP entry for unicast advertisements?  Or be liberal here
    #      and validate on the controller side?

    # INGRESS_TABLE: Send ARP requests for router to controller
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = INGRESS_TABLE
    fm.cookie = ARP_REQUEST_COOKIE
    fm.match.dl_type = pkt.ethernet.ARP_TYPE
    fm.match.nw_proto = pkt.arp.REQUEST
    fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    for portno,portobj in self._ports.items():
      if portno not in self._conn.ports: continue
      fm.match.in_port = portno
      for ip in portobj.ips:
        fm.match.nw_dst = ip
        self._conn.send(fm)

    # INGRESS_TABLE: Send ARP replies send to router to controller
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = INGRESS_TABLE
    fm.cookie = ARP_REPLY_COOKIE
    fm.match.dl_type = pkt.ethernet.ARP_TYPE
    fm.match.nw_proto = pkt.arp.REPLY
    fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    for portno,portobj in self._ports.items():
      if portno not in self._conn.ports: continue
      fm.match.in_port = portno
      fm.match.dl_dst = self._conn.ports[portno].hw_addr
      self._conn.send(fm)

    # INGRESS_TABLE: Send ICMP to controller
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = INGRESS_TABLE
    fm.cookie = PING_COOKIE
    fm.match.dl_type = pkt.ethernet.IP_TYPE
    fm.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
    fm.match.tp_src = pkt.ICMP.TYPE_ECHO_REQUEST # Type
    fm.match.tp_dst = 0 # Code
    fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    for portno,portobj in self._ports.items():
      if portno not in self._conn.ports: continue
      fm.match.in_port = portno
      fm.match.dl_dst = self._conn.ports[portno].hw_addr
      for ip in self.all_ips:
        fm.match.nw_dst = ip
        self._conn.send(fm)

    if core.hasComponent("DHCPD"):
      # INGRESS_TABLE: Send DHCP to controller
      fm = ovs.ofp_flow_mod_table_id()
      fm.table_id = INGRESS_TABLE
      fm.cookie = DHCP_COOKIE
      fm.match.dl_type = pkt.ethernet.IP_TYPE
      fm.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
      fm.match.tp_src = pkt.dhcp.CLIENT_PORT
      fm.match.tp_dst = pkt.dhcp.SERVER_PORT
      fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
      for portno,dhcpd in core.DHCPD.get_ports_for_dpid(self.dpid):
        if portno not in self._conn.ports: continue
        if dhcpd._install_flow:
          self.log.warn("Turning off DHCP server table entry installation.")
          self.log.warn("You probably want to configure it with no_flow.")
          dhcpd._install_flow = False
        fm.match.in_port = portno
        fm.match.dl_dst = pkt.ETHERNET.ETHER_BROADCAST
        fm.match.nw_dst = pkt.IPV4.IP_BROADCAST
        self._conn.send(fm)

        fm.match.dl_dst = self._conn.ports[portno].hw_addr
        fm.match.nw_dst = dhcpd.ip_addr
        self._conn.send(fm)

    # INGRESS_TABLE: IP packets (lower priority)
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = INGRESS_TABLE
    fm.priority -= 1
    fm.match.dl_type = pkt.ethernet.IP_TYPE
    fm.actions.append(ovs.nx_reg_move(dst=DST_IP_REGISTER,
                                      src=ovs.NXM_OF_IP_DST))
    fm.actions.append(ovs.nx_action_dec_ttl())
    fm.actions.append(ovs.nx_action_resubmit.resubmit_table(RIP_NET_TABLE))
    self._conn.send(fm)

  def _init_rip_net_table (self):
    # RIP_NET_TABLE default entry (drop)
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = RIP_NET_TABLE
    fm.priority = 0
    self._conn.send(fm)

  def _init_rip_port_table (self):
    # RIP_PORT_TABLE default entry (drop)
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = RIP_PORT_TABLE
    fm.priority = 0
    self._conn.send(fm)

  def _init_arp_table (self):
    # ARP_TABLE default entry
    fm = ovs.ofp_flow_mod_table_id()
    fm.table_id = ARP_TABLE
    fm.priority = 0
    fm.cookie = ARP_TABLE_COOKIE
    fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self._conn.send(fm)

  def _handle_openflow_ConnectionUp (self, event):
    if event.dpid != self.dpid: return
    self.log.info("Switch connected")
    self._conn.send(ovs.nx_flow_mod_table_id())
    self._conn.send(ovs.nx_packet_in_format())
    self._init_tables()
    self._refresh_ports()
    self._invalidate()

  def _handle_openflow_PortStatus (self, event):
    self._refresh_ports()
    self._invalidate()

  def _handle_openflow_PacketIn (self, event):
    try:
      cookie = event.ofp.cookie # Must be Nicira packet in!
    except:
      return
    if cookie == RIP_PACKET_COOKIE:
      self._do_rip(event)
    elif cookie == PING_COOKIE:
      self._do_ping(event)
    elif cookie == ARP_REQUEST_COOKIE:
      self._do_arp_request(event)
    elif cookie == ARP_REPLY_COOKIE:
      self._do_arp_reply(event)
    elif cookie == ARP_TABLE_COOKIE:
      self._do_arp_table(event)

  def _do_rip (self, event):
    ripp = event.parsed.find('rip')
    ipp = event.parsed.find('ipv4')
    if not ripp or not ipp:
      self.log.warn("Expected RIP packet wasn't RIP")
      return
    if ripp.version != 2: return
    if ripp.command == RIP.RIP_REQUEST:
      self.process_request(event.port, ipp.srcip, ripp)
    elif ripp.command == RIP.RIP_RESPONSE:
      self.log.debug("Processing RIP response")
      self.process_response(event.port, ipp.srcip, ripp)
      self.sync_table()

  def _do_arp_table (self, event):
    ipp = event.parsed.find('ipv4')
    if not ipp:
      self.log.warn("Packet that missed ARP table wasn't IP")
      return
    #TODO: rate limit ARPing
    port = self._ports[event.port]

    real_dst_ip = event.ofp.match.find(DST_IP_REGISTER)
    out_port = event.ofp.match.find(OUT_PORT_REGISTER)
    hop_ip = ipp.dstip

    if real_dst_ip is None:
      self.log.error("Packet to ARP for has no real IP")
      return
    real_dst_ip = real_dst_ip.value
    if out_port is None:
      self.log.error("Packet to ARP for has no port number")
      return
    out_port = out_port.value
    if out_port not in self._conn.ports:
      self.log.error("Packet to ARP for is using unknown port")
      return

    real_dst_ip = IPAddr(real_dst_ip, networkOrder=False) #FIXME: Endian issue?

    ipp.dstip = real_dst_ip

    router_ip = hop_ip if hop_ip != real_dst_ip else None

    def send (data):
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = out_port))
      msg.data = data
      event.connection.send(msg)

    out_port_eth = self._conn.ports[out_port].hw_addr

    arp_sent,entry = port.arp_table.send(event.parsed,
                                         router_ip=router_ip,
                                         src_eth=out_port_eth,
                                         src_ip=port.any_ip,
                                         send_function=send)
    if arp_sent:
      self.log.debug("ARPed for %s",
                     router_ip if router_ip is not None else real_dst_ip)
    else:
      self.log.debug("Used controller ARP entry for %s",
                     router_ip if router_ip is not None else real_dst_ip)

    if entry.mac:
      # (Re-?)ad entry to switch
      self._add_arp_entry(entry.ip, entry.mac)

  def _do_arp_reply (self, event):
    arpp = event.parsed.find('arp')
    if not arpp:
      self.log.warn("Expected ARP packet wasn't ARP")
      return
    port = self._ports.get(event.port)
    if port is None:
      self.log.warn("Got ARP from non-existent port")
      return
    port.arp_table.rx_arp_reply(arpp)
    self._add_arp_entry(arpp)

  def _do_arp_request (self, event):
    arpp = event.parsed.find('arp')
    if not arpp:
      self.log.warn("Expected ARP packet wasn't ARP")
      return
    port = self._ports.get(event.port)
    if port is None:
      self.log.warn("Got ARP from non-existent port")
      return
    port.arp_table.rx_arp(arpp)
    if arpp.protodst not in port.ips:
      # This shouldn't happen since we install table entries specifically
      # for our own ports!
      self.log.warn("Got ARP with wrong IP address")
      return
    send_arp_reply(event, True)
    self._add_arp_entry(arpp)

  def _add_arp_entry (self, ip_or_arp, eth=None):
    """
    Creates an entry in the switch ARP table

    You can either pass an ARP packet or an IP and Ethernet address
    """
    if not self._conn: return
    if eth is None:
      assert isinstance(ip_or_arp, pkt.arp)
      ip = ip_or_arp.protosrc
      eth = ip_or_arp.hwsrc
    else:
      ip = ip_or_arp
    self.log.debug("Populating ARP table with %s -> %s", ip, eth)

    fm = ovs.ofp_flow_mod_table_id()
    fm.xid = 0
    fm.table_id = ARP_TABLE
    fm.idle_timeout = ARP_IDLE_TIMEOUT
    fm.hard_timeout = ARP_HARD_TIMEOUT
    fm.match.dl_type = pkt.ethernet.IP_TYPE
    fm.match.nw_dst = ip
    fm.actions.append(of.ofp_action_dl_addr.set_dst(eth))
    fm.actions.append(ovs.nx_reg_move(src=DST_IP_REGISTER,
                                      dst=ovs.NXM_OF_IP_DST))
    fm.actions.append(ovs.nx_output_reg(reg=OUT_PORT_REGISTER))
    self._conn.send(fm)

  def _do_ping (self, event):
    eth = event.parsed
    icmpp = event.parsed.find('icmp')
    ipp = event.parsed.find('ipv4')
    if not icmpp or not ipp:
      self.log.warn("Expected ICMP packet wasn't ICMP")
      return
    oport = self._conn.ports.get(event.port)
    if oport is None:
      self.log.warn("Got ICMP from non-existent hardware port")
      return
    if oport.hw_addr != event.parsed.dst:
      # This shouldn't happen since we install table entries specifically
      # for our own ports!
      self.log.warn("Got ping with wrong Ethernet address")
      return
    port = self._ports.get(event.port)
    if port is None:
      self.log.warn("Got ICMP from non-existent port")
      return
    if ipp.dstip not in self.all_ips:
      # Unlike ARP, we use all_ips and not port.ips because we want to
      # respond to any of our IP addresses.
      # This shouldn't happen since we install table entries specifically
      # for our own ports!
      self.log.warn("Got ping with wrong IP address")
      return

    if icmpp.type == pkt.ICMP.TYPE_ECHO_REQUEST:
      echop = icmpp.payload
      if not isinstance(echop, pkt.ICMP.echo):
        self.log.warn("Expected ICMP echo wasn't ICMP echo")
        return
      # Make the ping reply
      r_icmp = pkt.icmp()
      r_icmp.type = pkt.TYPE_ECHO_REPLY
      r_icmp.payload = echop

      # Make the IP packet around it
      r_ipp = pkt.ipv4()
      r_ipp.protocol = ipp.ICMP_PROTOCOL
      r_ipp.srcip = ipp.dstip
      r_ipp.dstip = ipp.srcip

      # Ethernet around that...
      r_e = pkt.ethernet()
      r_e.src = oport.hw_addr
      r_e.dst = event.parsed.src
      r_e.type = r_e.IP_TYPE

      # Hook them up...
      r_ipp.payload = r_icmp
      r_e.payload = r_ipp

      # Send it back to the input port
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = event.port))
      msg.data = r_e.pack()
      event.connection.send(msg)

  @property
  def _conn (self):
    """
    The switch object
    """
    return core.openflow.connections.get(self.dpid)

  def send_updates (self, force):
    conn = self._conn
    if not conn: return
    direct = self._get_port_ip_map()

    out = []

    for port,dests in direct.items():
      if port not in conn.ports:
        self.log.warn("No such port %s", port)
        continue
      if port not in self._ports:
        # We aren't configured to do RIP on this port
        continue
      responses = self.get_responses(dests, force=force)
      #self.log.debug("Sending %s RIP packets via %s", len(responses), iface)
      for r in responses:
        udpp = pkt.udp()
        udpp.payload = r
        udpp.dstport = RIP.RIP_PORT
        udpp.srcport = RIP.RIP_PORT

        ipp = pkt.ipv4()
        ipp.payload = udpp
        ipp.dstip = RIP.RIP2_ADDRESS
        ipp.protocol = ipp.UDP_PROTOCOL
        # We may have multiple IPs on this interface.  Should we send an
        # advertisement from each one?  The RIP spec isn't very clear.
        # Assume no, and we want to just send one.  So just pick a source
        # IP from the ones available.
        ipp.srcip = self._ports[port].any_ip

        ethp = pkt.ethernet()
        ethp.payload = ipp
        ethp.dst = RIP.RIP2_ADDRESS.multicast_ethernet_address
        ethp.type = ethp.IP_TYPE
        src = conn.ports.get(port)
        if src is None:
          self.log.warn("Missing port %s", port)
          continue
        ethp.src = src.hw_addr

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = ethp.pack()
        out.append(msg.pack())

    #self.log.debug("Sending %s updates", len(out))
    if out: conn.send(b''.join(out))

    self._mark_all_clean()

  def sync_table (self):
    if not self._conn: return

    self._cur = {RIP_NET_TABLE:{}, RIP_PORT_TABLE:{}}
    cur = self._cur

    for e in self.table.values():
      if e.metric >= INFINITY: continue
      fm = ovs.ofp_flow_mod_table_id()
      fm.xid = 0
      fm.table_id = RIP_NET_TABLE
      fm.priority = e.size + 1  # +1 because 0 reserved for fallback
      fm.match.dl_type = pkt.ethernet.IP_TYPE
      fm.match.nw_dst = (e.ip, e.size)
      if e.dev is not None:
        # This is for a directly attached network.  It'll be looked up in
        # the port table.
        fm.actions.append(ovs.nx_action_resubmit.resubmit_table(RIP_PORT_TABLE))
      else:
        # This is for a remote network.
        # Load the gateway into the dst IP; it will be looked up in the port
        # table to find the right port.  The real dst IP will get reloaded
        # from a register before egress.
        fm.actions.append(of.ofp_action_nw_addr.set_dst(e.next_hop))
        fm.actions.append(ovs.nx_action_resubmit.resubmit_table(RIP_PORT_TABLE))
      cur[RIP_NET_TABLE][(e.ip, e.size)] = fm

    for e in self.table.values():
      if e.metric >= INFINITY: continue
      fm = ovs.ofp_flow_mod_table_id()
      fm.xid = 0
      fm.table_id = RIP_PORT_TABLE
      fm.priority = e.size + 1  # +1 because 0 reserved for fallback
      fm.match.dl_type = pkt.ethernet.IP_TYPE
      fm.match.nw_dst = (e.ip, e.size)
      if e.dev is not None:
        # This is for a directly attached network.  Look up the port.
        # Also, fix the dst IP address.
        port = self._conn.ports.get(e.dev)
        if port is None: continue
        fm.actions.append(ovs.nx_reg_load(dst=OUT_PORT_REGISTER,
                                          value=e.dev))
        fm.actions.append(of.ofp_action_dl_addr.set_src(port.hw_addr))
        fm.actions.append(ovs.nx_action_resubmit.resubmit_table(ARP_TABLE))
      else:
        # If we get to this table and we don't have a direct entry that
        # matches, we have no working route!
        # Should we install something so that we generate an ICMP unreachable
        # or something?
        pass
      cur[RIP_PORT_TABLE][(e.ip, e.size)] = fm

    if self._conn:
      data1 = b''.join(x.pack() for x in self._cur[RIP_PORT_TABLE].values())
      data2 = b''.join(x.pack() for x in self._cur[RIP_NET_TABLE].values())
      data = data1 + data2
      if data == self._prev: return # Nothing changed

      self._clear_table(RIP_NET_TABLE)
      self._clear_table(RIP_PORT_TABLE)
      self._init_rip_net_table()
      self._init_rip_port_table()

      self.log.debug("Syncing %s port and %s net table entries",
                     len(cur[RIP_PORT_TABLE]),
                     len(cur[RIP_NET_TABLE]))
      self._conn.send(data)

      self._prev = data
      #TODO: Handle errors!



class OVSRIPRouters (object):
  routers_by_dpid = {}

  def add (self, router):
    assert router.dpid not in self.routers_by_dpid
    self.routers_by_dpid[router.dpid] = router

  def get (self, dpid):
    return self.routers_by_dpid[dpid]



def static (dpid, __INSTANCE__=None, **kw):
  try:
    dpid = int(dpid)
  except:
    dpid = util.str_to_dpid(dpid)

  r = core.OVSRIPRouters.get(dpid=dpid)
  for prefix,rest in kw.items():
    prefix = IPAddr.parse_cidr(prefix)
    rest = rest.split(",")
    next_hop = IPAddr(rest[0])
    rest = rest[1:]
    attrs = {}
    for attr in rest:
      k,v = attr.split(":",1)
      f = {"metric":int}[k] # Fail for other
      attrs[k] = f(v)
    r.add_static_route(prefix=prefix, next_hop=next_hop, **attrs)



def launch (dpid, __INSTANCE__=None, **kw):
  if not core.hasComponent("OVSRIPRouters"):
    core.registerNew(OVSRIPRouters)

  if not core.hasComponent("NX"):
    import pox.openflow.nicira
    pox.openflow.nicira.launch(convert_packet_in=True)

  try:
    dpid = int(dpid)
  except:
    dpid = util.str_to_dpid(dpid)

  r = OVSRIPRouter(dpid=dpid)
  core.OVSRIPRouters.add(r)

  # Directly attached networks
  for iface,routes in kw.items():
    # Try to parse iface as a port number; else a name
    try:
      iface = int(iface)
    except:
      pass
    routes = routes.split(',')
    for route in routes:
      ip,prefix_size = IPAddr.parse_cidr(route, allow_host=True)
      prefix = ip.get_network(prefix_size)
      r.add_direct_network(iface, ip=ip, prefix=prefix)
