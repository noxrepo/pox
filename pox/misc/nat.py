# Copyright 2013 James McCauley
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
A kind of sloppy NAT component.

Required commandline parameters:
  --dpid            The DPID to NAT-ize
  --outside-port=X  The port on DPID that connects "upstream" (e.g, "eth0")

Optional parameters:
  --subnet=X        The local subnet to use (e.g., "192.168.0.1/24")
  --inside-ip=X     The inside-facing IP address the switch will claim to be

To get this to work with Open vSwitch, you probably have to disable OVS's
in-band control with something like:
  ovs-vsctl set bridge s1 other-config:disable-in-band=true

Please submit improvements. :)
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import pox.lib.packet as pkt

from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.util import str_to_bool, dpid_to_str, str_to_dpid
from pox.lib.revent import EventMixin, Event
from pox.lib.recoco import Timer
import pox.lib.recoco as recoco

import pox.openflow.libopenflow_01 as of
from pox.proto.dhcpd import DHCPD, SimpleAddressPool

import time
import random

FLOW_TIMEOUT = 60
FLOW_MEMORY_TIMEOUT = 60 * 10


class Record (object):
  def __init__ (self):
    self.touch()
    self.outgoing_match = None
    self.incoming_match = None
    self.real_srcport = None
    self.fake_srcport = None
    self.outgoing_fm = None
    self.incoming_fm = None

  @property
  def expired (self):
    return time.time() > self._expires_at

  def touch (self):
    self._expires_at = time.time() + FLOW_MEMORY_TIMEOUT

  def __str__ (self):
    s = "%s:%s" % (self.outgoing_match.nw_src, self.real_srcport)
    if self.fake_srcport != self.real_srcport:
      s += "/%s" % (self.fake_srcport,)
    s += " -> %s:%s" % (self.outgoing_match.nw_dst, self.outgoing_match.tp_dst)
    return s


class NAT (object):
  def __init__ (self, inside_ip, outside_ip, gateway_ip, dns_ip, outside_port,
      dpid, subnet = None):

    self.inside_ip = inside_ip
    self.outside_ip = outside_ip
    self.gateway_ip = gateway_ip
    self.dns_ip = dns_ip # Or None
    self.outside_port = outside_port
    self.dpid = dpid
    self.subnet = subnet

    self._outside_portno = None
    self._gateway_eth = None
    self._connection = None

    # Which NAT ports have we used?
    # proto means TCP or UDP
    self._used_ports = set() # (proto,port)

    # Flow records indexed in both directions
    # match -> Record
    self._record_by_outgoing = {}
    self._record_by_incoming = {}

    core.listen_to_dependencies(self)

  def _all_dependencies_met (self):
    log.debug('Trying to start...')
    if self.dpid in core.openflow.connections:
      self._start(core.openflow.connections[self.dpid])
    else:
      core.openflow.addListenerByName('ConnectionUp',
          self.__handle_dpid_ConnectionUp)

    self.expire_timer = Timer(60, self._expire, recurring = True)

  def _expire (self):
    dead = []
    for r in self._record_by_outgoing.values():
      if r.expired:
        dead.append(r)

    for r in dead:
      del self._record_by_outgoing[r.outgoing_match]
      del self._record_by_incoming[r.incoming_match]
      self._used_ports.remove((r.outgoing_match.nw_proto,r.fake_srcport))

    if dead and not self._record_by_outgoing:
      log.debug("All flows expired")

  def _is_local (self, ip):
    if ip.is_multicast: return True
    if self.subnet is not None:
      if ip.in_network(self.subnet): return True
      return False
    if ip.in_network('192.168.0.0/16'): return True
    if ip.in_network('10.0.0.0/8'): return True
    if ip.in_network('172.16.0.0/12'): return True
    return False

  def _pick_port (self, flow):
    """
    Gets a possibly-remapped outside port

    flow is the match of the connection
    returns port (maybe from flow, maybe not)
    """

    port = flow.tp_src

    if port < 1024:
      # Never allow these
      port = random.randint(49152, 65534)

    # Pretty sloppy!

    cycle = 0
    while cycle < 2:
      if (flow.nw_proto,port) not in self._used_ports:
        self._used_ports.add((flow.nw_proto,port))
        return port
      port += 1
      if port >= 65534:
        port = 49152
        cycle += 1

    log.warn("No ports to give!")
    return None

  @property
  def _outside_eth (self):
    if self._connection is None: return None
    #return self._connection.eth_addr
    return self._connection.ports[self._outside_portno].hw_addr

  def _handle_FlowRemoved (self, event):
    pass

  @staticmethod
  def strip_match (o):
    m = of.ofp_match()

    fields = 'dl_dst dl_src nw_dst nw_src tp_dst tp_src dl_type nw_proto'

    for f in fields.split():
      setattr(m, f, getattr(o, f))

    return m

  @staticmethod
  def make_match (o):
    return NAT.strip_match(of.ofp_match.from_packet(o))

  def _handle_PacketIn (self, event):
    if self._outside_eth is None: return

    #print
    #print "PACKET",event.connection.ports[event.port].name,event.port,
    #print self.outside_port, self.make_match(event.ofp)

    incoming = event.port == self._outside_portno

    if self._gateway_eth is None:
      # Need to find gateway MAC -- send an ARP
      self._arp_for_gateway()
      return

    packet = event.parsed
    dns_hack = False

    # We only handle TCP and UDP
    tcpp = packet.find('tcp')
    if not tcpp:
      tcpp = packet.find('udp')
      if not tcpp: return
      if tcpp.dstport == 53 and tcpp.prev.dstip == self.inside_ip:
        if self.dns_ip and not incoming:
          # Special hack for DNS since we've lied and claimed to be the server
          dns_hack = True
    ipp = tcpp.prev

    if not incoming:
      # Assume we only NAT public addresses
      if self._is_local(ipp.dstip) and not dns_hack: return
    else:
      # Assume we only care about ourselves
      if ipp.dstip != self.outside_ip: return

    match = self.make_match(event.ofp)

    if incoming:
      match2 = match.clone()
      match2.dl_dst = None # See note below
      record = self._record_by_incoming.get(match2)
      if record is None:
        # Ignore for a while
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 1
        fm.hard_timeout = 10
        fm.match = of.ofp_match.from_packet(event.ofp)
        event.connection.send(fm)
        return
      log.debug("%s reinstalled", record)
      record.incoming_fm.data = event.ofp # Hacky!
    else:
      record = self._record_by_outgoing.get(match)
      if record is None:
        record = Record()

        record.real_srcport = tcpp.srcport
        record.fake_srcport = self._pick_port(match)

        # Outside heading in
        fm = of.ofp_flow_mod()
        fm.flags |= of.OFPFF_SEND_FLOW_REM
        fm.hard_timeout = FLOW_TIMEOUT

        fm.match = match.flip()
        fm.match.in_port = self._outside_portno
        fm.match.nw_dst = self.outside_ip
        fm.match.tp_dst = record.fake_srcport
        fm.match.dl_src = self._gateway_eth

        # We should set dl_dst, but it can get in the way.  Why?  Because
        # in some situations, the ARP may ARP for and get the local host's
        # MAC, but in others it may not.
        #fm.match.dl_dst = self._outside_eth
        fm.match.dl_dst = None

        fm.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        fm.actions.append(of.ofp_action_nw_addr.set_dst(ipp.srcip))

        if dns_hack:
          fm.match.nw_src = self.dns_ip
          fm.actions.append(of.ofp_action_nw_addr.set_src(self.inside_ip))
        if record.fake_srcport != record.real_srcport:
          fm.actions.append(of.ofp_action_tp_port.set_dst(record.real_srcport))

        fm.actions.append(of.ofp_action_output(port = event.port))

        record.incoming_match = self.strip_match(fm.match)
        record.incoming_fm = fm

        # Inside heading out
        fm = of.ofp_flow_mod()
        fm.data = event.ofp
        fm.flags |= of.OFPFF_SEND_FLOW_REM
        fm.hard_timeout = FLOW_TIMEOUT
        fm.match = match.clone()
        fm.match.in_port = event.port
        fm.actions.append(of.ofp_action_dl_addr.set_src(self._outside_eth))
        fm.actions.append(of.ofp_action_nw_addr.set_src(self.outside_ip))
        if dns_hack:
          fm.actions.append(of.ofp_action_nw_addr.set_dst(self.dns_ip))
        if record.fake_srcport != record.real_srcport:
          fm.actions.append(of.ofp_action_tp_port.set_src(record.fake_srcport))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(self._gateway_eth))
        fm.actions.append(of.ofp_action_output(port = self._outside_portno))

        record.outgoing_match = self.strip_match(fm.match)
        record.outgoing_fm = fm

        self._record_by_incoming[record.incoming_match] = record
        self._record_by_outgoing[record.outgoing_match] = record

        log.debug("%s installed", record)
      else:
        log.debug("%s reinstalled", record)
        record.outgoing_fm.data = event.ofp # Hacky!

    record.touch()

    # Send/resend the flow mods
    if incoming:
      data = record.outgoing_fm.pack() + record.incoming_fm.pack()
    else:
      data = record.incoming_fm.pack() + record.outgoing_fm.pack()
    self._connection.send(data)

    # We may have set one of the data fields, but they should be reset since
    # they won't be valid in the future.  Kind of hacky.
    record.outgoing_fm.data = None
    record.incoming_fm.data = None

  def __handle_dpid_ConnectionUp (self, event):
    if event.dpid != self.dpid:
      return
    self._start(event.connection)

  def _start (self, connection):
    self._connection = connection

    self._outside_portno = connection.ports[self.outside_port].port_no

    fm = of.ofp_flow_mod()
    fm.match.in_port = self._outside_portno
    fm.priority = 1
    connection.send(fm)

    fm = of.ofp_flow_mod()
    fm.match.in_port = self._outside_portno
    fm.match.dl_type = 0x800 # IP
    fm.match.nw_dst = self.outside_ip
    fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    fm.priority = 2
    connection.send(fm)

    connection.addListeners(self)

    # Need to find gateway MAC -- send an ARP
    self._arp_for_gateway()

  def _arp_for_gateway (self):
    log.debug('Attempting to ARP for gateway (%s)', self.gateway_ip)
    self._ARPHelper_.send_arp_request(self._connection,
                                      ip = self.gateway_ip,
                                      port = self._outside_portno,
                                      src_ip = self.outside_ip)

  def _handle_ARPHelper_ARPReply (self, event):
    if event.dpid != self.dpid: return
    if event.port != self._outside_portno: return
    if event.reply.protosrc == self.gateway_ip:
      self._gateway_eth = event.reply.hwsrc
      log.info("Gateway %s is %s", self.gateway_ip, self._gateway_eth)

  def _handle_ARPHelper_ARPRequest (self, event):
    if event.dpid != self.dpid: return

    dstip = event.request.protodst
    if event.port == self._outside_portno:
      if dstip == self.outside_ip:
        if self._connection is None:
          log.warn("Someone tried to ARP us, but no connection yet")
        else:
          event.reply = self._outside_eth
    else:
      if dstip == self.inside_ip or not self._is_local(dstip):
        if self._connection is None:
          log.warn("Someone tried to ARP us, but no connection yet")
        else:
          #event.reply = self._connection.eth_addr
          event.reply = self._connection.ports[event.port].hw_addr


class NATDHCPD (DHCPD):
  """
  Subclass of the DHCP daemon for NAT

  Basically it's the normal DHCP server, but it works on one specific DPID and
  can ignore a particular port.
  """
  def __init__ (self, dpid, outside_port, *args, **kw):
    self._outside_port_name = outside_port
    self._outside_port_no = None
    self._dpid = dpid
    super(NATDHCPD,self).__init__(*args,**kw)

  def _handle_ConnectionUp (self, event):
    if self._dpid != event.dpid: return
    ports = event.connection.ports
    if self._outside_port_name not in ports:
      log.warn("No port %s on DPID %s", self._outside_port_name,
          dpid_to_str(self._dpid))
      return
    self._outside_port_no = ports[self._outside_port_name].port_no

    return super(NATDHCPD,self)._handle_ConnectionUp(event)

  def _handle_PacketIn (self, event):
    if self._dpid != event.dpid: return
    if event.port == self._outside_port_no: return
    return super(NATDHCPD,self)._handle_PacketIn(event)


def launch (dpid, outside_port, subnet = '172.16.1.0/24',
            inside_ip = '172.16.1.1'):

  import pox.proto.dhcp_client as dc
  dc.launch(dpid = dpid, port = outside_port, port_eth = True)

  import pox.proto.arp_helper as ah
  ah.launch(use_port_mac = True)

  dpid = str_to_dpid(dpid)
  inside_ip = IPAddr(inside_ip)

  pool = SimpleAddressPool(network = subnet, first = 100, last = 199)

  core.registerNew(NATDHCPD, install_flow = True, pool = pool,
                   ip_address = inside_ip, router_address = inside_ip,
                   dns_address = inside_ip, dpid = dpid,
                   outside_port = outside_port)


  def got_lease (event):
    outside_ip = event.lease.address

    if not event.lease.routers:
      log.error("Can't start NAT because we didn't get an upstream gateway")
      return
    gateway_ip = event.lease.routers[0]

    if event.lease.dns_servers:
      dns_ip = event.lease.dns_servers[0]
    else:
      dns_ip = None

    log.debug('Starting NAT')

    n = NAT(inside_ip, outside_ip, gateway_ip, dns_ip, outside_port, dpid,
            subnet=subnet)
    core.register(n)


  def init ():
    log.debug('Waiting for DHCP lease on port %s', outside_port)
    core.DHCPClient.addListenerByName('DHCPLeased', got_lease)

  core.call_when_ready(init, ['DHCPClient'])
