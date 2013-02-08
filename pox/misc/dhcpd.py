# Copyright 2013 James McCauley
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
A very quick and dirty DHCP server

This is currently missing lots of features and isn't incredibly
configurable or anything.  Send pull requests. ;)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

from pox.lib.addresses import IPAddr,EthAddr
from pox.lib.revent import *
from pox.lib.util import dpid_to_str

log = core.getLogger()


def ip_for_event (event):
  """
  Use a switch's DPID as an EthAddr
  """
  eth = dpid_to_str(event.dpid,True).split("|")[0].replace("-",":")
  return EthAddr(eth)


class DHCPLease (Event):
  """
  Raised when a lease is given

  Call nak() to abort this lease
  """
  def __init__ (self, host_mac, ip):
    super(DHCPLease, self).__init__()
    self.host_mac = host_mac
    self.ip = ip
    self._nak = False

  def nak (self):
    self._nak = True


class DHCPD (EventMixin):
  _eventMixin_events = set([DHCPLease])

  def __init__ (self, ip_address = "192.168.0.254", router_address = None,
                dns_address = None, subnet = None, install_flow = True):
    self._install_flow = install_flow

    self.ip_addr = IPAddr(ip_address)
    self.router_addr = IPAddr(router_address or ip_address)
    self.dns_addr = IPAddr(dns_address or self.router_addr)
    self.subnet = IPAddr(subnet or "255.255.255.0")

    self.lease_time = 60 * 60 # An hour
    #TODO: Actually make them expire :)

    self.pool = [IPAddr("192.168.0."+str(x)) for x in range(100,199)]
    self.offers = {} # Eth -> IP we offered
    self.leases = {} # Eth -> IP we leased

    core.openflow.addListeners(self)

  def _handle_ConnectionUp (self, event):
    if self._install_flow:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
      #msg.match.nw_dst = IP_BROADCAST
      msg.match.tp_src = pkt.dhcp.CLIENT_PORT
      msg.match.tp_dst = pkt.dhcp.SERVER_PORT
      msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
      #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)

  def _handle_PacketIn (self, event):
    p = event.parsed.find('dhcp')
    if p is None or not p.parsed:
      return

    if p.op != p.BOOTREQUEST:
      return

    t = p.options.get(p.MSG_TYPE_OPT)
    if t is None:
      return

    if t.type == p.DISCOVER_MSG:
      self.exec_discover(event, p)
    elif t.type == p.REQUEST_MSG:
      self.exec_request(event, p)
    elif t.type == p.RELEASE_MSG:
      self.exec_release(event, p)

  def reply (self, event, msg):
    orig = event.parsed.find('dhcp')
    broadcast = (orig.flags & orig.BROADCAST_FLAG) != 0
    msg.op = msg.BOOTREPLY
    msg.chaddr = event.parsed.src
    msg.htype = 1
    msg.hlen = 6
    msg.xid = orig.xid
    msg.add_option(pkt.DHCP.DHCPServerIdentifierOption(self.ip_addr))

    ethp = pkt.ethernet(src=ip_for_event(event),dst=event.parsed.src)
    ethp.type = pkt.ethernet.IP_TYPE
    ipp = pkt.ipv4(srcip = self.ip_addr)
    ipp.dstip = event.parsed.find('ipv4').srcip
    if broadcast:
      ipp.dstip = IP_BROADCAST
      ethp.dst = pkt.ETHERNET.ETHER_BROADCAST
    ipp.protocol = ipp.UDP_PROTOCOL
    udpp = pkt.udp()
    udpp.srcport = pkt.dhcp.SERVER_PORT
    udpp.dstport = pkt.dhcp.CLIENT_PORT
    udpp.payload = msg
    ipp.payload = udpp
    ethp.payload = ipp
    po = of.ofp_packet_out(data=ethp.pack())
    po.actions.append(of.ofp_action_output(port=event.port))
    event.connection.send(po)

  def nak (self, event, msg = None):
    if msg is None:
      msg = pkt.dhcp()
    msg.add_option(pkt.DHCP.DHCPMsgTypeOption(msg.NAK_MSG))
    msg.siaddr = self.ip_addr
    self.reply(event, msg)

  def exec_release (self, event, p):
    src = event.parsed.src
    if src != p.chaddr:
      log.warn("%s tried to release %s with bad chaddr" % (src,p.ciaddr))
      return
    if self.leases.get(p.chaddr) != p.ciaddr:
      log.warn("%s tried to release unleased %s" % (src,p.ciaddr))
      return
    del self.leases[p.chaddr]
    self.pool.append(p.ciaddr)
    log.info("%s released %s" % (src,p.ciaddr))

  def exec_request (self, event, p):
    if not p.REQUEST_IP_OPT in p.options:
      # Uhhh...
      return
    wanted_ip = p.options[p.REQUEST_IP_OPT].addr
    src = event.parsed.src
    got_ip = None
    if src in self.leases:
      if wanted_ip != self.leases[src]:
        self.pool.append(self.leases[src])
        del self.leases[src]
      else:
        got_ip = self.leases[src]
    if got_ip is None:
      if src in self.offers:
        if wanted_ip != self.offers[src]:
          self.pool.append(self.offers[src])
          del self.offers[src]
        else:
          got_ip = self.offers[src]
    if got_ip is None:
      if wanted_ip in self.pool:
        self.pool.remove(wanted_ip)
        got_ip = wanted_ip
    if got_ip is None:
      log.warn("%s asked for un-offered %s", src, wanted_ip)
      self.nak(event)
      return

    assert got_ip == wanted_ip
    self.leases[src] = got_ip
    ev = DHCPLease(src, got_ip)
    self.raiseEvent(ev)
    if ev._nak:
      self.nak(event)
      return
    log.info("Leased %s to %s" % (got_ip, src))

    reply = pkt.dhcp()
    reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.ACK_MSG))
    reply.yiaddr = wanted_ip
    reply.siaddr = self.ip_addr

    wanted_opts = set()
    if p.PARAM_REQ_OPT in p.options:
      wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
    self.fill(wanted_opts, reply)

    self.reply(event, reply)

  def exec_discover (self, event, p):
    reply = pkt.dhcp()
    reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.OFFER_MSG))
    src = event.parsed.src
    if src in self.leases:
      offer = self.leases[src]
      del self.leases[src]
      self.offers[src] = offer
    else:
      offer = self.offers.get(src)
      if offer is None:
        if len(self.pool) == 0:
          log.error("Out of IP addresses")
          #TODO: Send a NAK or something?
          return

        offer = self.pool[0]
        if p.REQUEST_IP_OPT in p.options:
          wanted_ip = p.options[p.REQUEST_IP_OPT].addr
          if wanted_ip in self.pool:
            offer = wanted_ip
        self.pool.remove(offer)
        self.offers[src] = offer
    reply.yiaddr = offer
    reply.siaddr = self.ip_addr

    wanted_opts = set()
    if p.PARAM_REQ_OPT in p.options:
      wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
    self.fill(wanted_opts, reply)

    self.reply(event, reply)

  def fill (self, wanted_opts, msg):
    """
    Fill out some options in msg
    """
    if msg.SUBNET_MASK_OPT in wanted_opts:
      msg.add_option(pkt.DHCP.DHCPSubnetMaskOption(self.subnet))
    if msg.ROUTERS_OPT in wanted_opts:
      msg.add_option(pkt.DHCP.DHCPRoutersOption(self.router_addr))
    if msg.DNS_SERVER_OPT in wanted_opts:
      msg.add_option(pkt.DHCP.DHCPDNSServersOption(self.dns_addr))
    msg.add_option(pkt.DHCP.DHCPIPAddressLeaseTimeOption(self.lease_time))


def launch (no_flow = False):
  core.registerNew(DHCPD, install_flow = not no_flow)
