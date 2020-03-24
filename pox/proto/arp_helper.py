# Copyright 2011,2012,2013,2017 James McCauley
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
A utility module for handling some mundane parts of ARP
"""

"""
TODO
----
arp_responder should be refactored to use this.  Also, it should be possible
to have a simple ARP learner which keeps an ARP table without responding...
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.revent import EventHalt, Event, EventMixin

import pox.openflow.libopenflow_01 as of



def send_arp_reply (reply_to, mac, src_mac = None):
  """
  Send an ARP reply.

  reply_to is a PacketIn event corresponding to an ARP request

  mac is the MAC address to reply with

  src_mac is the MAC address that the reply comes from (the L2 address)

  mac and src_mac can be EthAddrs, or the following special values:
    False - use the "DPID MAC" (MAC based on switch DPID)
    True  - use the MAC of the port the event was received by

  Additionally, src_mac can be None (the default), which means to use
  the same value as mac.
  """
  if mac is False:
    mac = reply_to.connection.eth_addr
  elif mac is True:
    mac = reply_to.connection.ports[reply_to.port].hw_addr
  mac = EthAddr(mac)

  if src_mac is None:
    src_mac = mac
  elif src_mac is False:
    src_mac = reply_to.connection.eth_addr
  elif src_mac is True:
    src_mac = reply_to.connection.ports[reply_to.port].hw_addr
  src_mac = EthAddr(src_mac)

  arpp = reply_to.parsed.find('arp')
  r = arp()
  r.opcode = r.REPLY
  r.hwdst = arpp.hwsrc
  r.protodst = arpp.protosrc
  r.hwsrc = mac
  r.protosrc = IPAddr(arpp.protodst)
  e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=r.hwdst)
  e.payload = r
  msg = of.ofp_packet_out()
  msg.data = e.pack()
  msg.actions.append(of.ofp_action_output(port = reply_to.port))
  msg.in_port = of.OFPP_NONE
  reply_to.connection.send(msg)


def send_arp_request (connection, ip, port = of.OFPP_FLOOD,
                      src_mac = False, src_ip = None):
  """
  Send an ARP request

  src_mac can be an EthAddr, or one of the following special values:
    False - use the "DPID MAC" (MAC based on switch DPID) -- default
    True  - use the MAC of the port the event was received by
  """
  if src_mac is False:
    src_mac = connection.eth_addr
  elif src_mac is True:
    if port in (of.OFPP_FLOOD, of.OFPP_ALL):
      for p in list(connection.ports.values()):
        if p.config & OFPPC_NO_FLOOD:
          if port == of.ofPP_FLOOD:
            continue
        if p.port_no < 0: continue
        if p.port_no > of.OFPP_MAX: continue # Off by one?
        send_arp_request(connection, ip, p.port_no,
                         src_mac=p.hw_addr, src_ip=src_ip)
      return
    src_mac = connection.ports[port].hw_addr
  else:
    src_mac = EthAddr(src_mac)
  r = arp()
  r.opcode = r.REQUEST
  r.hwdst = ETHER_BROADCAST
  r.protodst = IPAddr(ip)
  r.hwsrc = src_mac
  r.protosrc = IPAddr("0.0.0.0") if src_ip is None else IPAddr(src_ip)
  e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=r.hwdst)
  e.payload = r
  msg = of.ofp_packet_out()
  msg.data = e.pack()
  msg.actions.append(of.ofp_action_output(port = port))
  msg.in_port = of.OFPP_NONE
  connection.send(msg)


class ARPRequest (Event):
  @property
  def dpid (self):
    return self.connection.dpid

  def __str__ (self):
    return "ARPRequest for %s on %s"  % (self.ip, dpid_to_str(self.dpid))

  def __init__ (self, con, arpp, reply_from, eat_packet, port):
    super(ARPRequest,self).__init__()
    self.connection = con
    self.request = arpp # ARP packet
    self.reply_from = reply_from # MAC or special value from send_arp_request.
                                 # Don't modify to use ARPHelper default.
    self.eat_packet = eat_packet
    self.port = port

    self.ip = arpp.protosrc
    self.reply = None # Set to desired EthAddr


class ARPReply (Event):
  @property
  def dpid (self):
    return self.connection.dpid

  def __str__ (self):
    return "ARPReply for %s on %s"  % (self.reply.protodst,
                                       dpid_to_str(self.dpid))

  def __init__ (self, con, arpp, eat_packet, port):
    super(ARPReply,self).__init__()
    self.connection = con
    self.reply = arpp
    self.eat_packet = eat_packet
    self.port = port


_default_mac = object()

class ARPHelper (EventMixin):
  _eventMixin_events = set([ARPRequest,ARPReply])
  _rule_priority_adjustment = -0x1000 # lower than the default

  def __init__ (self, no_flow, eat_packets, default_request_src_mac = False,
                                            default_reply_src_mac = None):
    """
    Initialize

    default_request_src_mac and default_reply_src_mac are the default source
    MAC addresses for send_arp_request() and send_arp_reply().
    """
    core.addListeners(self)
    self._install_flow = not no_flow
    self.eat_packets = eat_packets
    self.default_request_src_mac = default_request_src_mac
    self.default_reply_src_mac = default_reply_src_mac

  def send_arp_request (self, connection, ip, port = of.OFPP_FLOOD,
                        src_mac = _default_mac, src_ip = None):
    if src_mac is _default_mac:
      src_mac = self.default_request_src_mac
    return send_arp_request(connection, ip, port, src_mac, src_ip)

  def send_arp_reply (self, reply_to, mac, src_mac = _default_mac):
    """
    Send an ARP reply

    reply_to is a an ARP request PacketIn event

    mac is the MAC address to reply with, True for the port MAC or False
    for the "DPID MAC".

    src_mac can be a MAC, True/False as above, None to use "mac", or if
    unspecified, defaults to self.default_src_mac.
    """
    if src_mac is _default_mac:
      src_mac = self.default_reply_src_mac
    return send_arp_reply(reply_to, mac, src_mac)

  def _handle_GoingUpEvent (self, event):
    core.openflow.addListeners(self)
    log.debug("Up...")

  def _handle_ConnectionUp (self, event):
    if self._install_flow:
      fm = of.ofp_flow_mod()
      fm.priority += self._rule_priority_adjustment
      fm.match.dl_type = ethernet.ARP_TYPE
      fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
      event.connection.send(fm)

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed

    a = packet.find('arp')
    if not a: return

    if a.prototype != arp.PROTO_TYPE_IP:
      return

    if a.hwtype != arp.HW_TYPE_ETHERNET:
      return

    if a.opcode == arp.REQUEST:
      log.debug("%s ARP request %s => %s", dpid_to_str(dpid),
                a.protosrc, a.protodst)

      src_mac = _default_mac
      ev = ARPRequest(event.connection, a, src_mac,
                      self.eat_packets, inport)
      self.raiseEvent(ev)
      if ev.reply is not None:
        log.debug("%s answering ARP for %s" % (dpid_to_str(dpid),
            str(a.protodst)))
        self.send_arp_reply(event, ev.reply, ev.reply_from)
        return EventHalt if ev.eat_packet else None

    elif a.opcode == arp.REPLY:
      log.debug("%s ARP reply %s => %s", dpid_to_str(dpid),
                a.protosrc, a.hwsrc)

      ev = ARPReply(event.connection,a,self.eat_packets,inport)
      self.raiseEvent(ev)
      return EventHalt if ev.eat_packet else None

    return EventHalt if self.eat_packets else None


def launch (no_flow=False, eat_packets=True, use_port_mac=False,
            reply_from_dst=False):
  """
  Start an ARP helper

  If use_port_mac, use the specific port's MAC instead of the "DPID MAC".
  If reply_from_dst, then replies will appear to come from the MAC address
  that is used in the reply (otherwise, it comes from the same place as
  requests).
  """
  use_port_mac = str_to_bool(use_port_mac)
  reply_from_dst = str_to_bool(reply_from_dst)

  request_src = True if use_port_mac else False
  reply_src = None if reply_from_dst else request_src

  core.registerNew(ARPHelper, str_to_bool(no_flow), str_to_bool(eat_packets),
                   request_src, reply_src)
