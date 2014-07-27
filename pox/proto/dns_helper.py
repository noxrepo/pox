# Copyright 2011-2012 James McCauley
# Copyright 2013 Felician Nemeth
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
dns_helper hides the details of DNS communication from other modules.

This module follows the logic of arp_helper by hiding the wire format
details of DNS packets and turning the into general events.
Therefore, higher layer modules can answer DNS lookups and process DNS
answers without understanding DNS packet formats.  Although,
additional low level details are exposed in the events raised by
dns_helper.

TODO: option to eat_packets?

Modules relying on dns_helper:
  dns_responder
  dns_spy
"""

from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
from pox.lib.packet.dns import rrtype_to_str, rrclass_to_str

log = core.getLogger()

class DNSAnswer (Event):
  def __init__ (self, item):
    super(DNSUpdate, self).__init__()
    self.item = item

class DNSLookup (Event):
  """
  Fired with one DNS question.

  When dns_helper receives a DNS packet, it fires a DNSLookup event
  for each question it founds in the packet.  Event handlers may
  answer this question by setting rr_answers or simple_answers.

  rr_answers is a list of full "rr"s, while simple_answers is a list
  of IP addresses for A lookups, fully qualified domain names for PTR
  lookups, etc.
  """
  def __init__ (self, rr):
    super(DNSLookup, self).__init__()

    self.name = rr.name
    self.qtype = rr.qtype

    self.rr = rr
    for t in rrtype_to_str.values():
      setattr(self, t, False)
    t = rrtype_to_str.get(rr.qtype)
    if t is not None:
      setattr(self, t, True)
      setattr(self, "UNKNOWN", False)
      self.qtype_name = t
    else:
      setattr(self, "UNKNOWN", True)
      self.qtype_name = "UNKNOWN"
    self.rr_answers = []
    self.simple_answers = []

class DNSHelper (EventMixin):
  _eventMixin_events = set([ DNSAnswer, DNSLookup ])

  def __init__ (self, install_flow = True):
    self._install_flow = install_flow
    core.openflow.addListeners(self)

  def _send_response (self, event, answers):
    q_eth = event.parsed.find('ethernet')
    q_ip = event.parsed.find('ipv4')
    q_udp = event.parsed.find('udp')
    if not (q_eth and q_ip and q_udp):
      return

    if q_udp.dstport == pkt.dns.MDNS_PORT:
      # respose will appear to be sent from here:
      r_ip_src = IPAddr('192.0.2.1')
      r_eth_src = EthAddr('11:22:33:44:55:66')
      # TODO random address is a bad idea.  We should dig up an
      # address from the answers.

      # multicast destination:
      r_ip_dst = q_ip.dstip
      r_eth_dst = q_eth.dst
    else:
      r_ip_src = q_ip.dstip
      r_eth_src = q_eth.dst
      r_ip_dst = q_ip.srcip
      r_eth_dst = q_eth.src

    r_dns = pkt.dns()
    r_dns.qr = True
    r_dns.aa = True
    r_dns.answers = answers

    r_udp = pkt.udp()
    r_udp.srcport = q_udp.dstport
    r_udp.dstport = q_udp.srcport
    r_udp.payload = r_dns

    r_ip = pkt.ipv4(srcip=r_ip_src, dstip=r_ip_dst)
    r_ip.protocol = r_ip.UDP_PROTOCOL
    r_ip.payload = r_udp

    r_eth = pkt.ethernet(src=r_eth_src, dst=r_eth_dst)
    r_eth.type = pkt.ethernet.IP_TYPE
    r_eth.payload = r_ip

    r_pkt = of.ofp_packet_out(data=r_eth.pack())
    r_pkt.actions.append(of.ofp_action_output(port=event.port))

    log.debug('response: %s' % r_dns)
    event.connection.send(r_pkt)

  def _handle_ConnectionUp (self, event):
    if self._install_flow:
      def install_one_flow (event, port):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
        msg.match.tp_src = port
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)

      install_one_flow(event, pkt.dns.SERVER_PORT)
      install_one_flow(event, pkt.dns.MDNS_PORT)

  def _handle_PacketIn (self, event):
    p = event.parsed.find('dns')

    if p is None or not p.parsed:
      return
    log.debug(p)

    answers = []
    for q in p.questions:
      if rrclass_to_str.get(q.qclass, '') != "IN":
        continue # Internet only
      ev = DNSLookup(q)
      self.raiseEvent(ev)
      for rr in ev.rr_answers:
        answers.append(rr)
      for rrdata in ev.simple_answers:
        ttl = 120  # 2 minutes
        length = 0 # should be calculated at 'packing'
        rr = pkt.dns.rr(q.name, q.qtype, q.qclass, ttl, length, rrdata)
        answers.append(rr)
    if answers:
      self._send_response(event, answers)

    def process_q (entry):
      if rrclass_to_str.get(entry.qclass, '') != "IN":
        return # Internet only
      self.raiseEvent(DNSAnswer, entry)

    for answer in p.answers:
      process_q(answer)
    for addition in p.additional:
      process_q(addition)


def launch (no_flow = False):
  core.registerNew(DNSHelper, not no_flow)
