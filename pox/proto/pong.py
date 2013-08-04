# Copyright 2012 James McCauley
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
A simple component that always replies to ARPs and pings.

When running this component, pings (and pretty much nothing else!)
should always work.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr

log = core.getLogger()


def _handle_PacketIn (event):
  packet = event.parsed

  if packet.find("arp"):
    # Reply to ARP
    a = packet.find("arp")
    if a.opcode == a.REQUEST:
      r = pkt.arp()
      r.hwtype = a.hwtype
      r.prototype = a.prototype
      r.hwlen = a.hwlen
      r.protolen = a.protolen
      r.opcode = r.REPLY
      r.hwdst = a.hwsrc
      r.protodst = a.protosrc
      r.protosrc = a.protodst
      r.hwsrc = EthAddr("02:00:DE:AD:BE:EF")
      e = pkt.ethernet(type=packet.type, src=r.hwsrc, dst=a.hwsrc)
      e.payload = r

      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      msg.in_port = event.port
      event.connection.send(msg)

      log.info("%s ARPed for %s", r.protodst, r.protosrc)

  elif packet.find("icmp"):
    # Reply to pings

    # Make the ping reply
    icmp = pkt.icmp()
    icmp.type = pkt.TYPE_ECHO_REPLY
    icmp.payload = packet.find("icmp").payload

    # Make the IP packet around it
    ipp = pkt.ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = packet.find("ipv4").dstip
    ipp.dstip = packet.find("ipv4").srcip

    # Ethernet around that...
    e = pkt.ethernet()
    e.src = packet.dst
    e.dst = packet.src
    e.type = e.IP_TYPE

    # Hook them up...
    ipp.payload = icmp
    e.payload = ipp

    # Send it back to the input port
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.data = e.pack()
    msg.in_port = event.port
    event.connection.send(msg)

    log.debug("%s pinged %s", ipp.dstip, ipp.srcip)


def launch ():
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Pong component running.")
