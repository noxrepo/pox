# Copyright 2012 James McCauley
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
