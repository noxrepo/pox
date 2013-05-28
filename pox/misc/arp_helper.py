# Copyright 2011,2012,2013 James McCauley
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



def send_arp_reply (reply_to, mac, src_mac = None, src_ip = None):
  # reply_to should be a PacketIn event
  arpp = reply_to.parsed.find('arp')
  mac = EthAddr(mac)
  if src_mac is None:
    src_mac = mac
  else:
    src_mac = EthAddr(src_mac)
  r = arp()
  r.opcode = r.REPLY
  r.hwdst = arpp.hwsrc
  r.protodst = arpp.protosrc
  r.hwsrc = EthAddr(src_mac)
  r.protosrc = IPAddr("0.0.0.0") if src_ip is None else IPAddr(src_ip)
  e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=r.hwdst)
  e.payload = r
  msg = of.ofp_packet_out()
  msg.data = e.pack()
  msg.actions.append(of.ofp_action_output(port = reply_to.port))
  msg.in_port = of.OFPP_NONE
  reply_to.connection.send(msg)


def send_arp_request (connection, ip, port = of.OFPP_FLOOD,
                      src_mac = None, src_ip = None):
  if src_mac is None:
    src_mac = _dpid_to_mac(connection.dpid)
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

 
def _dpid_to_mac (dpid):
  # Should maybe look at internal port MAC instead?
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


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
    self.reply_from = reply_from # MAC
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


class ARPHelper (EventMixin):
  _eventMixin_events = set([ARPRequest,ARPReply])
  _rule_priority = 0x7000 # Pretty high

  def __init__ (self, no_flow, eat_packets):
    core.addListeners(self)
    self._install_flow = not no_flow
    self.eat_packets = eat_packets

  def send_arp_request (self, *args, **kw):
    return send_arp_request(*args, **kw)

  def send_arp_reply (self, *args, **kw):
    return send_arp_reply(*args, **kw)

  def _handle_GoingUpEvent (self, event):
    core.openflow.addListeners(self)
    log.debug("Up...")

  def _handle_ConnectionUp (self, event):
    if self._install_flow:
      fm = of.ofp_flow_mod()
      fm.priority = self._rule_priority
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

      ev = ARPRequest(event.connection,a,_dpid_to_mac(dpid),self.eat_packets,
          inport)
      self.raiseEvent(ev)
      if ev.reply is not None:
        r = arp()
        r.hwtype = a.hwtype
        r.prototype = a.prototype
        r.hwlen = a.hwlen
        r.protolen = a.protolen
        r.opcode = arp.REPLY
        r.hwdst = a.hwsrc
        r.protodst = a.protosrc
        r.protosrc = a.protodst
        r.hwsrc = EthAddr(ev.reply)
        e = ethernet(type=packet.type, src=ev.reply_from, dst=a.hwsrc)
        e.payload = r
        log.debug("%s answering ARP for %s" % (dpid_to_str(dpid),
            str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port =
                                                of.OFPP_IN_PORT))
        msg.in_port = inport
        event.connection.send(msg)
        return EventHalt if ev.eat_packet else None

    elif a.opcode == arp.REPLY:
      log.debug("%s ARP reply %s => %s", dpid_to_str(dpid),
                a.protosrc, a.hwsrc)

      ev = ARPReply(event.connection,a,self.eat_packets,inport)
      self.raiseEvent(ev)
      return EventHalt if ev.eat_packet else None

    return EventHalt if self.eat_packets else None


def launch (no_flow=False, eat_packets=True):
  core.registerNew(ARPHelper, str_to_bool(no_flow), str_to_bool(eat_packets))

