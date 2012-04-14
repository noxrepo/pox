# Copyright 2011 James McCauley
# Copyright 2008 (C) Nicira, Inc.
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

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.

#======================================================================
# Ethernet header
#
#======================================================================

import struct

from packet_base import packet_base
from packet_utils import ethtype_to_str

from pox.lib.addresses import *

ETHER_ANY            = EthAddr(b"\x00\x00\x00\x00\x00\x00")
ETHER_BROADCAST      = EthAddr(b"\xff\xff\xff\xff\xff\xff")
BRIDGE_GROUP_ADDRESS = EthAddr(b"\x01\x80\xC2\x00\x00\x00")
LLDP_MULTICAST       = EthAddr(b"\x01\x80\xc2\x00\x00\x0e")
PAE_MULTICAST        = EthAddr(b'\x01\x80\xc2\x00\x00\x03') # 802.1x Port Access Entity
NDP_MULTICAST        = EthAddr(b'\x01\x23\x20\x00\x00\x01') # Nicira discovery
                                                   # multicast

class ethernet(packet_base):
  "Ethernet packet struct"

  resolve_names = False

  MIN_LEN = 14

  IP_TYPE   = 0x0800
  ARP_TYPE  = 0x0806
  RARP_TYPE = 0x8035
  VLAN_TYPE = 0x8100
  LLDP_TYPE = 0x88cc
  PAE_TYPE  = 0x888e           # 802.1x Port Access Entity
  MPLS_UNICAST_TYPE = 0x8847
  MPLS_MULTICAST_TYPE = 0x8848

  type_parsers = {}

  def __init__(self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    if len(ethernet.type_parsers) == 0:
      from vlan import vlan
      ethernet.type_parsers[ethernet.VLAN_TYPE] = vlan
      from arp  import arp
      ethernet.type_parsers[ethernet.ARP_TYPE]  = arp
      ethernet.type_parsers[ethernet.RARP_TYPE] = arp
      from ipv4 import ipv4
      ethernet.type_parsers[ethernet.IP_TYPE]   = ipv4
      from lldp import lldp
      ethernet.type_parsers[ethernet.LLDP_TYPE] = lldp
      from eapol import eapol
      ethernet.type_parsers[ethernet.PAE_TYPE]  = eapol
      from mpls import mpls
      ethernet.type_parsers[ethernet.MPLS_UNICAST_TYPE] = mpls
      ethernet.type_parsers[ethernet.MPLS_MULTICAST_TYPE] = mpls

    self.prev = prev

    self.dst  = ETHER_ANY
    self.src  = ETHER_ANY
    self.type = 0
    self.next = b''

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.raw = raw
    alen = len(raw)
    if alen < ethernet.MIN_LEN:
      self.msg('warning eth packet data too short to parse header: data len %u' % alen)
      return

    self.dst = EthAddr(raw[:6])
    self.src = EthAddr(raw[6:12])
    self.type = struct.unpack('!H', raw[12:ethernet.MIN_LEN])[0]

    self.hdr_len = ethernet.MIN_LEN
    self.payload_len = alen - self.hdr_len

    #TODO: support SNAP/LLC frames
    if self.type in ethernet.type_parsers:
      self.next = ethernet.type_parsers[self.type](raw[ethernet.MIN_LEN:], self)
    else:
      self.next = raw[ethernet.MIN_LEN:]

    self.parsed = True

  @staticmethod
  def getNameForType (ethertype):
    """ Returns a string name for a numeric ethertype """
    return ethtype_to_str(ethertype)

  def __str__(self):
    s = ''.join(('[',str(EthAddr(self.src)),'>',str(EthAddr(self.dst)),':',
                ethernet.getNameForType(self.type),']'))
    if self.next is None:
      return s
    elif isinstance(type(self.next), bytes):
      return s + '|<' + str(len(self.next)) + ' bytes>'
    else:
      return s + "|" + str(self.next)

  def hdr(self, payload):
    dst = self.dst
    src = self.src
    if type(dst) is EthAddr:
      dst = dst.toRaw()
    if type(src) is EthAddr:
      src = src.toRaw()
    return struct.pack('!6s6sH', dst, src, self.type)
