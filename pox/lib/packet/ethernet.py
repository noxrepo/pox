# Copyright 2011,2012,2013 James McCauley
# Copyright 2008 (C) Nicira, Inc.
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

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.

#======================================================================
# Ethernet header
#
#======================================================================

import struct

from .packet_base import packet_base
from .packet_utils import ethtype_to_str

from pox.lib.addresses import *

ETHER_ANY            = EthAddr(b"\x00\x00\x00\x00\x00\x00")
ETHER_BROADCAST      = EthAddr(b"\xff\xff\xff\xff\xff\xff")
BRIDGE_GROUP_ADDRESS = EthAddr(b"\x01\x80\xC2\x00\x00\x00")
LLDP_MULTICAST       = EthAddr(b"\x01\x80\xc2\x00\x00\x0e")
PAE_MULTICAST        = EthAddr(b'\x01\x80\xc2\x00\x00\x03') # 802.1x Port
                                                            #  Access Entity
NDP_MULTICAST        = EthAddr(b'\x01\x23\x20\x00\x00\x01') # Nicira discovery
                                                            #  multicast

class ethernet(packet_base):
  "Ethernet packet struct"

  resolve_names = False

  MIN_LEN = 14

  IP_TYPE    = 0x0800
  ARP_TYPE   = 0x0806
  RARP_TYPE  = 0x8035
  VLAN_TYPE  = 0x8100
  LLDP_TYPE  = 0x88cc
  PAE_TYPE   = 0x888e           # 802.1x Port Access Entity
  #MPLS_UNICAST_TYPE = 0x8847
  #MPLS_MULTICAST_TYPE = 0x8848
  MPLS_TYPE  = 0x8847
  MPLS_MC_TYPE = 0x8848         # Multicast
  IPV6_TYPE  = 0x86dd
  PPP_TYPE   = 0x880b
  LWAPP_TYPE = 0x88bb
  GSMP_TYPE  = 0x880c
  IPX_TYPE   = 0x8137
  IPX_TYPE   = 0x8137
  WOL_TYPE   = 0x0842
  TRILL_TYPE = 0x22f3
  JUMBO_TYPE = 0x8870
  SCSI_TYPE  = 0x889a
  ATA_TYPE   = 0x88a2
  QINQ_TYPE  = 0x9100

  INVALID_TYPE = 0xffff

  type_parsers = {}

  def __init__(self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    if len(ethernet.type_parsers) == 0:
      from .vlan import vlan
      ethernet.type_parsers[ethernet.VLAN_TYPE] = vlan
      from .arp  import arp
      ethernet.type_parsers[ethernet.ARP_TYPE]  = arp
      ethernet.type_parsers[ethernet.RARP_TYPE] = arp
      from .ipv4 import ipv4
      ethernet.type_parsers[ethernet.IP_TYPE]   = ipv4
      from .ipv6 import ipv6
      ethernet.type_parsers[ethernet.IPV6_TYPE] = ipv6
      from .lldp import lldp
      ethernet.type_parsers[ethernet.LLDP_TYPE] = lldp
      from .eapol import eapol
      ethernet.type_parsers[ethernet.PAE_TYPE]  = eapol
      from .mpls import mpls
      ethernet.type_parsers[ethernet.MPLS_TYPE] = mpls
      ethernet.type_parsers[ethernet.MPLS_MC_TYPE] = mpls
      from .llc import llc
      ethernet._llc = llc

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
    self.next = None # In case of unfinished parsing
    self.raw = raw
    alen = len(raw)
    if alen < ethernet.MIN_LEN:
      self.msg('warning eth packet data too short to parse header: data len %u'
               % (alen,))
      return

    self.dst = EthAddr(raw[:6])
    self.src = EthAddr(raw[6:12])
    self.type = struct.unpack('!H', raw[12:ethernet.MIN_LEN])[0]

    self.hdr_len = ethernet.MIN_LEN
    self.payload_len = alen - self.hdr_len

    self.next = ethernet.parse_next(self, self.type, raw, ethernet.MIN_LEN)
    self.parsed = True

  @staticmethod
  def parse_next (prev, typelen, raw, offset=0, allow_llc=True):
    parser = ethernet.type_parsers.get(typelen)
    if parser is not None:
      return parser(raw[offset:], prev)
    elif typelen < 1536 and allow_llc:
      return ethernet._llc(raw[offset:], prev)
    else:
      return raw[offset:]

  @staticmethod
  def getNameForType (ethertype):
    """ Returns a string name for a numeric ethertype """
    return ethtype_to_str(ethertype)

  @property
  def effective_ethertype (self):
    return self._get_effective_ethertype(self)

  @staticmethod
  def _get_effective_ethertype (self):
    """
    Get the "effective" ethertype of a packet.

    This means that if the payload is something like a VLAN or SNAP header,
    we want the type from that deeper header.  This is kind of ugly here in
    the packet library, but it should make user code somewhat simpler.
    """
    if not self.parsed:
      return ethernet.INVALID_TYPE
    if self.type == ethernet.VLAN_TYPE or type(self.payload) == ethernet._llc:
      try:
        return self.payload.effective_ethertype
      except:
        return ethernet.INVALID_TYPE
    return self.type

  def _to_str(self):
    s = ''.join(('[',str(EthAddr(self.src)),'>',str(EthAddr(self.dst)),' ',
                ethernet.getNameForType(self.type),']'))
    return s

  def hdr(self, payload):
    dst = self.dst
    src = self.src
    if type(dst) is EthAddr:
      dst = dst.toRaw()
    if type(src) is EthAddr:
      src = src.toRaw()
    return struct.pack('!6s6sH', dst, src, self.type)
