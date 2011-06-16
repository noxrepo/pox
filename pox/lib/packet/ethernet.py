# Copyright 2008 (C) Nicira, Inc.
# 
# This file is part of NOX.
# 
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
#======================================================================
# Ethernet header 
#
# Copyright (C) 2008 Nicira Networks
#
#======================================================================

import struct

from packet_base import packet_base

from packet_utils import  * 
from array import * 

ETHER_ANY            = "\x00\x00\x00\x00\x00\x00"
ETHER_BROADCAST      = "\xff\xff\xff\xff\xff\xff"
BRIDGE_GROUP_ADDRESS = "\x01\x80\xC2\x00\x00\x00"
LLDP_MULTICAST       = "\x01\x80\xc2\x00\x00\x0e"
PAE_MULTICAST        = '\x01\x80\xc2\x00\x00\x03' # 802.1x Port Access Entity
NDP_MULTICAST        = '\x01\x23\x20\x00\x00\x01' # Nicira discovery
                                                  # multicast

class ethernet(packet_base):
    "Ethernet packet struct"

    MIN_LEN = 14

    IP_TYPE   = 0x0800
    ARP_TYPE  = 0x0806
    RARP_TYPE = 0x8035
    VLAN_TYPE = 0x8100
    LLDP_TYPE = 0x88cc
    PAE_TYPE  = 0x888e           # 802.1x Port Access Entity

    type_parsers = {}

    def __init__(self, arr=None, prev=None):
        if len(ethernet.type_parsers) == 0:
          # trying to bypass a hairy cyclical include problems
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

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.dst  = array('B', ETHER_ANY)
        self.src  = array('B', ETHER_ANY)
        self.type = 0
        self.next = ''

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def parse(self):
        alen = len(self.arr)
        if alen < ethernet.MIN_LEN:
            self.msg('warning eth packet data too short to parse header: data len %u' % alen)
            return

        self.dst = self.arr[:6]
        self.src = self.arr[6:12]
        self.type = struct.unpack('!H', self.arr[12:ethernet.MIN_LEN])[0]

        self.hdr_len = ethernet.MIN_LEN
        self.payload_len = alen - self.hdr_len

        self.parsed = True

        # xxx Need to support SNAP/LLC frames
        if self.type in ethernet.type_parsers:
            self.next = ethernet.type_parsers[self.type](self.arr[ethernet.MIN_LEN:], self)
        else:
            self.next = self.arr[ethernet.MIN_LEN:].tostring()

    def __str__(self): 
        s = ''.join(('[',mac_to_str(self.src,True),'>',mac_to_str(self.dst,True),':',ethtype_to_str(self.type),']'))
        if self.next == None:
            return s
        elif type(self.next) == type(""):
            return s
        else:    
            return ''.join((s, str(self.next)))


    def hdr(self):        
        dst = self.dst
        src = self.src
        if type(dst) != type(""):
            dst = dst.tostring()
        if type(src) != type(""):
            src = src.tostring()
        return struct.pack('!6s6sH', dst, src, self.type)

"""
# trying to bypass a hairy cyclical include problems
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
"""
