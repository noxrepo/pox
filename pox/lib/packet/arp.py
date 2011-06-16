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
#=====================================================================
#
#    0                   1                   2                   3   
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |          Hardware type        |             Protocol type     |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                  Source hardware address :::                  |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                  Source protocol address :::                  |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |               Destination hardware address :::                |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |               Destination protocol address :::                |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           Data :::                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#=====================================================================
import struct

from packet_base import packet_base
from ipv4 import ipv4 

from ethernet import ethernet
from ethernet import ETHER_ANY 
from ethernet import ETHER_BROADCAST 

from array import *
from packet_utils       import *
from packet_exceptions  import *

class arp(packet_base):
    "ARP/RARP packet struct"

    MIN_LEN = 28 

    HW_TYPE_ETHERNET = 1 
    PROTO_TYPE_IP    = 0x0800

    # OPCODES
    REQUEST     = 1 # ARP
    REPLY       = 2 # ARP
    REV_REQUEST = 3 # RARP
    REV_REPLY   = 4 # RARP

    def __init__(self, arr=None, prev=None):
        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.hwtype     = arp.HW_TYPE_ETHERNET 
        self.prototype  = arp.PROTO_TYPE_IP 
        self.hwsrc      = ETHER_ANY
        self.hwdst      = ETHER_ANY
        self.hwlen      = 0
        self.opcode     = 0
        self.protolen   = 0
        self.protosrc   = 0
        self.protodst   = 0
        self.next       = ''

        if arr != None:
            if (type(arr) != array.array):
                self.err("arr of type %s unsupported" % (type(arr),))
                assert(0)
            self.arr = arr
            self.parse()

    def parse(self):
        dlen = len(self.arr)
        if dlen < arp.MIN_LEN:
            self.msg('(arp parse) warning IP packet data too short to parse header: data len %u' % dlen)
            return

        (self.hwtype, self.prototype, self.hwlen, self.protolen,self.opcode) =\
        struct.unpack('!HHBBH', self.arr[:8])
        
        if self.hwtype != arp.HW_TYPE_ETHERNET:
            self.msg('(arp parse) hw type unknown %u' % self.hwtype)
        if self.hwlen != 6:
            self.msg('(arp parse) unknown hw len %u' % self.hwlen)
        if self.prototype != arp.PROTO_TYPE_IP:
            self.msg('(arp parse) proto type unknown %u' % self.prototype)
        if self.protolen != 4: 
            self.msg('(arp parse) unknown proto len %u' % self.protolen)

        self.hwsrc = self.arr[8:14]
        self.protosrc = struct.unpack('!I',self.arr[14:18])[0]
        self.hwdst = self.arr[18:24]
        self.protodst = struct.unpack('!I',self.arr[24:28])[0]

        self.next = self.arr[28:].tostring()
        self.parsed = True

    def hdr(self):    
        buf = struct.pack('!HHBBH', self.hwtype, self.prototype,\
        self.hwlen, self.protolen,self.opcode)
        if type(self.hwsrc) == type(''):
            buf += self.hwsrc
        else:    
            buf += self.hwsrc.tostring()
        buf += struct.pack('!I',self.protosrc)
        if type(self.hwdst) == type(''):
            buf += self.hwdst
        else:    
            buf += self.hwdst.tostring()
        buf += struct.pack('!I',self.protodst)
        return buf

    def __str__(self):
        op = str(self.opcode)

        eth_type = None
        # Ethernet
        if hasattr(self.prev, 'type'):
            eth_type = self.prev.type
        # Vlan 
        elif hasattr(self.prev, 'eth_type'):
            eth_type = self.prev.eth_type
        else:
            self.err('(arp) unknown datalink type')
            eth_type = ethernet.ARP_TYPE

        if eth_type == ethernet.ARP_TYPE:
            if self.opcode == arp.REQUEST:
                op = "REQUEST"
            elif self.opcode == arp.REPLY:
                op = "REPLY"
        elif eth_type == ethernet.RARP_TYPE:
            if self.opcode == arp.REV_REQUEST:
                op = "REV_REQUEST"
            elif self.opcode == arp.REV_REPLY:
                op = "REV_REPLY"

        s = ''.join(('(',op,'[hw:'+str(self.hwtype),'p:'+str(self.prototype),\
                         '[', mac_to_str(self.hwsrc),'>', \
                              mac_to_str(self.hwdst),']:', \
                              '[',ip_to_str(self.protosrc), '>',  \
                                  ip_to_str(self.protodst),'])'))
        return s
