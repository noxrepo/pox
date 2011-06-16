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
#
#                      802.1q VLAN Header Format
#
#    0                   1                   2                   3   
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | PCP  |C|       VLANID         |       Encapsualted protocol   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct
import time

from packet_base import packet_base 
from ethernet import ethernet 

from arp      import arp 
from tcp      import tcp 
from ipv4     import ipv4 
from udp      import udp 

from packet_utils       import *
from array    import *


class vlan(packet_base):
    "802.1q vlan header"

    MIN_LEN = 4

    def __init__(self, arr=None, prev=None):
        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.next = None
        self.parsed = False

        if type(ethernet) == type(time):
            ethernet.ethernet.type_parsers[ethernet.VLAN_TYPE] = vlan
        else:    
            ethernet.type_parsers[ethernet.VLAN_TYPE] = vlan

        self.pcp      = 0 
        self.cfi      = 0 
        self.id       = 0
        self.eth_type = 0 

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self): 
        s = ''.join(('(vlanid='+str(self.id)+':pcp='+str(self.pcp)+")["+ethtype_to_str(self.eth_type)+']'))
        if self.next == None:
            return s
        return ''.join((s, str(self.next)))

    def parse(self):
        dlen = len(self.arr)
        if dlen < vlan.MIN_LEN:
            self.msg('(vlan parse) warning VLAN packet data too short to parse header: data len %u' % dlen)
            return 

        (pcpid, self.eth_type) = struct.unpack("!HH", \
                self.arr[:vlan.MIN_LEN])

        self.pcp = pcpid >> 13
        self.c   = pcpid  & 0x1000
        self.id  = pcpid  & 0x0fff

        self.parsed = True

        if self.eth_type in ethernet.type_parsers:
            self.next = ethernet.type_parsers[self.eth_type](arr=self.arr[vlan.MIN_LEN:],prev=self)

    def hdr(self):
        pcpid  = self.pcp << 13
        pcpid |= self.c   << 12
        pcpid |= self.id
        buf = struct.pack("!HH", pcpid, self.eth_type)
        return buf
