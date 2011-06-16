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
#                          IPv4 Header Format
#
#    0                   1                   2                   3   
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version|  IHL  |Type of Service|          Total Length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Identification        |Flags|      Fragment Offset    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Time to Live |    Protocol   |         Header Checksum       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination Address                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct
import time
from packet_utils       import *
from packet_exceptions  import *
from array import *
from tcp import *
from udp import *
from icmp import *

from packet_base import packet_base 


class ipv4(packet_base):
    "IP packet struct"

    MIN_LEN = 20

    IPv4 = 4
    ICMP_PROTOCOL = 1
    TCP_PROTOCOL  = 6
    UDP_PROTOCOL  = 17

    DF_FLAG = 0x02
    MF_FLAG = 0x01

    ip_id = 0

    def __init__(self, arr=None, prev=None):

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.v     = 4
        self.hl    = ipv4.MIN_LEN / 4
        self.tos   = 0
        self.iplen = ipv4.MIN_LEN
        self.id    = int(time.time())
        ipv4.ip_id += 1
        self.flags = 0
        self.frag  = 0
        self.ttl   = 64
        self.protocol = 0
        self.csum  = 0
        self.srcip = 0
        self.dstip = 0
        self.next  = ''

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        s = ''.join(('(','[v:'+str(self.v),'hl:'+str(self.hl),\
                         'l:', str(self.iplen),'t:', \
                         str(self.ttl), ']', ipproto_to_str(self.protocol), \
                         ' cs:', '%x' %self.csum, '[',ip_to_str(self.srcip), \
                         '>', ip_to_str(self.dstip),'])'))
        if self.next == None:
            return s
        return ''.join((s, str(self.next)))

    def parse(self):
        dlen = len(self.arr)
        if dlen < ipv4.MIN_LEN:
            self.msg('warning IP packet data too short to parse header: data len %u' % dlen)
            return 

        (vhl, self.tos, self.iplen, self.id, self.frag, self.ttl, 
            self.protocol, self.csum, self.srcip, self.dstip) \
             = struct.unpack('!BBHHHBBHII', self.arr[:ipv4.MIN_LEN])

        self.v = vhl >> 4
        self.hl = vhl & 0x0f

        self.flags = self.frag >> 13
        self.frag  = self.frag & 0x1f 

        if self.v != ipv4.IPv4:
            self.msg('ip parse) warning IP version %u not IPv4' % self.v)
            return
        elif self.hl < 5:
            self.msg('(ip parse) warning IP header %u longer than len %u' \
                        % (self.hl, self.iplen))
            return
        elif self.iplen < ipv4.MIN_LEN:
            self.msg('(ip parse) warning invalid IP len %u' % self.iplen)
            return
        elif (self.hl * 4) >= self.iplen or (self.hl * 4) > dlen:
            self.msg('(ip parse) warning IP header %u longer than len %u' \
                        % (self.hl, self.iplen))
            return

        # At this point, we are reasonably certain that we have an IP
        # packet
        self.parsed = True
        
        length = self.iplen
        if length > dlen: 
            length = dlen # Clamp to what we've got
        if self.protocol == ipv4.UDP_PROTOCOL:
            self.next = udp(arr=self.arr[self.hl*4:length], prev=self)
        elif self.protocol == ipv4.TCP_PROTOCOL:
            self.next = tcp(arr=self.arr[self.hl*4:length], prev=self)
        elif self.protocol == ipv4.ICMP_PROTOCOL:
            self.next = icmp(arr=self.arr[self.hl*4:length], prev=self)
        elif dlen < self.iplen:
            self.msg('(ip parse) warning IP packet data shorter than IP len: %u < %u' % (dlen, self.iplen))
        else:
            self.next =  self.arr[self.hl*4:length].tostring()

        if isinstance(self.next, packet_base) and not self.next.parsed:
            self.next =  self.arr[self.hl*4:length].tostring()

    def checksum(self):    
        data = struct.pack('!BBHHHBBHII', (self.v << 4) + self.hl, self.tos, \
                                 self.iplen, self.id, \
                                 (self.flags << 13) | self.frag, self.ttl, \
                                 self.protocol, 0, self.srcip, \
                                 self.dstip)
        return checksum(data, 0)


    def hdr(self):
        self.csum = self.checksum()
        return struct.pack('!BBHHHBBHII', (self.v << 4) + self.hl, self.tos, \
                                 self.iplen, self.id, (self.flags << 13) | self.frag, self.ttl, \
                                 self.protocol, self.csum, self.srcip, \
                                 self.dstip)

