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
#                            UDP Header Format
#
#                  0      7 8     15 16    23 24    31  
#                 +--------+--------+--------+--------+ 
#                 |     Source      |   Destination   | 
#                 |      Port       |      Port       | 
#                 +--------+--------+--------+--------+ 
#                 |                 |                 | 
#                 |     Length      |    Checksum     | 
#                 +--------+--------+--------+--------+ 
#                 |                                     
#                 |          data octets ...            
#                 +---------------- ...                
#======================================================================
import struct
from packet_utils       import *
from packet_exceptions  import *
from array import *
from dhcp import *
from dns  import *

from packet_base import packet_base 

class udp(packet_base):
    "UDP packet struct"

    MIN_LEN = 8

    def __init__(self, arr=None, prev=None):

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.srcport = 0
        self.dstport = 0
        self.len = 8
        self.csum = 0
        self.payload = ''

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        s = ''.join(('{', str(self.srcport), '>', \
                         str(self.dstport), '} l:', \
                         str(self.len), ' c: ', str(self.csum)))

        if self.next == None or type(self.next) == type(''):
            return s
        return ''.join((s, str(self.next))) 


    def parse(self):
        dlen = len(self.arr)
        if dlen < udp.MIN_LEN:
            self.msg('(udp parse) warning UDP packet data too short to parse header: data len %u' % dlen)
            return

        (self.srcport, self.dstport, self.len, self.csum) \
            = struct.unpack('!HHHH', self.arr[:udp.MIN_LEN])

        self.hdr_len = udp.MIN_LEN
        self.payload_len = self.len - self.hdr_len
        self.parsed = True

        if self.len < udp.MIN_LEN:
            self.msg('(udp parse) warning invalid UDP len %u' % self.len)
            return

        if (self.dstport == dhcp.SERVER_PORT 
                    or self.dstport == dhcp.CLIENT_PORT):
            self.next = dhcp(arr=self.arr[udp.MIN_LEN:],prev=self)
        elif (self.dstport == dns.SERVER_PORT 
                    or self.srcport == dns.SERVER_PORT):
            self.next = dns(arr=self.arr[udp.MIN_LEN:],prev=self)
        elif dlen < self.len:
            self.msg('(udp parse) warning UDP packet data shorter than UDP len: %u < %u' % (dlen, self.len))
            return

        self.payload = self.arr[udp.MIN_LEN:]     

    def hdr(self):    
        return struct.pack('!HHHH', self.srcport, self.dstport, self.len, self.csum)

    def checksum(self):    
        assert(isinstance(self.next, packet_base) or type(self.next) == type(''))

        csum = 0
        if self.prev.__class__.__name__ != 'ipv4':
            self.msg('(tcp checksum) tcp packet not in ipv4, cannot calculate checksum over psuedo-header' )
            return 0

        ippacket = struct.pack('!IIBBH', self.prev.srcip, \
                                         self.prev.dstip, \
                                         0,\
                                         self.prev.protocol, \
                                         len(self.arr))
        udphdr = self.hdr()
        if isinstance(self.next, packet_base):
            return checksum(ippacket + udphdr + self.next.tostring(), 0, 9)
        else:
            return checksum(ippacket + udphdr + self.next, 0, 9)
           
