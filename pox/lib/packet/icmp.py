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
#                            ICMP Header Format
#
#   0                   1                   2                   3   
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |      Type     |      Code     |           Checksum            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             Data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#
#======================================================================
import struct
import random
from packet_utils       import *
from packet_exceptions  import *
from array import *

from packet_base import packet_base 


TYPE_ECHO_REPLY   = 0
TYPE_DEST_UNREACH = 3
TYPE_SRC_QUENCH   = 4
TYPE_REDIRECT     = 5
TYPE_ECHO_REQUEST = 8
TYPE_TIME_EXCEED  = 11

CODE_UNREACH_NET     = 0
CODE_UNREACH_HOST    = 1
CODE_UNREACH_PROTO   = 2
CODE_UNREACH_PORT    = 3
CODE_UNREACH_FRAG    = 4
CODE_UNREACH_SRC_RTE = 5

#----------------------------------------------------------------------
#
#  Echo Request/Reply
#   0                   1                   2                   3   
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           Identifier          |        Sequence Number        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             Data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#----------------------------------------------------------------------
class echo(packet_base):
    "ICMP echo packet struct"

    MIN_LEN = 4

    def __init__(self, arr=None, prev=None):

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.id  = random.randint(0, 65535)
        self.seq = 0

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        return ''.join(('{', 'id:', str(self.id), 'seq:', str(self.seq), '}'))

    def parse(self):
        dlen = len(self.arr)

        if dlen < self.MIN_LEN:
            self.msg('(echo parse) warning echo payload too short to parse header: data len %u' % dlen)
            return

        (self.id, self.seq) \
            = struct.unpack('!HH', self.arr[:self.MIN_LEN])

        self.parsed = True
        self.next = self.arr[echo.MIN_LEN:].tostring()

    def hdr(self):    
        return struct.pack('!HH', self.id, self.seq)

    def tostring(self):    
        buf = self.hdr()

        if self.next == None:
            return buf
        elif isinstance(self.next, packet_base):
            return ''.join((buf, self.next.tostring()))
        else: 
            return ''.join((buf, self.next))

#----------------------------------------------------------------------
#
#  Destination Unreachable
#   0                   1                   2                   3   
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |            Unused             |         Next-Hop MTU          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |       IP Header + 8 bytes of original datagram's data         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#----------------------------------------------------------------------
class unreach(packet_base):
    "ICMP unreachable packet struct"

    MIN_LEN = 4

    def __init__(self, arr=None, prev=None):

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.unused = 0
        self.next_mtu = 0

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        s = ''.join(('{', 'm:', str(self.next_mtu), '}'))

        if self.next == None:
            return s

        return ''.join((s, str(self.next))) 

    def parse(self):
        dlen = len(self.arr)
        if dlen < self.MIN_LEN:
            self.msg('(unreach parse) warning unreachable payload too short to parse header: data len %u' % dlen)
            return

        (self.unused, self.next_mtu) \
            = struct.unpack('!HH', self.arr[:self.MIN_LEN])

        self.parsed = True

        if dlen >= 28:
            # xxx We're assuming this is IPv4!
            import ipv4
            self.next = ipv4.ipv4(arr=self.arr[unreach.MIN_LEN:],prev=self)
        else:
            self.next = self.arr[unreach.MIN_LEN:].tostring()

    def hdr(self):    
        return struct.pack('!HH', self.unused, self.next_mtu)

    def tostring(self):    
        buf = self.hdr()

        if self.next == None:
            return buf
        elif isinstance(self.next, packet_base):
            self.next.tostring()

            return ''.join((buf, self.next.tostring()))
        else: 
            return ''.join((buf, self.next))

class icmp(packet_base):
    "ICMP packet struct"

    MIN_LEN = 4

    def __init__(self, arr=None, prev=None):

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.type = 0
        self.code = 0
        self.csum = 0

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        s = ''.join(('{', 't:', str(self.type), ' c:', str(self.code), 
                         ' csum: ', str(hex(self.csum)), '}'))

        if self.next == None:
            return s

        return ''.join((s, str(self.next))) 

    def parse(self):
        dlen = len(self.arr)
        if dlen < self.MIN_LEN:
            self.msg('(icmp parse) warning ICMP packet data too short to parse header: data len %u' % dlen)
            return

        (self.type, self.code, self.csum) \
            = struct.unpack('!BBH', self.arr[:self.MIN_LEN])

        self.parsed = True

        if (self.type == TYPE_ECHO_REQUEST or self.type == TYPE_ECHO_REPLY):
            self.next = echo(arr=self.arr[self.MIN_LEN:],prev=self)
        elif self.type == TYPE_DEST_UNREACH:
            self.next = unreach(arr=self.arr[self.MIN_LEN:],prev=self)

    def hdr(self):        
        return struct.pack('!BBH', self.type, self.code, self.csum)
