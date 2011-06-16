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
#                           TCP Header Format
#
#   0                   1                   2                   3   
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Data |           |U|A|P|R|S|F|                               |
#  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
#  |       |           |G|K|H|T|N|N|                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           Checksum            |         Urgent Pointer        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Options                    |    Padding    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct
from packet_utils       import *
from packet_exceptions  import *
from socket import htons
from socket import htonl
from array import *

from packet_base import packet_base 

class tcp_opt:

    EOL      = 0
    NOP      = 1
    MSS      = 2
    WSOPT    = 3
    SACKPERM = 4
    SACK     = 5
    TSOPT    = 8

    def __init__(self, type, val):
        self.type = type 
        self.val  = val

    def to_bytes(self):    
        if self.type == tcp_opt.EOL or self.type == tcp_opt.NOP:
            return struct.pack('B',self.type) 
        elif self.type == tcp_opt.MSS:
            return struct.pack('!BBH',self.type,4,self.val) 
        elif self.type == tcp_opt.WSOPT:
            return struct.pack('!BBB',self.type,3,self.val) 
        elif self.type == tcp_opt.SACKPERM:
            return struct.pack('!BB',self.type,2) 
        elif self.type == tcp_opt.TSOPT:
            return struct.pack('!BBII',self.type,10,self.val[0],self.val[1]) 
        else:    
            self.msg('(tcp_opt to_bytes) warning, unknown option')
            return '' 

class tcp(packet_base):
    "TCP packet struct"

    MIN_LEN = 20 

    FIN  = 0x01
    SYN  = 0x02
    RST  = 0x04
    PUSH = 0x08
    ACK  = 0x10
    URG  = 0x20
    ECN  = 0x40
    CWR  = 0x80

    def __init__(self, arr=None, prev=None):

        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.srcport  = 0 # 16 bit
        self.dstport  = 0 # 16 bit
        self.seq      = 0 # 32 bit
        self.ack      = 0 # 32 bit
        self.off      = 0 # 4 bits
        self.res      = 0 # 4 bits
        self.flags    = 0 # reserved, 2 bits flags 6 bits
        self.win      = 0 # 16 bits
        self.csum     = 0 # 16 bits
        self.urg      = 0 # 16 bits
        self.tcplen   = 20 # Options? 
        self.options  = [] 
        self.next     = ''

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        s = ''.join(('{', str(self.srcport), '>', \
                         str(self.dstport), '} seq:', \
                         str(self.seq), ' ack:', str(self.ack), ' f:',
                         hex(self.flags)))
        if self.next == None or type(self.next) == type(''):
            return s
        return ''.join((s, str(self.next))) 

    def parse_options(self):    
        
        self.options = []
        dlen = len(self.arr)

        # option parsing    
        i = tcp.MIN_LEN 
        arr = self.arr

        while i < self.hdr_len:
            if (arr[i] > 1) and (i + 2 > dlen or arr[i] + arr[i+1] > dlen or arr[i+1] < 2):
                raise Exception() 
            elif arr[i] == tcp_opt.EOL:    
                break 
            elif arr[i] == tcp_opt.NOP:    
                self.options.append(tcp_opt(tcp_opt.NOP,None))
                i += 1
                continue
            elif arr[i] == tcp_opt.MSS:    
                if arr[i+1] != 4:
                    raise Exception() 
                val = struct.unpack('!H',arr[i+2:i+4])    
                self.options.append(tcp_opt(tcp_opt.MSS,val))
            elif arr[i] == tcp_opt.WSOPT:    
                if arr[i+1] != 3:
                    raise Exception()
                self.options.append(tcp_opt(tcp_opt.WSOPT, arr[i+2]))
            elif arr[i] == tcp_opt.SACKPERM:    
                if arr[i+1] != 2:
                    raise Exception() 
                self.options.append(tcp_opt(tcp_opt.SACKPERM, None))
            elif arr[i] == tcp_opt.TSOPT:    
                if arr[i+1] != 10:
                    raise Exception() 
                (val1,val2) = struct.unpack('!II',arr[i+2:i+10])    
                self.options.append(tcp_opt(tcp_opt.TSOPT,(val1,val2)))
            else:
                self.msg('(tcp parse_options) warning, unknown option %x '\
                % arr[i])
                self.options.append(tcp_opt(arr[i], arr[i+2:i+2+arr[i+1]]))
            
            i += arr[i+1]
        return i    

    def parse(self):
        dlen = len(self.arr)
        if dlen < tcp.MIN_LEN:
            self.msg('(tcp parse) warning TCP packet data too short to parse header: data len %u' % dlen)
            return

        (self.srcport, self.dstport, self.seq, self.ack, offres, self.flags,\
        self.win, self.csum, self.urg) \
            = struct.unpack('!HHIIBBHHH', self.arr[:tcp.MIN_LEN])

        self.off = offres >> 4
        self.res = offres & 0x0f

        self.hdr_len = self.off * 4
        self.payload_len = dlen - self.hdr_len

        self.tcplen = dlen
        if dlen < self.tcplen:
            self.msg('(tcp parse) warning TCP packet data shorter than TCP len: %u < %u' % (dlen, self.tcplen))
            return
        if (self.off * 4) < self.MIN_LEN or (self.off * 4) > dlen :
            self.msg('(tcp parse) warning TCP data offset too long or too short %u' % (self.off))
            return

        try:
            self.parse_options()
        except Exception, e:    
            self.msg(e) 
            return

        self.next   = self.arr[self.hdr_len:].tostring()
        self.parsed = True

    def hdr(self):    
        offres = self.off << 4 | self.res
        packet = struct.pack('!HHIIBBHHH',\
            self.srcport, self.dstport, self.seq, self.ack, offres, self.flags,\
            self.win, self.csum, self.urg) 
        for option in self.options:
            packet += option.to_bytes()
        return packet    

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
        tcphdr = self.hdr()                                
        if isinstance(self.next, packet_base):
            return checksum(ippacket + tcphdr + self.next.tostring(), 0, 14)
        else:    
            return checksum(ippacket + tcphdr + self.next, 0, 14)

