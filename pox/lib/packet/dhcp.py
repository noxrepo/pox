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
#                     DHCP Message Format
#
#  0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
#   +---------------+---------------+---------------+---------------+
#   |                            xid (4)                            |
#   +-------------------------------+-------------------------------+
#   |           secs (2)            |           flags (2)           |
#   +-------------------------------+-------------------------------+
#   |                          ciaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          yiaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          siaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          giaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          chaddr  (16)                         |
#   |                                                               |
#   |                                                               |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          sname   (64)                         |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          file    (128)                        |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          options (variable)                   |
#   +---------------------------------------------------------------+
#
#======================================================================
import struct
from packet_utils       import *
from packet_exceptions  import *
from array import *

from packet_base import packet_base 

class dhcp(packet_base):
    "DHCP Packet struct"

    STRUCT_BOUNDARY = 28
    MIN_LEN = 240

    SERVER_PORT = 67
    CLIENT_PORT = 68

    BROADCAST_FLAG = 0x8000

    BOOTREQUEST = 1
    BOOTREPLY = 2

    MSG_TYPE_OPT = 53
    NUM_MSG_TYPES = 8
    DISCOVER_MSG = 1
    OFFER_MSG = 2
    REQUEST_MSG = 3
    DECLINE_MSG = 4
    ACK_MSG = 5
    NAK_MSG = 6
    RELEASE_MSG = 7
    INFORM_MSG = 8

    SUBNET_MASK_OPT = 1
    GATEWAY_OPT = 3
    DNS_SERVER_OPT = 6
    HOST_NAME_OPT = 12
    DOMAIN_NAME_OPT = 15
    MTU_OPT = 26
    BCAST_ADDR_OPT = 28

    REQUEST_IP_OPT = 50
    REQUEST_LEASE_OPT = 51
    OVERLOAD_OPT = 52
    SERVER_ID_OPT = 54
    PARAM_REQ_OPT = 55
    T1_OPT = 58
    T2_OPT = 59
    CLIENT_ID_OPT = 61
    PAD_OPT = 0
    END_OPT = 255

    MAGIC = array('B', '\x63\x82\x53\x63')

    def __init__(self, arr=None, prev=None):
        self.prev = prev

        if self.prev == None:
            self.op = 0
            self.htype = 0
            self.hlen = 0
            self.hops = 0
            self.xid = 0
            self.secs = 0
            self.flags = 0
            self.ciaddr = 0
            self.yiaddr = 0
            self.siaddr = 0
            self.giaddr = 0
            self.chaddr = array('B')
            self.sname = array('B')
            self.file = array('B')
            self.magic = array('B')
            self.options = array('B')
            self.parsedOptions = {}
        else:
            if type(arr) == type(''):
                arr = array('B', arr)
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        if self.parsed == False:
            return ""

        return ' '.join(('[','op:'+str(self.op),'htype:'+str(self.htype), \
                            'hlen:'+str(self.hlen),'hops:'+str(self.hops), \
                            'xid:'+str(self.xid),'secs:'+str(self.secs), \
                            'flags:'+str(self.flags), \
                            'ciaddr:'+ip_to_str(self.ciaddr), \
                            'yiaddr:'+ip_to_str(self.yiaddr), \
                            'siaddr:'+ip_to_str(self.siaddr), \
                            'giaddr:'+ip_to_str(self.giaddr), \
                            'chaddr:'+mac_to_str(self.chaddr[:self.hlen]), \
                            'magic:'+str(self.magic), \
                            'options:'+str(self.options),']'))

    def parse(self):
        dlen = len(self.arr)
        if dlen < dhcp.MIN_LEN:
            self.msg('(dhcp parse) warning DHCP packet data too short to parse header: data len %u' % dlen)
            return None

        (self.op, self.htype, self.hlen, self.hops, self.xid, self.secs, \
             self.flags, self.ciaddr, self.yiaddr, self.siaddr, self.giaddr) \
             = struct.unpack('!BBBBIHHIIII', self.arr[:28])
         
        self.chaddr = self.arr[28:44]
        self.sname = self.arr[44:108]
        self.file = self.arr[102:236]
        self.magic = self.arr[236:240]

        self.hdr_len = dlen
        self.parsed = True

        if self.hlen > 16:
            self.warn('(dhcp parse) DHCP hlen %u too long' % self.hlen)
            return

        for i in range(4):
            if dhcp.MAGIC[i] != self.magic[i]:
                self.warn('(dhcp parse) bad DHCP magic value %s' % str(self.magic))
                return

        self.parsedOptions = {}

        self.options = self.arr[240:]
        self.parseOptions()
        self.parsed = True

    def parseOptions(self):
        self.parsedOptions = {}
        self.parseOptionSegment(self.options)
        if self.parsedOptions.has_key(dhcp.OVERLOAD_OPT):
            opt_val = self.parsedOptions[dhcp.OVERLOAD_OPT]
            if opt_val[0] != 1:
                self.warn('DHCP overload option has bad len %u' % opt_val[0])
                return
            if opt_val[1] == 1 or opt_val[1] == 3:
                self.parseOptionSegment(self.file)
            if opt_val[1] == 2 or opt_val[1] == 3:
                self.parseOptionSegment(self.sname)

    def parseOptionSegment(self, barr):
        ofs = 0;
        len = barr.buffer_info()[1]
        while ofs < len:
            opt = barr[ofs]
            if opt == dhcp.END_OPT:
                return
            ofs += 1
            if opt == dhcp.PAD_OPT:
                continue
            if ofs >= len:
                self.warn('DHCP option ofs extends past segment')
                return
            opt_len = barr[ofs]
            ofs += 1         # Account for the length octet
            if ofs + opt_len > len:
                return False
            if self.parsedOptions.has_key(opt):
                self.info('(parseOptionSegment) ignoring duplicate DHCP option: %d' % opt)
            else:
                self.parsedOptions[opt] = barr[ofs:ofs+opt_len]
            ofs += opt_len
        self.warn('DHCP end of option segment before END option')

    def hdr(self):
        fmt = '!BBBBIHHIIII16s64s128s4s%us' % self.options.buffer_info()[1]
        return struct.pack(fmt, self.op, self.htype, self.hlen, \
                    self.hops, self.xid, self.secs, self.flags, \
                    self.ciaddr, self.yiaddr, self.siaddr, self.giaddr, \
                    self.chaddr.tostring(), self.sname.tostring(), \
                    self.file.tostring(), self.magic.tostring(), \
                    self.options.tostring())

    def hasParsedOption(self, opt, len):
        if self.parsedOptions.has_key(opt) == False:
            return False
        if len != None and self.parsedOptions[opt][0][0] != len:
            return False
        return True

    def addUnparsedOption(self, code, len, val):
        self.options.append(code)
        self.options.append(len)
        self.options.extend(val)
