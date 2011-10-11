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
from packet_utils import *

from packet_base import packet_base
import pox.lib.util as util
from pox.lib.addresses import *

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

    MAGIC = b'\x63\x82\x53\x63'

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.op = 0
        self.htype = 0
        self.hlen = 0
        self.hops = 0
        self.xid = 0
        self.secs = 0
        self.flags = 0
        self.ciaddr = IP_ANY
        self.yiaddr = IP_ANY
        self.siaddr = IP_ANY
        self.giaddr = IP_ANY
        self.chaddr = None
        self.sname = b''
        self.file = b''
        self.magic = b''
        self._raw_options = b''

        if raw is not None:
            self.parse(raw)
        else:
            self.options = util.DirtyDict()

        self._init(kw)

    def __str__(self):
        s  = '[op:'+str(self.op)
        s += ' htype:'+str(self.htype)
        s += ' hlen:'+str(self.hlen)
        s += ' hops:'+str(self.hops)
        s += ' xid:'+str(self.xid)
        s += ' secs:'+str(self.secs)
        s += ' flags:'+str(self.flags)
        s += ' ciaddr:'+str(self.ciaddr)
        s += ' yiaddr:'+str(self.yiaddr)
        s += ' siaddr:'+str(self.siaddr)
        s += ' giaddr:'+str(self.giaddr)
        s += ' chaddr:'
        if isinstance(self.chaddr, EthAddr):
            s += str(self.chaddr)
        else:
            s += ' '.join(["{0:02x}".format(x) for x in self.chaddr])
        s += ' magic:'+' '.join(["{0:02x}".format(x) for x in self.magic])
        s += ' options:'+' '.join(["{0:02x}".format(x) for x in
                                  self._raw_options])
        s += ']'
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < dhcp.MIN_LEN:
            self.msg('(dhcp parse) warning DHCP packet data too short ' +
                     'to parse header: data len %u' % (dlen,))
            return None

        (self.op, self.htype, self.hlen, self.hops, self.xid,self.secs,
         self.flags, self.ciaddr, self.yiaddr, self.siaddr,
         self.giaddr) = struct.unpack('!BBBBIHHIIII', raw[:28])

        self.ciaddr = IPAddr(self.ciaddr)
        self.yiaddr = IPAddr(self.yiaddr)
        self.siaddr = IPAddr(self.siaddr)
        self.giaddr = IPAddr(self.giaddr)

        self.chaddr = raw[28:44]
        if self.hlen == 6:
            # Assume chaddr is ethernet
            self.chaddr = EthAddr(self.chaddr[:6])
        self.sname = raw[44:108]
        self.file = raw[102:236]
        self.magic = raw[236:240]

        self.hdr_len = dlen
        self.parsed = True

        if self.hlen > 16:
            self.warn('(dhcp parse) DHCP hlen %u too long' % (self.hlen),)
            return

        for i in range(4):
            if dhcp.MAGIC[i] != self.magic[i]:
                self.warn('(dhcp parse) bad DHCP magic value %s' %
                          str(self.magic))
                return

        self._raw_options = raw[240:]
        self.parseOptions()
        self.parsed = True

    def parseOptions(self):
        self.options = util.DirtyDict()
        self.parseOptionSegment(self._raw_options)
        if dhcp.OVERLOAD_OPT in self.options:
            opt_val = self.options[dhcp.OVERLOAD_OPT]
            if opt_val[0] != 1:
                self.warn('DHCP overload option has bad len %u' %
                          (opt_val[0],))
                return
            if opt_val[1] == 1 or opt_val[1] == 3:
                self.parseOptionSegment(self.file)
            if opt_val[1] == 2 or opt_val[1] == 3:
                self.parseOptionSegment(self.sname)

    def parseOptionSegment(self, barr):
        ofs = 0;
        l = len(barr)
        while ofs < l:
            opt = ord(barr[ofs])
            if opt == dhcp.END_OPT:
                return
            ofs += 1
            if opt == dhcp.PAD_OPT:
                continue
            if ofs >= l:
                self.warn('DHCP option ofs extends past segment')
                return
            opt_len = ord(barr[ofs])
            ofs += 1         # Account for the length octet
            if ofs + opt_len > l:
                return False
            if opt in self.options:
                # Append option, per RFC 3396
                self.options[opt] += barr[ofs:ofs+opt_len]
            else:
                self.options[opt] = barr[ofs:ofs+opt_len]
            ofs += opt_len
        self.warn('DHCP end of option segment before END option')

    def packOptions (self):
        o = b''
        def addPart (k, v):
            o = b''
            o += chr(k)
            o += chr(len(v))
            o += bytes(v)
            if len(o) & 1: # Length is not even
                o += chr(dhcp.PAD_OPT)
            return o

        for k,v in self.options.iteritems():
            if k == dhcp.END_OPT: continue
            if k == dhcp.PAD_OPT: continue
            if isinstance(v, bytes) and (len(v) > 255):
                # Long option, per RFC 3396
                v = [v[i:i+255] for i in range(0, len(v), 255)]
            if isinstance(v, list): # Better way to tell?
                for part in v:
                    o += addPart(k, part)
            else:
                o += addPart(k, v)
        o += chr(dhcp.END_OPT)
        self._raw_options = o

        if isinstance(self.options, util.DirtyDict):
            self.options.dirty = False

    def hdr(self, payload):
        if isinstance(self.options, util.DirtyDict):
            if self.options.dirty:
                self.packOptions()
        else:
            self.packOptions()

        if isinstance(self.chaddr, EthAddr):
          chaddr = self.chaddr.toRaw() + (b'\x00' * 10)
        fmt = '!BBBBIHHIIII16s64s128s4s%us' % (len(self._raw_options),)
        return struct.pack(fmt, self.op, self.htype, self.hlen,
                           self.hops, self.xid, self.secs, self.flags,
                           self.ciaddr, self.yiaddr, self.siaddr,
                           self.giaddr, chaddr, self.sname, self.file,
                           self.magic, self._raw_options)

    def appendRawOption (self, code, val = None, length = None):
        """
        In general, a much better way to add options should just be
        to add them to the .options dictionary.
        """
        
        self._raw_options += chr(code)
        if length is None:
            if val is None:
                return
            length = len(val)
        self._raw_options += chr(length)
        self._raw_options += val

