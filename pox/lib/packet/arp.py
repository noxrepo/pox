# Copyright 2011 James McCauley
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

from .packet_base import packet_base
from .ipv4 import ipv4

from .ethernet import ethernet
from .ethernet import ETHER_ANY
from .ethernet import ETHER_BROADCAST

from .ipv4 import IP_ANY
from .ipv4 import IP_BROADCAST

from pox.lib.addresses import IPAddr, EthAddr

from .packet_utils       import *

class arp (packet_base):
    "ARP/RARP packet struct"

    MIN_LEN = 28

    HW_TYPE_ETHERNET = 1
    PROTO_TYPE_IP    = 0x0800

    # OPCODES
    REQUEST     = 1 # ARP
    REPLY       = 2 # ARP
    REV_REQUEST = 3 # RARP
    REV_REPLY   = 4 # RARP

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.hwtype     = arp.HW_TYPE_ETHERNET
        self.prototype  = arp.PROTO_TYPE_IP
        self.hwsrc      = ETHER_ANY
        self.hwdst      = ETHER_ANY
        self.hwlen      = 6
        self.opcode     = 0
        self.protolen   = 4
        self.protosrc   = IP_ANY
        self.protodst   = IP_ANY
        self.next       = b''

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def parse (self, raw):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        dlen = len(raw)
        if dlen < arp.MIN_LEN:
            self.msg('(arp parse) warning IP packet data too short to parse header: data len %u' % dlen)
            return

        (self.hwtype, self.prototype, self.hwlen, self.protolen,self.opcode) =\
        struct.unpack('!HHBBH', raw[:8])

        if self.hwtype != arp.HW_TYPE_ETHERNET:
            self.msg('(arp parse) hw type unknown %u' % self.hwtype)
            return
        if self.hwlen != 6:
            self.msg('(arp parse) unknown hw len %u' % self.hwlen)
            return
        else:
            self.hwsrc = EthAddr(raw[8:14])
            self.hwdst = EthAddr(raw[18:24])
        if self.prototype != arp.PROTO_TYPE_IP:
            self.msg('(arp parse) proto type unknown %u' % self.prototype)
            return
        if self.protolen != 4:
            self.msg('(arp parse) unknown proto len %u' % self.protolen)
            return
        else:
            self.protosrc = IPAddr(struct.unpack('!I',raw[14:18])[0])
            self.protodst = IPAddr(struct.unpack('!I',raw[24:28])[0])

        self.next = raw[28:]
        self.parsed = True

    def hdr(self, payload):
        buf = struct.pack('!HHBBH', self.hwtype, self.prototype,
            self.hwlen, self.protolen,self.opcode)
        if type(self.hwsrc) == bytes:
            buf += self.hwsrc
        else:
            buf += self.hwsrc.toRaw()
        if type(self.protosrc) is IPAddr:
          buf += struct.pack('!I',self.protosrc.toUnsigned())
        else:
          buf += struct.pack('!I',self.protosrc)
        if type(self.hwdst) == bytes:
            buf += self.hwdst
        else:
            buf += self.hwdst.toRaw()
        if type(self.protodst) is IPAddr:
          buf += struct.pack('!I',self.protodst.toUnsigned())
        else:
          buf += struct.pack('!I',self.protodst)
        return buf

    def _to_str(self):
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

        s = "[ARP {0} hw:{1} p:{2} {3}>{4} {5}>{6}]".format(op,
                                                  self.hwtype,
                                                  self.prototype,
                                                  EthAddr(self.hwsrc),
                                                  EthAddr(self.hwdst),
                                                  IPAddr(self.protosrc),
                                                  IPAddr(self.protodst))
        return s
