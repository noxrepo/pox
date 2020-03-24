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
from .packet_utils       import *
from .tcp import *
from .udp import *
from .icmp import *
from .igmp import *
from .gre import *

from .packet_base import packet_base

from pox.lib.addresses import IPAddr, IP_ANY, IP_BROADCAST

class ipv4(packet_base):
    "IP packet struct"

    MIN_LEN = 20

    IPv4 = 4
    ICMP_PROTOCOL = 1
    TCP_PROTOCOL  = 6
    UDP_PROTOCOL  = 17
    IGMP_PROTOCOL = 2
    GRE_PROTOCOL  = gre.PROTOCOL

    DF_FLAG = 0x02
    MF_FLAG = 0x01

    ip_id = int(time.time())

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.v     = 4
        self.hl    = ipv4.MIN_LEN // 4
        self.tos   = 0
        self.iplen = ipv4.MIN_LEN
        ipv4.ip_id = (ipv4.ip_id + 1) & 0xffff
        self.id    = ipv4.ip_id
        self.flags = 0
        self.frag  = 0
        self.ttl   = 64
        self.protocol = 0
        self.csum  = 0
        self.srcip = IP_ANY
        self.dstip = IP_ANY
        self.next  = b''
        self.raw_options = b''

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[IP+%s %s>%s (cs:%02x v:%s hl:%s l:%s t:%s)]" % (
            ipproto_to_str(self.protocol),
            self.srcip, self.dstip,
            self.csum,
            self.v, self.hl, self.iplen, self.ttl)

        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        dlen = len(raw)
        if dlen < ipv4.MIN_LEN:
            self.msg('warning IP packet data too short to parse header: data len %u' % (dlen,))
            return

        (vhl, self.tos, self.iplen, self.id, self.frag, self.ttl,
            self.protocol, self.csum, self.srcip, self.dstip) \
             = struct.unpack('!BBHHHBBHII', raw[:ipv4.MIN_LEN])

        self.v = vhl >> 4
        self.hl = vhl & 0x0f

        self.flags = self.frag >> 13
        self.frag  = self.frag & 0x1fff

        self.dstip = IPAddr(self.dstip)
        self.srcip = IPAddr(self.srcip)

        if self.v != ipv4.IPv4:
            self.msg('(ip parse) warning: IP version %u not IPv4' % self.v)
            return
        if self.hl < 5:
            self.msg('(ip parse) warning: IP header length shorter than MIN_LEN (IHL=%u => header len=%u)' \
                        % (self.hl, 4 * self.hl))
            return
        if self.iplen < ipv4.MIN_LEN:
            self.msg('(ip parse) warning: Invalid IP len %u' % self.iplen)
            return
        if (self.hl * 4) > self.iplen:
            self.msg('(ip parse) warning: IP header longer than IP length including payload (%u vs %u)' \
                        % (self.hl, self.iplen))
            return
        if (self.hl * 4) > dlen:
            self.msg('(ip parse) warning: IP header is truncated')
            return

        self.raw_options = raw[self.MIN_LEN:self.hl*4]
        # At this point, we are reasonably certain that we have an IP
        # packet
        self.parsed = True

        length = self.iplen
        if length > dlen:
            length = dlen # Clamp to what we've got
        if self.frag != 0:
            # We can't parse payloads!
            self.next =  raw[self.hl*4:length]
        elif self.protocol == ipv4.UDP_PROTOCOL:
            self.next = udp(raw=raw[self.hl*4:length], prev=self)
        elif self.protocol == ipv4.TCP_PROTOCOL:
            self.next = tcp(raw=raw[self.hl*4:length], prev=self)
        elif self.protocol == ipv4.ICMP_PROTOCOL:
            self.next = icmp(raw=raw[self.hl*4:length], prev=self)
        elif self.protocol == ipv4.IGMP_PROTOCOL:
            self.next = igmp(raw=raw[self.hl*4:length], prev=self)
        elif self.protocol == ipv4.GRE_PROTOCOL:
            self.next = gre(raw=raw[self.hl*4:length], prev=self)
        elif dlen < self.iplen:
            self.msg('(ip parse) warning IP packet data shorter than IP len: %u < %u' % (dlen, self.iplen))
        else:
            self.next =  raw[self.hl*4:length]

        if isinstance(self.next, packet_base) and not self.next.parsed:
            self.next = raw[self.hl*4:length]

    def checksum(self):
        data = struct.pack('!BBHHHBBHII', (self.v << 4) + self.hl, self.tos,
                                 self.iplen, self.id,
                                 (self.flags << 13) | self.frag, self.ttl,
                                 self.protocol, 0, self.srcip.toUnsigned(),
                                 self.dstip.toUnsigned()) + self.raw_options
        return checksum(data, 0)


    def hdr(self, payload):
        self.iplen = self.hl * 4 + len(payload)
        self.csum = self.checksum()
        return struct.pack('!BBHHHBBHII', (self.v << 4) + self.hl, self.tos,
                           self.iplen, self.id,
                           (self.flags << 13) | self.frag, self.ttl,
                           self.protocol, self.csum, self.srcip.toUnsigned(),
                           self.dstip.toUnsigned()) + self.raw_options
