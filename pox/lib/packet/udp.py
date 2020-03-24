# Copyright 2011,2017 James McCauley
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
from .packet_utils import *
from .dhcp import *
from .dns  import *
from .rip  import *
from .vxlan import *

from .packet_base import packet_base

# We grab ipv4 later to prevent cyclic dependency
#_ipv4 = None

class udp(packet_base):
    "UDP packet struct"

    MIN_LEN = 8

    def __init__(self, raw=None, prev=None, **kw):
        #global _ipv4
        #if not _ipv4:
        #  from ipv4 import ipv4
        #  _ipv4 = ipv4

        packet_base.__init__(self)

        self.prev = prev

        self.srcport = 0
        self.dstport = 0
        self.len = 8
        self.csum = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[UDP %s>%s l:%s c:%02x]' % (self.srcport, self.dstport,
                                         self.len, self.csum)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < udp.MIN_LEN:
            self.msg('(udp parse) warning UDP packet data too short to parse header: data len %u' % dlen)
            return

        (self.srcport, self.dstport, self.len, self.csum) \
            = struct.unpack('!HHHH', raw[:udp.MIN_LEN])

        self.hdr_len = udp.MIN_LEN
        self.payload_len = self.len - self.hdr_len
        self.parsed = True

        if self.len < udp.MIN_LEN:
            self.msg('(udp parse) warning invalid UDP len %u' % self.len)
            return

        #TODO: DHCPv6, etc.

        if (self.dstport == dhcp.SERVER_PORT
                    or self.dstport == dhcp.CLIENT_PORT):
            self.next = dhcp(raw=raw[udp.MIN_LEN:],prev=self)
        elif (self.dstport == dns.SERVER_PORT
                    or self.srcport == dns.SERVER_PORT):
            self.next = dns(raw=raw[udp.MIN_LEN:],prev=self)
        elif (self.dstport == dns.MDNS_PORT
                    or self.srcport == dns.MDNS_PORT):
            self.next = dns(raw=raw[udp.MIN_LEN:],prev=self)
        elif ( (self.dstport == rip.RIP_PORT
                or self.srcport == rip.RIP_PORT) ):
#               and isinstance(self.prev, _ipv4)
#               and self.prev.dstip == rip.RIP2_ADDRESS ):
            self.next = rip(raw=raw[udp.MIN_LEN:],prev=self)
        elif (self.dstport == vxlan.VXLAN_PORT
                    or self.srcport == vxlan.VXLAN_PORT):
            self.next = vxlan(raw=raw[udp.MIN_LEN:],prev=self)
        elif dlen < self.len:
            self.msg('(udp parse) warning UDP packet data shorter than UDP len: %u < %u' % (dlen, self.len))
            return
        else:
            self.payload = raw[udp.MIN_LEN:]


    def hdr(self, payload):
        self.len = len(payload) + udp.MIN_LEN
        self.csum = self.checksum()
        return struct.pack('!HHHH', self.srcport, self.dstport, self.len, self.csum)

    def checksum(self, unparsed=False):
        """
        Calculates the checksum.
        If unparsed, calculates it on the raw, unparsed data.  This is
        useful for validating that it is correct on an incoming packet.
        """

        ip_ver = None
        if self.prev.__class__.__name__  == 'ipv4':
          ip_ver = 4
        elif self.prev.__class__.__name__  == 'ipv6':
          ip_ver = 6
        else:
          self.msg('packet not in IP; cannot calculate checksum ' +
                    'over psuedo-header' )
          return 0

        if unparsed:
            payload_len = len(self.raw)
            payload = self.raw
        else:
            if isinstance(self.next, packet_base):
                payload = self.next.pack()
            elif self.next is None:
                payload = bytes()
            else:
                payload = self.next
            payload_len = udp.MIN_LEN + len(payload)

            myhdr = struct.pack('!HHHH', self.srcport, self.dstport,
                                payload_len, 0)
            payload = myhdr + payload

        if ip_ver == 4:
            ph = struct.pack('!IIBBH', self.prev.srcip.toUnsigned(),
                                       self.prev.dstip.toUnsigned(),
                                       0,
                                       self.prev.protocol,
                                       payload_len)
            r = checksum(ph + payload, 0, 9)
            return 0xffff if r == 0 else r
        elif ip_ver == 6:
            ph = self.prev.srcip.raw + self.prev.dstip.raw
            ph += struct.pack('!IHBB', payload_len, 0, 0,
                              self.prev.next_header_type)
            r = checksum(ph + payload, 0, 23)
            return 0xffff if r == 0 else r
