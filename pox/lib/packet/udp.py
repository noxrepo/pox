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
from dhcp import *
from dns  import *

from packet_base import packet_base

class udp(packet_base):
    "UDP packet struct"

    MIN_LEN = 8

    def __init__(self, raw=None, prev=None, **kw):
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
        s = ''.join(('{', str(self.srcport), '>', \
                         str(self.dstport), '} l:', \
                         str(self.len), ' c: ', str(self.csum)))

        if self.next is None or type(self.next) is bytes:
            return s
        return ''.join((s, str(self.next)))


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

        if (self.dstport == dhcp.SERVER_PORT
                    or self.dstport == dhcp.CLIENT_PORT):
            self.next = dhcp(raw=raw[udp.MIN_LEN:],prev=self)
        elif (self.dstport == dns.SERVER_PORT
                    or self.srcport == dns.SERVER_PORT):
            self.next = dns(raw=raw[udp.MIN_LEN:],prev=self)
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

        if self.prev.__class__.__name__ != 'ipv4':
            self.msg('packet not in ipv4, cannot calculate checksum ' +
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

        ippacket = struct.pack('!IIBBH', self.prev.srcip.toUnsigned(),
                                         self.prev.dstip.toUnsigned(),
                                         0,
                                         self.prev.protocol,
                                         payload_len)

        if not unparsed:
          myhdr = struct.pack('!HHHH', self.srcport, self.dstport,
                              payload_len, 0)
          payload = myhdr + payload

        r = checksum(ippacket + payload, 0, 9)
        return 0xffff if r == 0 else r

