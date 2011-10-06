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

_type_to_name = {
    0   : "ECHO_REPLY",
    3   : "DEST_UNREACH",
    4   : "SRC_QUENCH",
    5   : "REDIRECT",
    8   : "ECHO_REQUEST",
    11  : "TIME_EXCEED",
}

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

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.id  = random.randint(0, 65535)
        self.seq = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        return "{id:%i seq:%i}" % (self.id, self.seq)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw

        dlen = len(raw)

        if dlen < self.MIN_LEN:
            self.msg('(echo parse) warning echo payload too short to '
                     'parse header: data len %u' % (dlen,))
            return

        (self.id, self.seq) = struct.unpack('!HH', raw[:self.MIN_LEN])

        self.parsed = True
        self.next = raw[echo.MIN_LEN:]

    def hdr(self, payload):
        return struct.pack('!HH', self.id, self.seq)


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

    def __init__(self, raw=None, prev=None, **kw):

        self.prev = prev

        self.unused = 0
        self.next_mtu = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = ''.join(('{', 'm:', str(self.next_mtu), '}'))

        if self.next is None:
            return s

        return ''.join((s, str(self.next)))

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(unreach parse) warning unreachable payload too short to parse header: data len %u' % dlen)
            return

        (self.unused, self.next_mtu) \
            = struct.unpack('!HH', raw[:self.MIN_LEN])

        self.parsed = True

        if dlen >= 28:
            # xxx We're assuming this is IPv4!
            import ipv4
            self.next = ipv4.ipv4(raw=raw[unreach.MIN_LEN:],prev=self)
        else:
            self.next = raw[unreach.MIN_LEN:]

    def hdr(self, payload):
        return struct.pack('!HH', self.unused, self.next_mtu)


class icmp(packet_base):
    "ICMP packet struct"

    MIN_LEN = 4

    def __init__(self, raw=None, prev=None, **kw):

        self.prev = prev

        self.type = 0
        self.code = 0
        self.csum = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        t = _type_to_name.get(self.type, str(self.type))
        s = '{t:%s c:%i chk:%x}' % (t, self.code, self.csum)

        if self.next is None:
            return s

        return ''.join((s, str(self.next)))

    def parse(self, raw):
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(icmp parse) warning ICMP packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return

        (self.type, self.code, self.csum) \
            = struct.unpack('!BBH', raw[:self.MIN_LEN])

        self.parsed = True

        if (self.type == TYPE_ECHO_REQUEST or self.type == TYPE_ECHO_REPLY):
            self.next = echo(raw=raw[self.MIN_LEN:],prev=self)
        elif self.type == TYPE_DEST_UNREACH:
            self.next = unreach(raw=raw[self.MIN_LEN:],prev=self)
        else:
            self.next = raw[self.MIN_LEN:]

    def hdr(self, payload):
        self.csum = checksum(struct.pack('!BBH', self.type, self.code, 0) +
                             payload)
        return struct.pack('!BBH', self.type, self.code, self.csum)
