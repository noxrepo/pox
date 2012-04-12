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
#                     MPLS tag format 
#
#    0               1               2               3             4
#    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |              LABEL                    |  TC |S|    TTL        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================
import struct

from packet_base import packet_base
from ethernet import ethernet

from packet_utils       import *


class mpls(packet_base):
    "mpls header"

    MIN_LEN = 4

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.next = None
        self.label = 0
        self.tc = 0
        self.s = 0
        self.ttl = 0
        if raw is not None:
            self.parse(raw)
        self._init(kw)

    def __str__(self):
        s = "mls label={0} tc={1} s={2} ttl={3}".format(self.label, self.tc,
                                                self.s, self.ttl)
        if self.next is None:
            return s
        return s + "|" + str(self.next)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < mpls.MIN_LEN:
            self.msg('(mpls parse) warning MPLS packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return

        (label_high, label_low_tc_s, self.ttl) = struct.unpack("!HBB", raw[:mpls.MIN_LEN])
        self.s = label_low_tc_s & 0x1
        self.tc = ((label_low_tc_s & 0xf) >> 1)
        self.label = (label_high << 4) | (label_low_tc_s >> 4)
        self.parsed = True
        self.next = raw[mpls.MIN_LEN:]

    def hdr(self, payload):
        label = self.label & 0xfffff
        tc = self.tc & 0x7
        s = self.s & 0x1
        ttl = self.ttl & 0xff
        label_high = label >> 4
        label_low_tc_s = ((label & 0xf) << 4) | (tc << 1) | s
        buf = struct.pack('!HBB', label_high, label_low_tc_s, ttl)
        return buf
