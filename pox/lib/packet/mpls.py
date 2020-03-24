# Copyright 2011,2013 James McCauley
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

from .packet_base import packet_base
from .ethernet import ethernet

from .packet_utils import *


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
        s = "[MPLS " + str(self.label)
        if self.tc: s += " " + str(self.tc)
        if self.s: s += " bos"
        s += " ttl=" + str(self.ttl) + "]"
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < mpls.MIN_LEN:
            self.msg('(mpls parse) warning MPLS packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return

        (label_high, label_low_tc_s, self.ttl) = \
            struct.unpack("!HBB", raw[:mpls.MIN_LEN])
        self.s = label_low_tc_s & 0x1
        self.tc = ((label_low_tc_s & 0xf) >> 1)
        self.label = (label_high << 4) | (label_low_tc_s >> 4)
        self.parsed = True
        if dlen >= 8 and not self.s:
          try:
            self.next = mpls(raw[mpls.MIN_LEN:])
            return
          except:
            # Recursion depth?
            pass
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
