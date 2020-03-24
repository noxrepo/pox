# Copyright 2017 James McCauley
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
#                     RFC 7348 VXLAN Header Format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |R|R|R|R|I|R|R|R|            Reserved                           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                VXLAN Network Identifier (VNI) |   Reserved    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct

from .packet_base import packet_base
from .ethernet import ethernet

from .packet_utils import *

VXLAN_PORT = 4789

class vxlan (packet_base):
    "vxlan header"

    MIN_LEN = 8
    ENCAPSULATION = True

    VXLAN_PORT = VXLAN_PORT
    START_SRC_PORT = 49152

    FLAG_I = 8

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.next = None

        self.vni = None # i flag unset

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[VXLAN"
        if self.vni is not None: s += " %s" % (self.vni,)
        return s + "]"

    @classmethod
    def calc_src_port (cls, eth):
        """
        Calculates a reasonable source outer UDP port

        The RFC recommends using a hash of the inner Ethernet fields and
        putting that in the range starting at 49152, so that's what we do.
        """
        h = hash(eth.hdr(None))
        return h % (65535 - self.START_SRC_PORT + 1) + self.START_SRC_PORT

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < vxlan.MIN_LEN:
            self.msg('(vxlan parse) warning VXLAN packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return

        (flags,reserved1,vni1,vni2,vni3,reserved2) = (
                struct.unpack("!B3sBBBB", raw[:vxlan.MIN_LEN]))

        self.vni = (vni1 << 16) | (vni2 << 8) | (vni3 << 0)

        if flags & self.FLAG_I == 0: self.vni = None

        self.parsed = True

        self.next = ethernet(raw=raw[vxlan.MIN_LEN:])

    def hdr (self, payload):
        flags = 0
        vni = self.vni
        if vni is None:
            vni = 0
        else:
            flags ^= self.FLAG_I

        vni1 = (vni >> 16) & 0xff
        vni2 = (vni >>  8) & 0xff
        vni3 = (vni >>  0) & 0xff

        buf = struct.pack("!BBBBBBBB", flags,0,0,0, vni1,vni2,vni3,0)
        return buf
