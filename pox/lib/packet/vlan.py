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
#                      802.1q VLAN Header Format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | PCP  |C|       VLANID         |       Encapsualted protocol   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct

from packet_base import packet_base
from ethernet import ethernet

from packet_utils       import *


class vlan(packet_base):
    "802.1q vlan header"

    MIN_LEN = 4

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.next = None

        self.pcp      = 0
        self.cfi      = 0
        self.id       = 0
        self.eth_type = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "vlan={0} pcp={1} ether={2}".format(self.id, self.pcp,
                                                ethtype_to_str(self.eth_type))
        if self.next is None:
            return s
        return s + "|" + str(self.next)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < vlan.MIN_LEN:
            self.msg('(vlan parse) warning VLAN packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return

        (pcpid, self.eth_type) = struct.unpack("!HH", raw[:vlan.MIN_LEN])

        self.pcp = pcpid >> 13
        self.c   = pcpid  & 0x1000
        self.id  = pcpid  & 0x0fff

        self.parsed = True

        # Don't know what to do about a VLAN'd VLAN...
        assert self.eth_type != 0x8100

        if self.eth_type in ethernet.type_parsers:
            self.next = ethernet.type_parsers[self.eth_type]\
             (raw=raw[vlan.MIN_LEN:],prev=self)

    def hdr(self, payload):
        pcpid  = self.pcp << 13
        pcpid |= self.c   << 12
        pcpid |= self.id
        buf = struct.pack("!HH", pcpid, self.eth_type)
        return buf
