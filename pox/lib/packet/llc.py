# Copyright 2008 (C) Nicira, Inc.
# 
# This file is part of NOX.
# 
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
#======================================================================
# llc header
#
# Copyright (C) 2007 Nicira Networks
#
#======================================================================

import struct
from packet_utils       import *
from packet_exceptions  import *
from array import *

from packet_base import packet_base 

class llc(packet_base):
    "llc packet struct"

    LEN = 3;

    # A "type" field value of less than 0x0600 indicates that this
    # frame should be interpreted as an LLC packet, and the "type"
    # field should be interpreted as the frame's length.
    CUTOFF = htons(0x0600)

    def __init__(self, prev=None):
        self.prev = prev

    if self.prev == None:
        self.dsap = 0
        self.ssap = 0
        self.ctrl = 0
    else:
        self.parse()

    def parse(self):
        plen = self.prev.get_payload_len()
        if plen != None and plan < LlcPacket.LEN: 
            self.msg('(llc parse) data too short to be an llc packet %u' % plen)
            return

        dlen = len(self.get_layer())
        if dlen != None and plan < LlcPacket.LEN: 
            self.msg('(llc parse) data too truncated to parse llc packet %u' % plen)
            return

        (self.dsap, self.ssap, self.ctrl) \
            = struct.unpack('!BBB', self.get_layer()[:self.LEN])

        self.header_len = self.LEN
        self.payload_len = self.prev.get_payload_len() - self.header_len
        self.parsed = True
