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
#                      RFC 1701 GRE Header Format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |      Checksum (optional)      |       Offset (optional)       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                         Key (optional)                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Sequence Number (optional)                 |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                         Routing (optional)
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct

from .packet_base import packet_base
from .packet_utils import checksum
from .ethernet import ethernet
from . import ipv4

from .packet_utils import *


class gre (packet_base):
    """
    gre header

    The default behavior for checksum computation is to ignore it when parsing
    (verify_csum=False).  When packing, the default is to skip the checksum if
    .csum is None or to include it if it is set to a number.  If .csum=True,
    we compute the checksum ourselves.  Two more flags can override this
    packing behavior.  If compute_csum=True, we always compute the checksum.
    If skip_csum=True, we never include a checksum.
    """

    MIN_LEN = 4
    PROTOCOL = 47
    ENCAPSULATION = True

    verify_csum = False


    compute_csum = False # If True, always compute when packing
    skip_csum = False    # If True, always skip when packing

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.next = None

        self.type = 0 # Inner packet type
        self.ver = 0
        self.strict_source_route = False
        self.recursion = 0 #TODO: Implement this right

        self.route_offset = 0

        self.key = None
        self.seq = None
        self.csum = None

        self.routing = None

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[GRE"
        if self.key is not None: s += " k:%s" % (self.key,)
        if self.seq is not None: s += " s:%s" % (self.seq,)
        if isinstance(self.csum, int): s += " c:%04x" % (self.csum,)
        return s + "]"

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < gre.MIN_LEN:
            self.msg('warning GRE packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return

        o = 0
        flags,self.type = struct.unpack("!HH", raw[o:o+4])
        o += 4
        self.ver = flags & 7
        if self.ver != 0:
            self.msg('unknown GRE version: %s' % (self.ver,))
        csum_present = (flags & 0x8000) != 0
        route_present = (flags & 0x4000) != 0
        key_present = (flags & 0x2000) != 0
        seq_present = (flags & 0x1000) != 0
        self.strict_source_route = (flags & 0x800) != 0
        self.recursion = (flags & 0x700) >> 8

        offset = None
        if csum_present or route_present:
            self.csum,self.route_offset = struct.unpack("!HH", raw[o:o+4])
            o += 4
            if self.verify_csum:
                if checksum(raw) != 0:
                    self.msg('warning GRE checksum did not match')
                    return

        if key_present:
            self.key = struct.unpack("!I", raw[o:o+4])[0]
            o += 4

        if seq_present:
            self.seq = struct.unpack("!I", raw[o:o+4])[0]
            o += 4

        if route_present:
            self.routing = []
            while True:
                af,so,sl = struct.unpack("!HBB", raw[o:o+4])
                o += 4
                sd = raw[o:o+sl]
                o += sl
                self.routing.append((af,so,sl,sd))
                if sl == 0: break

        self.parsed = True

        if self.type == 0x0800:
            self.next = ipv4.ipv4(raw=raw[o:])
        elif self.type == 0x6558:
            self.next = ethernet(raw=raw[o:])
        else:
            self.next = raw[o:]

    def hdr (self, payload):
        if self.skip_csum: self.csum = None
        flags = 0
        if self.csum is not None: flags |= 0x8000
        if self.routing is not None: flags |= 0x4000
        if self.key is not None: flags |= 0x2000
        if self.seq is not None: flags |= 0x1000
        if self.strict_source_route: flags |= 0x800
        flags |= (self.recursion & 0x700) << 8

        r = struct.pack("!HH", flags, self.type)

        if self.compute_csum: self.csum = True

        if (self.routing is not None) or (self.csum is not None):
            # If we're doing checksum computation, insert a 0 for now, and
            # we'll fix it later.
            r += struct.pack("!HH", 0 if self.csum is True else self.csum,
                             self.route_offset)

        if self.key is not None:
            r += struct.pack("!I", self.key)

        if self.seq is not None:
            r += struct.pack("!I", self.seq)

        if self.routing is not None:
            sl = 0
            for ro in self.routing:
                if isinstance(ro, bytes):
                    sl = 0
                    r += ro
                else: # Better be a sequence...
                    af,so,sl = ro
                    r += struct.pack("!HBB", af, so, sl)
            if sl != 0:
                self.msg('warning GRE routing did not end with empty entry')

        if self.csum is True:
            csum = checksum(r + payload)
            r = r[:4] + struct.pack("!H", csum) + r[4+2:]
            self.csum = csum
        elif self.csum is not None:
            assert checksum(r + payload) == 0

        return r
