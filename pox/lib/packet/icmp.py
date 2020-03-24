# Copyright 2011,2014 James McCauley
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
from .packet_utils import *

from .packet_base import packet_base

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


# This is such a hack; someone really needs to rewrite the
# stringizing.
# (Note: There may actually be a better way now using _to_str().)
def _str_rest (s, p):
  if p.next is None:
    return s
  if isinstance(p.next, bytes):
    return "[%s bytes]" % (len(p.next),)
  return s+str(p.next)


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
        return "[ICMP id:%i seq:%i]" % (self.id, self.seq)

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
#  Time Exceeded
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                              Unused                           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |       IP Header + 8 bytes of original datagram's data         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#----------------------------------------------------------------------
class time_exceeded (packet_base):
    """
    ICMP time exceeded packet struct
    """

    #NOTE: unreachable and time_exceeded are really similar.  If you
    #      update one, please look at the other as well!

    MIN_LEN = 4

    def __init__ (self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.unused = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__ (self):
        s = '[time_exceeded]'

        return _str_rest(s, self)

    def parse (self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(time_exceeded parse) warning payload too short '
                     'to parse header: data len %u' % (dlen,))
            return

        self.unused = struct.unpack('!I', raw[:self.MIN_LEN])[0]

        self.parsed = True

        if dlen >= 28:
            # xxx We're assuming this is IPv4!
            from . import ipv4
            self.next = ipv4.ipv4(raw=raw[self.MIN_LEN:],prev=self)
        else:
            self.next = raw[self.MIN_LEN:]

    def hdr (self, payload):
        return struct.pack('!I', self.unused)


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
    """
    ICMP unreachable packet struct
    """

    #NOTE: unreachable and time_exceeded are really similar.  If you
    #      update one, please look at the other as well!

    MIN_LEN = 4

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.unused = 0
        self.next_mtu = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = ''.join(('[', 'm:', str(self.next_mtu), ']'))

        return _str_rest(s, self)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(unreach parse) warning unreachable payload too short '
                     'to parse header: data len %u' % dlen)
            return

        (self.unused, self.next_mtu) \
            = struct.unpack('!HH', raw[:self.MIN_LEN])

        self.parsed = True

        if dlen >= 28:
            # xxx We're assuming this is IPv4!
            from . import ipv4
            self.next = ipv4.ipv4(raw=raw[unreach.MIN_LEN:],prev=self)
        else:
            self.next = raw[unreach.MIN_LEN:]

    def hdr(self, payload):
        return struct.pack('!HH', self.unused, self.next_mtu)

    @property
    def srcip (self):
        """
        srcip of referenced packet or None
        """
        try:
          return self.payload.srcip
        except Exception:
          return None

    @property
    def dstip (self):
        """
        dstip of referenced packet or None
        """
        try:
          return self.payload.dstip
        except Exception:
          return None


class icmp(packet_base):
    "ICMP packet struct"

    MIN_LEN = 4

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.type = 0
        self.code = 0
        self.csum = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        t = _type_to_name.get(self.type, str(self.type))
        s = '[t:%s c:%i chk:%x]' % (t, self.code, self.csum)
        return _str_rest(s, self)

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

        if self.type == TYPE_ECHO_REQUEST or self.type == TYPE_ECHO_REPLY:
            self.next = echo(raw=raw[self.MIN_LEN:],prev=self)
        elif self.type == TYPE_DEST_UNREACH:
            self.next = unreach(raw=raw[self.MIN_LEN:],prev=self)
        elif self.type == TYPE_TIME_EXCEED:
            self.next = time_exceeded(raw=raw[self.MIN_LEN:],prev=self)
        else:
            self.next = raw[self.MIN_LEN:]

    def hdr(self, payload):
        self.csum = checksum(struct.pack('!BBH', self.type, self.code, 0) +
                             payload)
        return struct.pack('!BBH', self.type, self.code, self.csum)
