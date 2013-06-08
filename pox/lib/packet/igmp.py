# Copyright 2012 James McCauley
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
#                          IGMP v1/v2
#
#                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Ver * | Type  | MRT/Unused ** | Checksum                      |
#   +-------+-------+---------------+-------------------------------+
#   | Group Address                                                 |
#   +-------------------------------+-------------------------------+
#
#   *  In v2, there is no Version field, and Type is the whole 8 bits
#   ** Max Response Time in v2 only
#
#======================================================================

#TODO: Support for IGMP v3

import struct
from packet_utils import *
from packet_base import packet_base
from pox.lib.addresses import *

MEMBERSHIP_QUERY     = 0x11
MEMBERSHIP_REPORT    = 0x12
MEMBERSHIP_REPORT_V2 = 0x16
LEAVE_GROUP_V2       = 0x17

# IGMP multicast address
IGMP_ADDRESS = IPAddr("224.0.0.22")

# IGMP IP protocol
IGMP_PROTOCOL = 2

class igmp (packet_base):
  """
  IGMP Message
  """

  MIN_LEN = 8
  IGMP_ADDRESS = IGMP_ADDRESS
  IGMP_PROTOCOL = IGMP_PROTOCOL

  MEMBERSHIP_QUERY     = MEMBERSHIP_QUERY
  MEMBERSHIP_REPORT    = MEMBERSHIP_REPORT
  MEMBERSHIP_REPORT_V2 = MEMBERSHIP_REPORT_V2
  LEAVE_GROUP_V2       = LEAVE_GROUP_V2

  def __init__(self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.ver_and_type = 0
    self.max_response_time = 0
    self.csum = 0
    self.address = None
    self.extra = b''

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def hdr (self, payload):
    s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time,
                    0, self.address.toSigned(networkOrder=False))
    s += self.extra
    self.csum = checksum(s)
    s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time,
                    self.csum, self.address.toSigned(networkOrder=False))
    s += self.extra
    return s

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.raw = raw
    dlen = len(raw)
    if dlen < self.MIN_LEN:
      self.msg('packet data too short to parse')
      return None

    self.ver_and_type, self.max_response_time, self.csum, ip = \
        struct.unpack("!BBHi", raw[:self.MIN_LEN])
    self.extra = raw[self.MIN_LEN:]

    self.address = IPAddr(ip, networkOrder = False)

    s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time,
                    0, self.address.toSigned(networkOrder=False))
    s += self.extra
    csum = checksum(s)
    if csum != self.csum:
      self.err("IGMP hecksums don't match")
    else:
      self.parsed = True

  def __str__ (self):
    s = "[IGMP "
    s += "vt:%02x %s" % (self.ver_and_type, self.address)
    return s + "]"
