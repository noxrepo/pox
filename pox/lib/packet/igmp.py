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
from .packet_utils import *
from .packet_base import packet_base
from pox.lib.addresses import *
from pox.lib.util import initHelper

MEMBERSHIP_QUERY     = 0x11
MEMBERSHIP_REPORT    = 0x12
MEMBERSHIP_REPORT_V2 = 0x16
MEMBERSHIP_REPORT_V3 = 0x22
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
  MEMBERSHIP_REPORT_V3 = MEMBERSHIP_REPORT_V3
  LEAVE_GROUP_V2       = LEAVE_GROUP_V2

  def __init__(self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.ver_and_type = 0
    self.max_response_time = 0
    self.csum = 0
    self.address = None
    self.group_records = []
    self.extra = b''

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def hdr (self, payload):
    if self.ver_and_type == MEMBERSHIP_REPORT_V3:
      gd = b''
      for g in self.group_records:
        gd += g.pack()
      s = struct.pack("!BBHHH", self.ver_and_type, 0, 0, 0,
                      len(self.group_records))
      s += gd + self.extra
      self.csum = checksum(s)
      s = struct.pack("!BBHHH", self.ver_and_type, 0, self.csum, 0,
                      len(self.group_records))
      s += gd + self.extra
    else:
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

    ver_and_type = raw[0]
    if ver_and_type == MEMBERSHIP_REPORT_V3:
      self.ver_and_type, res1, self.csum, res2, num = \
          struct.unpack("!BBHHH", raw[:self.MIN_LEN])
      self.extra = raw[self.MIN_LEN:]

      s = struct.pack("!BBHHH", self.ver_and_type, 0, 0, 0, num)
      s += self.extra

      for _ in range(num):
        off,gr = GroupRecord.unpack_new(self.extra)
        self.extra = self.extra[off:]
        self.group_records.append(gr)

    elif ver_and_type in (MEMBERSHIP_QUERY, MEMBERSHIP_REPORT,
                          MEMBERSHIP_REPORT_V2, LEAVE_GROUP_V2):
      self.ver_and_type, self.max_response_time, self.csum, ip = \
          struct.unpack("!BBHi", raw[:self.MIN_LEN])
      self.extra = raw[self.MIN_LEN:]

      self.address = IPAddr(ip, networkOrder = False)

      s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time,
                      0, self.address.toSigned(networkOrder=False))
      s += self.extra
    else:
      self.warn("Unknown IGMP type " + str(ver_and_type))
      return

    csum = checksum(s)

    if csum != self.csum:
      self.err("IGMP checksums don't match")
    else:
      self.parsed = True

  def __str__ (self):
    s = "[IGMP vt:%02x " % (self.ver_and_type,)
    if self.ver_and_type == MEMBERSHIP_REPORT_V3:
      s += " ".join(str(g) for g in self.group_records)
    else:
      s += str(self.address)
    return s + "]"



class GroupRecord (object):
  def __init__ (self, **kw):
    self.type = None
    self.aux = b''
    self.source_addresses = []
    self.address = None
    initHelper(self, kw)

  def __str__ (self):
    s = "%s(t:%s" % (self.address, self.type)

    if self.source_addresses:
      s += " a:" + ",".join(str(a) for a in self.source_addresses)

    return s + ")"

  @classmethod
  def unpack_new (cls, raw, offset=0):
    t, auxlen, n, addr = struct.unpack_from("BBH4s", raw, offset)
    offset += 1+1+2+4
    addr = IPAddr(addr)
    auxlen *= 4
    addrs = []
    for _ in range(n):
      addrs.append( IPAddr(raw[offset:offset+4])  )
      offset += 4
    aux = raw[offset:offset+auxlen]
    offset += auxlen
    r = cls(type=t,aux=aux,source_addresses=addrs,address=addr)
    return offset,r

  def pack (self):
    o = struct.pack("BBH", self.type, len(self.aux) // 4,
                    len(self.source_addresses))
    o += self.address.raw
    for sa in self.source_addresses:
      o += sa.raw
    o += self.aux
    return o
