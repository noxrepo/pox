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
#                           RIP Message Format
#
#                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Command       | Version       | Zero                          |
#   +---------------+---------------+-------------------------------+
#   |                                                               |
#   / RIP Entry (20 bytes)                                          /
#   /                                                               /
#   +---------------------------------------------------------------+
#
#
#                               RIP Entry
#
#                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Address Family                | Route Tag *                   |
#   +-------------------------------+-------------------------------+
#   | IP Address                                                    |
#   +---------------------------------------------------------------+
#   | Subnet Mask *                                                 |
#   +---------------------------------------------------------------+
#   | Next Hop *                                                    |
#   +---------------------------------------------------------------+
#   | Metric                                                        |
#   +---------------------------------------------------------------+
#
#   * RIP v2 only -- all zeros in RIP v1
#
#======================================================================

import struct
from .packet_utils import *
from .packet_base import packet_base
from pox.lib.addresses import *

# RIP v2 multicast address
RIP2_ADDRESS = IPAddr("224.0.0.9")

# RIP v1/v2 UDP port
RIP_PORT = 520

RIP_REQUEST = 1
RIP_RESPONSE = 2

class rip (packet_base):
  """
  RIP Message
  """

  MIN_LEN = 24
  RIP_PORT = RIP_PORT
  RIP2_ADDRESS = RIP2_ADDRESS

  def __init__(self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.entries = []

    self.command = 0
    self.version = 0

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def hdr (self, payload):
    s = struct.pack("!BBH", self.command, self.version, 0)
    for e in self.entries:
      s += e.pack()
    return s

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.raw = raw
    dlen = len(raw)
    if dlen < self.MIN_LEN:
      self.msg('RIP packet data too short to parse')
      return None

    self.command, self.version, z = struct.unpack("!BBH", raw[:4])
    if z != 0:
      self.err("Zero field in RIP message not zero!")
      return None

    self.entries = []

    raw = raw[4:]
    while len(raw) >= 20:
      try:
        self.entries.append(RIPEntry(raw=raw[0:20]))
      except Exception as e:
        self.err('Exception parsing RIP entries: ' + str(e))
        return None
      raw = raw[20:]
    if len(raw) != 0:
      self.err('RIP had partial entry?  %s bytes left' % (len(raw),))

    self.parsed = True

  def __str__ (self):
    cmd = {RIP_REQUEST:"REQ",RIP_RESPONSE:"RESP"}.get(self.command,
                                                      str(self.command))

    s = "[RIP ver:%i cmd:%s num:%i|" % (self.version,
        cmd, len(self.entries))
    for e in self.entries:
      s += str(e) + "|"
    s = s[:-1] + "]"
    return s
RIPMessage = rip


class RIPEntry (packet_base):
  def __init__ (self, raw=None, prev=None, **kw):
    #TODO: netmask initializer?
    packet_base.__init__(self)

    self.address_family = 0
    self.route_tag = 0
    self.ip = None # IPAddr; bad default is to force setting
    self._netmask = 0 # An IPAddr, but netmask property lets you assign a
                      # dotquad string or an integer number of bits.
    self.next_hop = IP_ANY
    self.metric = 0

    if raw is not None:
      self.parse(raw)
    self._init(kw)

  @property
  def netmask (self):
    return self._netmask

  @netmask.setter
  def netmask (self, netmask):
    if isinstance(netmask, int):
      netmask = cidr_to_netmask(netmask)
    elif not isintance(netmask, IPAddr):
      netmask = IPAddr(netmask)
    self._netmask = netmask

  @property
  def network_bits (self):
    """
    Returns the number of network bits.  May raise an exception
    if the netmask is not CIDR-compatible.
    """
    return netmask_to_cidr(self._netmask)

  @network_bits.setter
  def network_bits (self, bits):
    self._netmask = cidr_to_netmask(bits)

  def hdr (self, payload):
    s = struct.pack("!HHiiii", self.address_family, self.route_tag,
                    self.ip.toSigned(networkOrder=False),
                    self.netmask.toSigned(networkOrder=False),
                    self.next_hop.toSigned(networkOrder=False),
                    self.metric)

    return s

  def parse (self, raw):
    self.address_family, self.route_tag, ip, netmask, next_hop, self.metric \
     = struct.unpack("!HHiiii", raw)
    self.ip = IPAddr(ip, networkOrder = False)
    self._netmask = IPAddr(netmask, networkOrder = False)
    self.next_hop = IPAddr(next_hop, networkOrder = False)

  def __str__ (self):
    s = "tag:%s ip:%s/%s nh:%s m:%s" % (self.route_tag, self.ip,
        self._netmask, self.next_hop, self.metric)
    return s
