# Copyright 2013 James McCauley
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

import struct

from .packet_base import packet_base
from .ethernet import ethernet

from .packet_utils import *


class llc (packet_base):
  "802.2 LLC header, possibly with SNAP header"

  MIN_LEN = 3

  def __init__ (self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.next = None

    self.length = self.MIN_LEN
    self.dsap = None
    self.ssap = None
    self.control = None
    self.oui = None #FIXME: Stored as bytes; lib.addresses uses ints.
    self.eth_type = ethernet.INVALID_TYPE

    if raw is not None:
        self.parse(raw)

    self._init(kw)

  @property
  def has_snap (self):
    return self.oui is not None

  def __str__ (self):
    #TODO: include field values!
    s = "[LLC"
    if self.has_snap:
      s += "+SNAP t:%04x" % (self.eth_type,)
    else:
      s += " ssap:0x%02x dsap:0x%02x c:%s" % (self.ssap, self.dsap,
                                              self.control)
    s += "]"
    return s

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.raw = raw
    dlen = len(raw)
    if dlen < self.MIN_LEN:
      self.msg('(llc parse) warning: packet data too short')
      return

    self.length = 3
    (self.dsap, self.ssap, self.control) \
        = struct.unpack('!BBB', raw[:self.MIN_LEN])
    if ((self.control & 1) == 0) or ((self.control & 3) == 2):
      if dlen < self.length + 1:
        self.msg('(llc parse) warning: packet data too short')
        return
      self.control |= (ord(raw[3:4]) << 8)
      self.length = 4

    if (self.ssap & 0xfe) == 0xaa:
      if (self.dsap & 0xfe) == 0xaa:
        # Oh snap
        if dlen < self.length + 5:
          self.msg('(llc parse) warning: incomplete SNAP')
          return
        self.oui = raw[self.length:self.length+3]
        self.length += 3
        self.eth_type = struct.unpack("!H", raw[self.length:self.length+2])[0]
        self.length += 2

    self.parsed = True

    if self.oui == '\0\0\0':
      self.next = ethernet.parse_next(self, self.eth_type, raw, self.length,
                                      allow_llc = False)
    else:
      self.next = raw[self.length:]

  @property
  def effective_ethertype (self):
    return ethernet._get_effective_ethertype(self)

  @property
  def type (self):
    """
    This is just an alias for eth_type.

    It's annoying that the ethertype on an ethernet packet is in the
    'type' attribute, and for vlan/llc it's in the 'eth_type' attribute.
    We should probably normalize this. For now, we at least have this.
    """
    return self.eth_type

  def hdr (self, payload):
    r = struct.pack("!BB", self.dsap, self.ssap)
    if self.length == 3 or self.length == 8:
      # One byte control
      r += struct.pack("!B", self.control)
    else:
      #FIXME: this is sloppy
      r += struct.pack("BB", self.control & 0xff,
                             (self.control>>8) & 0xff )
    if self.has_snap:
      # SNAP
      r += self.oui
      r += struct.pack("!H", self.eth_type)
    return r
