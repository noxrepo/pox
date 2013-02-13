# Copyright 2013 James McCauley
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

import struct

from packet_base import packet_base
from ethernet import ethernet

from packet_utils import *


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
    self.oui = None
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

    self.next = ethernet.parse_next(self, self.eth_type, raw, self.length,
                                    allow_llc = False)

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
      r += chr(self.control & 0xff)
      r += chr((self.control>>8) & 0xff)
    if self.has_snap:
      # SNAP
      r += self.oui
      r += struct.pack("!H", self.eth_type)
    return r
