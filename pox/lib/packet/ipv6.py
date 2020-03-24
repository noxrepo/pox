# Copyright 2012,2013 James McCauley
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


#======================================================================
#
#                          IPv6 Header Format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version| Traffic Class |              Flow Label               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Payload Length        |  Next Header  |   Hop Limit   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   |                       Source Address                          |
#   |                                                               |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   |                    Destination Address                        |
#   |                                                               |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

"""
IPv6 packet classes

This is still rough.  There are a number of things remaining to do
(additional extension header types, payload inference), and there
are probably places where the API isn't quite right yet.  But it's
a start.
"""

import struct
from .packet_utils import *
from .tcp import *
from .udp import *
from .icmpv6 import *

from .packet_base import packet_base

from pox.lib.addresses import IPAddr6
from pox.lib.util import init_helper


_extension_headers = {}

def extension_header_def (header_type):
  """
  Extension Header decorator
  """
  #TODO: Switch to using generic class registry
  def f (cls):
    _extension_headers[header_type] = cls
    cls.TYPE = header_type
    return cls
  return f


class ExtensionHeader (object):
  next_header_type = None


class NormalExtensionHeader (ExtensionHeader):
  """
  A superclass for many ExtensionHeaders

  Many Extension Headers follow the same basic format, which is also suggested
  for future Extension Headers in RFC 6564.
  """

  #TYPE = <type number>

  def __init__ (self, *args, **kw):
    self.payload_length = 0
    self._init(*args, **kw)

    init_helper(self, kw)

  def __len__ (self):
    """
    Returns the packed length
    """
    l = self.payload_length + 2
    return ((l + 7) // 8) - 1

  @classmethod
  def unpack_new (cls, raw, offset = 0, max_length = None):
    """
    Unpacks a new instance of this class from a buffer

    returns (new_offset, object)
    """
    if max_length and max_length < 2:
      raise TruncatedException()
    nh,l = struct.unpack_from("!BB", raw, offset)
    max_length -= 2
    l = l * 8 + 6
    if max_length is not None and max_length < l:
      raise TruncatedException()
    offset += 2
    d = cls._unpack_body(raw, offset, nh, l)
    offset += l
    d['payload_length'] = l
    d['next_header_type'] = nh
    return offset, cls(**d)

  def pack (self):
    o = struct.pack("!BB", self.next_header_type, len(self))
    return o + self._pack_body()

  def _init (self, *args, **kw):
    """
    Called during initialization

    Override me
    """
    pass

  def _pack_body (self):
    """
    Returns the body of this Extension Header packed into bytes

    Override me
    """
    return b''

  @classmethod
  def _unpack_body (cls, raw, offset, next_header_type, length):
    """
    Unpacks the body portion of an Extension Header

    Override me.
    """
    return {}


class FixedExtensionHeader (ExtensionHeader):
  """
  A superclass for fixed length Extension Headers
  """

  #TYPE = <type number>
  #LENGTH = <total length in bytes>

  def __init__ (self, *args, **kw):
    self.next_header_type = None
    self._init(*args, **kw)

    init_helper(self, kw)

  def __len__ (self):
    """
    Returns the packed length
    """
    return self.LENGTH

  @classmethod
  def unpack_new (cls, raw, offset = 0, max_length = None):
    """
    Unpacks a new instance of this class from a buffer
    """
    if max_length is not None and (max_length - offset) < cls.LENGTH:
      raise TruncatedException()

    nh = struct.unpack_from("!B", raw, offset)[0]
    d = cls._unpack_body(raw, offset + 1, nh, cls.LENGTH - 1)
    offset += cls.LENGTH
    d['next_header_type'] = nh
    return offset, cls(**d)

  def pack (self):
    o = struct.pack("!B", self.next_header_type) + self._pack_body()
    assert len(o) == self.LENGTH, "Bad packed length"
    return o

  def _init (self, *args, **kw):
    """
    Called during initialization

    Override me
    """
    pass

  def _pack_body (self):
    """
    Returns the body of this Extension Header packed into bytes

    Override me
    """
    return b''

  @classmethod
  def _unpack_body (self, raw, offset, next_header_type, length):
    """
    Unpacks the body portion of an Extension Header

    Override me.
    """
    return {}


class DummyExtensionHeader (NormalExtensionHeader):
  """
  Just saves the raw body data
  """
  def _init (self, *args, **kw):
    self.raw_body = b''
  def _pack_body (self):
    return self.raw_body
  @classmethod
  def _unpack_body (self, raw, offset, next_header_type, length):
    return {'raw_body':raw[offset:offset+length]}


class DummyFixedExtensionHeader (FixedExtensionHeader):
  """
  Just saves the raw body data
  """
  def _init (self, *args, **kw):
    self.raw_body = '\x00' * (self.LENGTH - 1)
  def _pack_body (self):
    return self.raw_body
  @classmethod
  def _unpack_body (self, raw, offset, next_header_type, length):
    return {'raw_body':raw[offset:offset+length]}


#TODO: Implement Extension Headers for real (they're pretty much just
#      placeholders at present)
#TODO: Implement the IPSec options (Authentication and ESP)

@extension_header_def(0)
class HopByHopOptions (DummyExtensionHeader):
  pass

@extension_header_def(43)
class Routing (DummyExtensionHeader):
  pass

@extension_header_def(44)
class Fragment (DummyFixedExtensionHeader):
  LENGTH = 8
  pass

@extension_header_def(60)
class DestinationOptions (DummyExtensionHeader):
  pass


class ipv6 (packet_base):
  """
  IPv6 packet class
  """

  MIN_LEN = 40

  ICMP6_PROTOCOL = 58
  TCP_PROTOCOL  = 6
  UDP_PROTOCOL  = 17
  IGMP_PROTOCOL = 2
  NO_NEXT_HEADER = 59

  def __init__ (self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.v     = 6
    self.tc    = 0
    self.flow  = 0
    self.payload_length = 0
    self.next_header_type = None
    self.hop_limit = 0
    self.srcip = IPAddr6.UNDEFINED
    self.dstip = IPAddr6.UNDEFINED
    self.extension_headers = []

    self.next  = b''

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  @property
  def payload_type (self):
    """
    The last header type
    """
    if len(self.extension_headers):
      if isinstance(self.extension_headers[-1], ExtensionHeader):
        return self.extension_headers[-1].next_header_type
    else:
      return self.next_header_type
    return None

  @payload_type.setter
  def payload_type (self, value):
    if len(self.extension_headers):
      if isinstance(self.extension_headers[-1], ExtensionHeader):
        self.extension_headers[-1].next_header_type = value
      else:
        raise RuntimeError("Can't set payload_type")
    else:
      self.next_header_type = value

  def parse (self, raw, offset=0):
    assert isinstance(raw, bytes)
    self.next = None # In case of unfinished parsing
    self.raw = raw
    if len(raw) < self.MIN_LEN:
      self.msg('warning IP packet data too short to parse header:'
               ' data len %u' % (len(raw),))
      return

    (vtcfl, self.payload_length, nht, self.hop_limit) \
        = struct.unpack('!IHBB', raw[offset:offset+8])
    self.srcip = IPAddr6(raw[offset+8:offset+24], raw=True)
    self.dstip = IPAddr6(raw[offset+24:offset+40], raw=True)
    self.next_header_type = nht
    offset += 40

    self.v = vtcfl >> 28
    self.tc = (vtcfl >> 20) & 0xff
    self.flow = vtcfl & 0xfffff

    if self.v != 6:
      self.msg('ip parse) warning IP version %u not IPv6' % self.v)
      return

    length = self.payload_length
    if length > len(raw):
      length = len(raw) # Clamp to what we've got
      self.msg('(ipv6) warning IP packet data incomplete (%s of %s)'
               % (len(raw), self.payload_length))

    while nht != ipv6.NO_NEXT_HEADER:
      c = _extension_headers.get(nht)
      if c:
        if length < 8:
          self.msg('(ipv6) warning, packet data incomplete')
          return
        try:
          offset,o = c.unpack_new(raw, offset, max_length = length)
          length -= len(o)
        except TruncatedException:
          self.msg('(ipv6) warning, packet data truncated')
          return
        self.extension_headers.append(o)
        nht = o.next_header_type
      else:
        break

    self.parsed = True

    #TODO: This should be done a better way (and shared with IPv4?).
    if nht == self.UDP_PROTOCOL:
      self.next = udp(raw=raw[offset:offset+length], prev=self)
    elif nht == self.TCP_PROTOCOL:
      self.next = tcp(raw=raw[offset:offset+length], prev=self)
    elif nht == self.ICMP6_PROTOCOL:
      self.next = icmpv6(raw=raw[offset:offset+length], prev=self)
#    elif nht == self.IGMP_PROTOCOL:
#      self.next = igmp(raw=raw[offset:offset+length], prev=self)
    elif nht == self.NO_NEXT_HEADER:
      self.next = None
    else:
      self.next =  raw[offset:offset+length]

    if isinstance(self.next, packet_base) and not self.next.parsed:
      self.next = raw[offset:offset+length]

  def add_header (self, eh):
    if self.extension_headers:
      assert isinstance(self.extension_headers[-1], ExtensionHeader)
      self.extension_headers[-1].next_header_type = eh.TYPE
    else:
      self._next_header_type = eh.TYPE

  def hdr (self, payload):
    vtcfl = self.v << 28
    vtcfl |= (self.flow & 0xfffff)
    vtcfl |= (self.tc & 0xff) << 20

    if self.next_header_type is None:
      if self.extension_headers:
        nht = self.extension_headers[0].TYPE
      else:
        #TODO: We should infer this?
        assert False, "Must set next header type"
    else:
      nht = self.next_header_type

    self.next_header_type = nht #FIXME: this is a hack

    # Ugh, this is also an ugly hack
    if hasattr(payload, 'pack'):
      self.payload_length = len(payload.pack())
    else:
      self.payload_length = len(payload)


    r = struct.pack("!IHBB", vtcfl, self.payload_length, nht, self.hop_limit)
    r += self.srcip.raw
    r += self.dstip.raw

    return r

  def _to_str (self):
    ehs = [ipproto_to_str(self.next_header_type)]
    for eh in self.extension_headers:
      ehs.append(ipproto_to_str(eh.next_header_type))
    s = "IPv6 %s>%s" % (self.srcip, self.dstip)
    return "[" + s + " " + "+".join(ehs) + "]"

  #def __str__ (self):
  #  s = "[IP%s+%s %s>%s (hl:%s)]" % (
  #      self.v,
  #      ipproto_to_str(self.next_header_type),
  #      self.srcip, self.dstip, self.hop_limit)
  #  return s
