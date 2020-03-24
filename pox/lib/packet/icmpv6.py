# Copyright 2011-2013 James McCauley
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
#                           ICMPv6 Header Format
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

"""
This file parses ICMPv6 as well as NDP

See RFCs 4443 and 4861 in particular.
"""

#TODO: Move NDP into its own file?
#TODO: Clean this up in general
#TODO: Write tests (at least pack/unpack)

import struct
import random
from .packet_utils import *
from .packet_base import packet_base

from pox.lib.addresses import IPAddr6,EthAddr
from pox.lib.util import hexdump, init_helper

# Errors
TYPE_DEST_UNREACH   = 1
TYPE_PACKET_TOO_BIG = 2
TYPE_TIME_EXCEED    = 3
TYPE_PARAM_PROB     = 4

# Informational
TYPE_ECHO_REQUEST           = 128
TYPE_ECHO_REPLY             = 129
TYPE_MC_LISTENER_QUERY      = 130
TYPE_MC_LISTENER_REPORT     = 131
TYPE_MC_LISTENER_DONE       = 132
TYPE_ROUTER_SOLICITATION    = 133 # NDP
TYPE_ROUTER_ADVERTISEMENT   = 134 # NDP
TYPE_NEIGHBOR_SOLICITATION  = 135 # NDP
TYPE_NEIGHBOR_ADVERTISEMENT = 136 # NDP
TYPE_REDIRECT               = 137 # NDP
TYPE_ROUTER_RENUMBER        = 138
TYPE_MC_LISTENER_REPORT_V2  = 143
TYPE_MRD_ADVERTISEMENT      = 151
TYPE_MRD_SOLICITATION       = 152
TYPE_MRD_TERMINATION        = 153

CODE_UNREACH_NO_ROUTE         = 0
CODE_UNREACH_ADMIN_PROHIBIT   = 1
CODE_UNREACH_BEYOND_SRC_SCOPE = 2
CODE_UNREACH_ADDR_UNREACHABLE = 3
CODE_UNREACH_PORT_UNREACHABLE = 4
CODE_UNREACH_SRC_POLICY_FAIL  = 5
CODE_UNREACH_DST_ROUTE_REJECT = 6
CODE_UNREACH_SRC_ROUTE_ERROR  = 7

CODE_TIME_HOP_EXCEEDED        = 0
CODE_TIME_FRAG_TIME_EXCEEDED  = 1

CODE_PARAM_BAD_HEADER         = 0
CODE_PARAM_BAD_NEXT_HEADER    = 1
CODE_PARAM_BAD_OPTION         = 2

#TODO: Use a class registry for this
_type_to_name = {
  1   : "TYPE_DEST_UNREACH",
  2   : "TYPE_PACKET_TOO_BIG",
  3   : "TYPE_TIME_EXCEED",
  4   : "TYPE_PARAM_PROB",
  128 : "TYPE_ECHO_REQUEST",
  129 : "TYPE_ECHO_REPLY",
  130 : "TYPE_MC_LISTENER_QUERY",
  131 : "TYPE_MC_LISTENER_REPORT",
  132 : "TYPE_MC_LISTENER_DONE",
  133 : "TYPE_ROUTER_SOLICITATION",
  134 : "TYPE_ROUTER_ADVERTISEMENT",
  135 : "TYPE_NEIGHBOR_SOLICITATION",
  136 : "TYPE_NEIGHBOR_ADVERTISEMENT",
  137 : "TYPE_REDIRECT",
  138 : "TYPE_ROUTER_RENUMBER",
  143 : "TYPE_MC_LISTENER_REPORT_V2",
  151 : "TYPE_MRD_ADVERTISEMENT",
  152 : "TYPE_MRD_SOLICITATION",
  153 : "TYPE_MRD_TERMINATION",
}


_nd_options = {}


def nd_option_def (cls):
  """
  Neighbor Discovery option decorator
  """
  _nd_options[cls.TYPE] = cls
  return cls


def _parse_ndp_options (raw, prev, offset = 0, buf_len = None):
  """
  Parse ICMPv6 options and return (new_offset,[option_list])
  """
  # This is pretty bad at the moment
  _offset = offset
  if buf_len is None: buf_len = len(raw)
  remaining = buf_len - offset
  r = []

  while offset < buf_len - 2:
    if (buf_len - offset) % 8 != 0:
      raise RuntimeError("Bad option data length")
    offset,o = NDOptionBase.unpack_new(raw, offset, buf_len, prev=prev)
    r.append(o)

  return offset,r


class NDOptionBase (packet_base):
  "Neighbor Discovery option base class"

  #LENGTH = <fixed padded payload length in bytes or None>
  #TYPE = <type>

  def __init__ (self, *args, **kw):
    self.prev = kw.pop('prev', None)
    self._init(*args, **kw)
    init_helper(self, kw)

  def __repr__ (self):
    s = type(self).__name__
    if s.startswith("NDOption"):
      s = s[8:]
    elif s.startswith("NDOpt"):
      s = s[5:]
    ss = self._fields()
    if ss:
      s += ' '
      s += " ".join(["%s:%s" % (k,v) for k,v in ss.items()])
    return "[" + s + "]"

  @property
  def type (self):
    return self.prev.type
  @property
  def code (self):
    return self.prev.code

  def _fields (self):
    """
    Override to add fields to stringizing
    """
    return None

  def _init (self, *args, **kw):
    """
    Called during initialization

    Override me
    """
    pass

  def __len__ (self):
    """
    Payload length in bytes

    Override if your option type has flexible length
    """
    assert self.LENGTH is not None
    return self.LENGTH

  @staticmethod
  def unpack_new (raw, offset = 0, buf_len = None, prev = None):
    """
    Unpacks a new instance of the appropriate subclass from a buffer

    returns (new_offset, object)
    """
    if buf_len is None: buf_len = len(raw)

    if buf_len < 2:
      raise TruncatedException()
    t,l = struct.unpack_from("BB", raw, offset)
    if l == 0:
      raise RuntimeError("Zero-length NDP option")

    offset += 2
    length_bytes = l * 8 - 2
    if (buf_len - offset) < length_bytes:
      raise TruncatedException()

    c = _nd_options.get(t) #FIXME: Ugh, *class registry*
    if c is None:
      c = NDOptionGeneric
    if c.LENGTH is not None and c.LENGTH != length_bytes:
      raise RuntimeError("Bad length for NDP option")

    new_off,o = c._unpack_new(raw, offset, t, length_bytes, prev=prev)

    assert new_off == offset+length_bytes
    return new_off,o

  def pack (self):
    d = self._pack_body()
    while (len(d)+2) % 8: d += "\x00" # sloppy
    return struct.pack("BB", self.TYPE, (len(d)+2)//8) + d

  @classmethod
  def _unpack_new (cls, raw, offset, t, length, prev):
    """
    Unpacks the body portion of this option type into a new object

    Override me.
    """
    raise RuntimeError("Not implemented")
    #o = new.instance(cls)
    #o._init()
    #return offset+length,o

  def _pack_body (self):
    """
    Returns the body of this option packed into bytes

    Override me
    """
    raise RuntimeError("Not implemented")
    #return b''


class NDOptionGeneric (NDOptionBase):
  LENGTH = None
  TYPE = None

  def __repr__ (self):
    return "<NDP Option Type %s>" % (self.TYPE,)

  def _init (self, *args, **kw):
    self.raw = b''

  def __len__ (self):
    return len(self.raw)

  def _pack_body (self):
    return self.raw

  @classmethod
  def _unpack_new (cls, raw, offset, t, length, prev):
    """
    Unpacks the body portion of this option type into a new object

    Override me.
    """
    #o = new.instance(cls) # Weird; this doesn't work despite the fact
                           # that it should be a new style class.
    o = cls()
    o._init()
    o.TYPE = t
    o.prev = prev
    #o.LENGTH = length
    o.raw = raw[offset:offset+length]
    return offset+length,o


class NDOptLinkLayerAddress (NDOptionBase):
  """
  Superclass for this source/target LL address options

  Assumes L2 is Ethernet
  """
  LENGTH = 6

  def _init (self, *args, **kw):
    a = kw.pop('address',None)
    if a is None:
      self.address = None
    else:
      self.address = EthAddr(a)

  def _fields (self):
    return {'addr':self.address}

  @classmethod
  def _unpack_new (cls, raw, offset, t, length, prev):
    return offset+length,cls(address = EthAddr(raw[offset:offset+length]),
        prev=prev)

  def _pack_body (self):
    return self.address.raw


@nd_option_def
class NDOptSourceLinkLayerAddress (NDOptLinkLayerAddress):
  TYPE = 1

@nd_option_def
class NDOptTargetLinkLayerAddress (NDOptLinkLayerAddress):
  TYPE = 2

@nd_option_def
class NDOptPrefixInformation (NDOptionBase):
  LENGTH = 1 + 1 + 4 + 4 + 4 + 4 * 4
  TYPE = 3

  ON_LINK_FLAG = 0x80
  AUTONOMOUS_FLAG = 0x40

  def _init (self, *args, **kw):
    self.prefix_length = 0
    self.on_link = False
    self.is_autonomous = False
    self.valid_lifetime = 0
    self.preferred_lifetime = 0
    self.prefix = IPAddr6.UNDEFINED

  def _fields (self):
    r = {}
    if self.on_link: r['on_link'] = True
    if self.is_autonomous: r['autonomous'] = True
    r['valid'] = self.valid_lifetime
    r['preferred'] = self.preferred_lifetime
    r['prefix'] = "%s/%s" % (self.prefix, self.prefix_length)
    return r

  @classmethod
  def _unpack_new (cls, raw, offset, t, length, prev):
    o = cls()
    o.prefix_length,flags,o.valid_lifetime,o.preferred_lifetime = \
        struct.unpack_from('!BBII', raw, offset)
    offset += 1 + 1 + 4 + 4
    offset += 4 # Reserved
    o.prefix = IPAddr6(raw=raw[offset:offset+16])
    offset += 16
    o.on_link = (flags & cls.ON_LINK_FLAG) != 0
    o.is_autonomous = (flags & cls.AUTONOMOUS_FLAG) != 0
    o.prev = prev

    return offset,o

  @property
  def flags (self):
    f = 0
    if self.on_link: f |= self.ON_LINK_FLAG
    if self.is_autonomous: f |= self.AUTONOMOUS_FLAG
    return f

  def pack (self):
    s = struct.pack("!BBII", self.prefix_length, self.flags,
        self.valid_lifetime,self.preferred_lifetime)
    s += '\x00' * 4
    s += self.prefix.raw
    return s


@nd_option_def
class NDOptMTU (NDOptionBase):
  LENGTH = 6
  TYPE = 5

  def _init (self, *args, **kw):
    self.mtu = 0

  def _fields (self):
    return {'mtu':self.mtu}

  @classmethod
  def _unpack_new (cls, raw, offset, t, length, prev):
    o = cls()
    o.prev = prev
    _,o.mtu = struct.unpack_from('!HI', raw, offset)
    offset += 2 + 4
    return offset,o

  def pack (self):
    return struct.pack("!HI", 0, self.mtu)



#NOTE: icmp_base sort of ignores the usual packet_base API.  Hopefully
#      the way it does so doesn't break too much.  The API it supports
#      is closer to the way a newer version of the API would work.

class icmp_base (packet_base):
  "ICMPv6 base class"

  def __str__ (self):
    s = "[ICMPv6/" + self.__class__.__name__
    ss = self._fields()
    if ss:
      s += ' '
      s += " ".join(["%s:%s" % (k,v) for k,v in ss.items()])
    return s + "]"

  def _fields (self):
    """
    Return map of fields used for string formatting.

    Override me to customize stringizing.
    """
    return {}

  def _init_ (self):
    """
    Called during initialization

    Override me

    In most other hierarchies that follow a similar pattern, this method
    would be named "_init", but that name is already used in the
    packet_base hierarchy.
    """
    pass

  @property
  def type (self):
    return self.prev.type
  @property
  def code (self):
    return self.prev.code

  def __init__ (self, prev=None, **kw):
    packet_base.__init__(self)
    self.prev = prev
    self.next = None

    self._init_()

    self._init(kw)
    self.parsed = True

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    """
    Unpacks a new instance of this class from a buffer

    returns (new_offset, object)
    """
    raise RuntimeError("Unimplemented on class %s" % (cls.__name__,))
    #.parsed = True

  def pack (self):
    raise RuntimeError("Unimplemented on class %s" % (type(self).__name__,))


class ICMPGeneric (icmp_base):
  def _fields (self):
    return {'bytes':len(self.raw)}

  def _init_ (self):
    self.raw = b''

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()
    o.raw = raw[offset:offset+buf_len]
    o.prev = prev
    o.parsed = True
    return offset+buf_len,o

  def pack (self):
    return self.raw


class NDRouterSolicitation (icmp_base):
  "Router Solicitation"
  def _init_ (self):
    self.options = []

  def _fields (self):
    return {"num_opts":len(self.options)}

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()

    _offset = offset
    if buf_len is None: buf_len = len(raw)

    try:
      offset += 4 # Skip reserved
      offset,o.options = _parse_ndp_options(raw, prev, offset, buf_len)

      o.parsed = True
    except TruncatedException:
      pass

    o.prev = prev
    return offset,o

  def pack (self):
    o = '\x00' * 4 # _PAD4
    for opt in self.options:
      o += opt.pack()
    return o


class NDRouterAdvertisement (icmp_base):
  "Router Advertisement"
  MANAGED_FLAG = 0x80
  OTHER_FLAG = 0x40

  def __init__ (self, raw=None, prev=None, **kw):
    icmp_base.__init__(self)
    self.prev = prev

    self.hop_limit = 0
    self.is_managed = False
    self.is_other = False
    self.lifetime = 0 # seconds
    self.reachable = 0 # milliseconds
    self.retrans_timer = 0 # milliseconds
    self.options = []

    if raw is not None: self.parse(raw)
    self._init(kw)

  def _fields (self):
    f = ['hop_limit','lifetime','reachable',
         'retrans_timer']
    r = {}
    #if len(self.options): r['num_opts'] = len(self.options)
    if len(self.options): r["opts"] = self.options
    if self.is_managed: r['managed'] = True
    if self.is_other: r['other'] = True
    for ff in f:
      r[ff] = getattr(self, ff)
    return r

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()

    _offset = offset
    if buf_len is None: buf_len = len(raw)

    try:
      o.hop_limit,flags,o.lifetime,o.reachable,o.retrans_time = \
          struct.unpack_from("!BBHII", raw, offset)
      offset += 1 + 1 + 2 + 4 + 4
      offset,o.options = _parse_ndp_options(raw, prev, offset, buf_len)
      o.is_managed = flags & cls.MANAGED_FLAG
      o.is_other = flags & cls.OTHER_FLAG

      o.parsed = True
    except TruncatedException:
      pass

    o.raw = raw[_offset:offset]
    o.prev = prev
    return offset,o

  @property
  def flags (self):
    f = 0
    if self.is_managed: f |= self.MANAGED_FLAG
    if self.is_other: f |= self.OTHER_FLAG
    return f

  def pack (self):
    o = '\x00' * 4 # _PAD4

    o += struct.pack("!BBHII", self.hop_limit, self.flags, self.lifetime,
        self.reachable, self.retrans_time)

    for opt in self.options:
      o += opt.pack()
    return o


class NDNeighborSolicitation (icmp_base):
  "Neighbor Solicitation"
  def __init__ (self, raw=None, prev=None, **kw):
    icmp_base.__init__(self)
    self.prev = prev

    self.target = IPAddr6.UNDEFINED
    self.options = []

    if raw is not None: self.parse(raw)
    self._init(kw)

  def _fields (self):
    f = ['target']
    r = {'num_opts':len(self.options)}
    r["opts"]=self.options
    for ff in f:
      r[ff] = getattr(self, ff)
    return r

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()

    _offset = offset
    if buf_len is None: buf_len = len(raw)

    try:
      offset += 4 # Skip reserved
      o.target = IPAddr6(raw=raw[offset:offset+16])
      offset += 16
      offset,o.options = _parse_ndp_options(raw, prev, offset, buf_len)

      o.parsed = True
    except TruncatedException:
      pass

    o.raw = raw[_offset:offset]
    o.prev = prev
    return offset,o

  def pack (self):
    o = '\x00' * 4 # _PAD4
    o += self.target.raw
    for opt in self.options:
      o += opt.pack()
    return o


class NDNeighborAdvertisement (icmp_base):
  "Neighbor Advertisement"

  ROUTER_FLAG = 0x80
  SOLICITED_FLAG = 0x40
  OVERRIDE_FLAG = 0x20

  def __init__ (self, raw=None, prev=None, **kw):
    icmp_base.__init__(self)
    self.prev = prev

    self.target = IPAddr6.UNDEFINED
    self.options = []
    self.is_router = False
    self.is_solicited = False
    self.is_override = False

    if raw is not None: self.parse(raw)
    self._init(kw)

  def _fields (self):
    f = ['target']
    r = {}
    #if len(self.options): r['num_opts'] = len(self.options)
    if len(self.options): r["opts"] = self.options
    if self.is_router: r['router'] = True
    if self.is_solicited: r['solicited'] = True
    if self.is_override: r['override'] = True
    for ff in f:
      r[ff] = getattr(self, ff)
    return r

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()

    _offset = offset
    if buf_len is None: buf_len = len(raw)

    try:
      flags = raw[offset]
      o.is_router = (flags & cls.ROUTER_FLAG) != 0
      o.is_solicited = (flags & cls.SOLICITED_FLAG) != 0
      o.is_override = (flags & cls.OVERRIDE_FLAG) != 0

      offset += 4 # Skip reserved
      o.target = IPAddr6(raw=raw[offset:offset+16])
      offset += 16
      offset,o.options = _parse_ndp_options(raw, prev, offset, buf_len)

      o.parsed = True
    except TruncatedException:
      pass

    o.raw = raw[_offset:offset]
    o.prev = prev
    return offset,o

  def pack (self):
    o = 0
    if self.is_router: o |= self.ROUTER_FLAG
    if self.is_solicited: o |= self.SOLICITED_FLAG
    if self.is_override : o |= self.OVERRIDE_FLAG
    o = chr(o)
    o += '\x00' * 3 # _PAD3
    o += self.target.raw
    for opt in self.options:
      o += opt.pack()
    return o


class TimeExceeded (icmp_base):
  "Time Exceeded Big Message"

  def __init__ (self, raw=None, prev=None, **kw):
    icmp_base.__init__(self)
    self.prev = prev
    self.next = None

    if raw is not None: self.parse(raw)
    self._init(kw)

  def _fields (self):
    f = ['mtu']
    r = {}
    for ff in f:
      r[ff] = getattr(self, ff)
    return r

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()

    _offset = offset
    if buf_len is None: buf_len = len(raw)

    try:
      offset += 4 # Unused

      o.next = raw[offset:buf_len]
      offset = buf_len

      o.parsed = True
    except TruncatedException:
      pass

    o.raw = raw[_offset:offset]
    o.prev = prev
    return offset,o

  def hdr (self, payload):
    return struct.pack('!I', 0) # Unused


class PacketTooBig (icmp_base):
  "Packet Too Big Message"

  def __init__ (self, raw=None, prev=None, **kw):
    icmp_base.__init__(self)
    self.prev = prev
    self.next = None

    self.mtu = 0

    if raw is not None: self.parse(raw)
    self._init(kw)

  def _fields (self):
    f = ['mtu']
    r = {}
    for ff in f:
      r[ff] = getattr(self, ff)
    return r

  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    o = cls()

    _offset = offset
    if buf_len is None: buf_len = len(raw)

    try:
      o.mtu = struct.unpack_from("!I", raw, offset)
      offset += 4

      o.next = raw[offset:buf_len]
      offset = buf_len

      o.parsed = True
    except TruncatedException:
      pass

    o.raw = raw[_offset:offset]
    o.prev = prev
    return offset,o

  def hdr (self, payload):
    return struct.pack('!I', self.mtu)


class unpack_new_adapter (object):
  """
  Mixin to support unpack_new on classes with old-style construction/parse()
  """
  @classmethod
  def unpack_new (cls, raw, offset = 0, buf_len = None, prev = None):
    raw = raw[offset:]
    if buf_len is not None:
      raw = raw[:buf_len]
    o = cls(raw=raw,prev=prev)
    #o.parse(raw)
    return offset+len(o.raw),o

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
class echo (packet_base, unpack_new_adapter):
  "ICMP echo packet struct"

  MIN_LEN = 4

  def __init__ (self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.id  = random.randint(0, 65535)
    self.seq = 0

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def __str__ (self):
    return "[ICMP6 echo id:%i seq:%i]" % (self.id, self.seq)

  def parse (self, raw):
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

  def hdr (self, payload):
    return struct.pack('!HH', self.id, self.seq)


#----------------------------------------------------------------------
#
#  Destination Unreachable
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                            Unused                             |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |       IP Header + 8 bytes of original datagram's data         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#----------------------------------------------------------------------
class unreach (packet_base, unpack_new_adapter):
  "ICMP unreachable packet struct"

  MIN_LEN = 4

  def __init__ (self, raw=None, prev=None, **kw):

    self.prev = prev

    self.unused = 0

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def __str__ (self):
    s = ''.join(('[', 'm:', str(self.next_mtu), ']'))

    return _str_rest(s, self)

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.raw = raw
    dlen = len(raw)
    if dlen < self.MIN_LEN:
      self.msg('(unreach parse) warning unreachable payload too '
               + 'short to parse header: data len %u' % (dlen,))
      return

    (self.unused,) = struct.unpack('!I', raw[:self.MIN_LEN])

    self.parsed = True

    from . import ipv6
    # xxx We're assuming this is IPv6!
    if dlen >= 8 + ipv6.MIN_LEN:
      self.next = ipv6.ipv6(raw=raw[unreach.MIN_LEN:],prev=self)
    else:
      self.next = raw[unreach.MIN_LEN:]

  def hdr (self, payload):
    return struct.pack('!I', self.unused)




class icmpv6 (packet_base):
  "ICMP packet struct"

  MIN_LEN = 4

  def __init__ (self, raw=None, prev=None, **kw):
    super(icmpv6, self).__init__()

    self.prev = prev

    self.type = 0
    self.code = 0
    self.csum = 0

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def _calc_checksum (self):
    ph = self.prev.srcip.raw + self.prev.dstip.raw
    ph += struct.pack('!IHBB', len(self.raw), 0, 0, 58) # 58 == ICMPv6
    return checksum(ph + self.raw, skip_word=21)

  @property
  def checksum_ok (self):
    if not self.prev: return True
    if getattr(self, 'raw', None) is None: return True
    return self.csum == self._calc_checksum()

  def _to_str (self):
    t = _type_to_name.get(self.type, str(self.type))
    cs = ''
    if not self.checksum_ok:
      cs = " BAD_CHECKSUM(%02x!=%02x)" % (self.csum, self._calc_checksum())
    s = '[ICMP+%s/%i%s]' % (t, self.code, cs)
    return s

  def parse (self, raw, buf_len=None):
    assert isinstance(raw, bytes)
    if buf_len is None:
      buf_len = len(raw)
      self.raw = raw[:buf_len]
    else:
      self.raw = raw
    dlen = len(self.raw)
    if dlen < self.MIN_LEN:
      self.msg('(icmp parse) warning ICMP packet data too short to '
                + 'parse header: data len %u' % (dlen,))
      return

    (self.type, self.code, self.csum) \
        = struct.unpack('!BBH', raw[:self.MIN_LEN])
    #self.parsed = True

    if not self.checksum_ok:
      self.msg("Bad ICMPv6 checksum")
      self.next = raw[self.MIN_LEN:]
      return
    else:
      self.parsed = True

    #TODO: Use a class registry
    cls = {
        TYPE_ECHO_REQUEST:echo,
        TYPE_ECHO_REPLY:echo,
        TYPE_PACKET_TOO_BIG:PacketTooBig,
        TYPE_TIME_EXCEED:TimeExceeded,
        TYPE_DEST_UNREACH:unreach,
        TYPE_ROUTER_SOLICITATION:NDRouterSolicitation,
        TYPE_NEIGHBOR_SOLICITATION:NDNeighborSolicitation,
        TYPE_ROUTER_ADVERTISEMENT:NDRouterAdvertisement,
        TYPE_NEIGHBOR_ADVERTISEMENT:NDNeighborAdvertisement,
        }.get(self.type)
    if cls is None:
      #cls = unknown
      self.next = raw[self.MIN_LEN:]
      return

    offset,self.next = cls.unpack_new(raw, offset=self.MIN_LEN,
        buf_len=buf_len,prev=self)


  def hdr (self, payload):
    payload_len = len(payload) + 4
    ph = self.prev.srcip.raw + self.prev.dstip.raw
    ph += struct.pack('!IHBBBBH', payload_len, 0, 0, 58, # 58 == ICMPv6
                      self.type, self.code, 0)
    self.csum = checksum(ph + payload, 0, 21)
    return struct.pack('!BBH', self.type, self.code, self.csum)
