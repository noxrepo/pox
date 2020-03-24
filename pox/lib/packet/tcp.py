# Copyright 2011,2013,2014 James McCauley
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
#                           TCP Header Format
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Data |           |U|A|P|R|S|F|                               |
#  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
#  |       |           |G|K|H|T|N|N|                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           Checksum            |         Urgent Pointer        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Options                    |    Padding    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct
from .packet_utils import *
from socket import htons
from socket import htonl

from .packet_base import packet_base

import logging
lg = logging.getLogger('packet')


class tcp_opt (object):
  """
  A TCP option

  Currently, this single class represents any of several TCP options, as well
  as being a "catch all" for unknown options.  In the future, individual
  options may be broken out into separate classes.
  """
  EOL      = 0
  NOP      = 1
  MSS      = 2
  WSOPT    = 3
  SACKPERM = 4
  SACK     = 5
  TSOPT    = 8
  MPTCP    = 30

  def __init__ (self, type, val):
    self.type = type
    self.val  = val

  def pack (self):
    if self.type == tcp_opt.EOL or self.type == tcp_opt.NOP:
      return struct.pack('B',self.type)
    elif self.type == tcp_opt.MSS:
      return struct.pack('!BBH',self.type,4,self.val)
    elif self.type == tcp_opt.WSOPT:
      return struct.pack('!BBB',self.type,3,self.val)
    elif self.type == tcp_opt.SACKPERM:
      return struct.pack('!BB',self.type,2)
    elif self.type == tcp_opt.SACK:
      return struct.pack("!" + "II" * len(self.val),
                         *[x for p in self.val for x in p])
    elif self.type == tcp_opt.TSOPT:
      return struct.pack('!BBII',self.type,10,self.val[0],self.val[1])
    else:
      lg.debug('(tcp_opt pack) warning, unknown option type ' +
               str(self.type))
      return struct.pack('BB',self.type,2+len(self.val)) + self.val

  @classmethod
  def unpack_new (cls, buf, offset = 0):
    o = cls(buf[offset], None)

    arr = buf
    i = offset
    length = arr[i+1]

    # These should be special-cased elsewhere
    assert o.type != tcp_opt.EOL
    assert o.type != tcp_opt.NOP

    if o.type == tcp_opt.MSS:
      if length != 4:
        raise RuntimeError("MSS option length != 4")
      o.val = struct.unpack('!H',arr[i+2:i+4])[0]
    elif o.type == tcp_opt.WSOPT:
      if length != 3:
        raise RuntimeError("WSOPT option length != 3")
      o.val = arr[i+2]
    elif o.type == tcp_opt.SACKPERM:
      if length != 2:
        raise RuntimeError("SACKPERM option length != 2")
    elif o.type == tcp_opt.SACK:
      if length >= 2 and ((length-2) % 8) == 0:
        num = (length - 2) // 8
        val = struct.unpack("!" + "II" * num, arr[i+2:])
        val = [(x,y) for x,y in zip(val[0::2],val[1::2])]
        o.val = val
      else:
        raise RuntimeError("Invalid SACK option")
    elif o.type == tcp_opt.TSOPT:
      if length != 10:
        raise RuntimeError("TSOPT option length != 10")
      (val1,val2) = struct.unpack('!II',arr[i+2:i+10])
      o.val = (val1,val2)
    elif o.type == tcp_opt.MPTCP:
      #TODO: Clean this up (we're throwing away an already-initialized tcp_opt)
      return mptcp_opt.unpack_new(buf, offset)
    else:
      #self.msg('(tcp parse_options) warning, unknown option %x '
      #         % (ord(arr[i]),))
      o.val = arr[i+2:i+2+length]

    return offset+length,o

  def __str__ (self):
    #FIXME: Ugly
    names={0:'EOL',1:'NOP',2:'MSS',3:'WSOPT',4:'SACKPERM',5:'SACK',8:'TSOPT'}
    return names.get(self.type,"tcp_opt-%s" % (self.type,))


# Decorator for mptcp subtypes
_mptcp_opts = {} # type -> class
def _register_mptcp_opt (type):
  def register_subtype (cls):
    _mptcp_opts[type] = cls
    return cls
  return register_subtype


class mptcp_opt (tcp_opt):
  """
  An MPTCP option

  MPTCP uses a single TCP option with subtypes.  We handle this specially.
  This is really an abstract superclass.
  """
  MP_CAPABLE     = 0
  MP_JOIN        = 1
  MP_DSS         = 2
  MP_ADD_ADDR    = 3
  MP_REMOVE_ADDR = 4
  MP_PRIO        = 5
  MP_FAIL        = 6
  MP_FASTCLOSE   = 7

  def __init__ (self):
    self.type = self.MPTCP
    self.subtype = None

  @classmethod
  def unpack_new (dummy, buf, offset = 0):
    """
    Unpacks an MPTCP option

    Returns a subclass for the specific option subtype.  If the subtype
    is unknown, returns a generic mp_unknown.
    """
    t = buf[offset]
    assert t == 30
    st = (buf[offset+2] & 0xf0) >> 4
    cls = _mptcp_opts.get(st, mp_unknown)
    return cls.unpack_new(buf, offset)

  def pack (self):
    raise RuntimeError("You can only pack a subtype")

  def __str__ (self):
    n = type(self).__name__
    return "%s" % (n,)


class mp_unknown (mptcp_opt):
  """
  An unknown MPTCP option
  """
  def __init__ (self):
    self.type = self.MPTCP
    self.subtype = None
    self.data = b''

  def pack (self):
    return struct.pack('BB',self.type,2+len(self.data)) + self.data

  @classmethod
  def unpack_new (cls, buf, offset = 0):
    o = cls()
    o.type = buf[offset]
    length = buf[offset+1]
    o.data = buf[offset+2:offset+2+length]
    try:
      self.subtype = (buf[offset+2] & 0xf0) >> 4
    except:
      pass

    return offset+length,o

  def __str__ (self):
    # Special case.  We don't parse the subtype, into an attribute, but
    # we'll display it.
    if self.subtype is not None:
      subtype = self.subtype
    else:
      subtype = "???"
    return "mptcp_opt-%s" % (subtype,)


@_register_mptcp_opt(mptcp_opt.MP_CAPABLE)
class mp_capable_opt (mptcp_opt):
  def __init__ (self):
    self.type = self.MPTCP
    self.subtype = self.MP_CAPABLE
    self.version = 0
    self.flags = 0
    self.skey = None
    self.rkey = None

  @property
  def checksum_required (self):
    return self.flags & (1<<7)

  @property
  def use_hmac_sha1 (self):
    return self.flags & (1<<0)

  @classmethod
  def unpack_new (cls, buf, offset = 0):
    o = cls()
    o.type,length,subver,o.flags = struct.unpack_from('!BBBB', buf, offset)
    o.subtype = (subver & 0xf0) >> 4
    o.version = (subver & 0x0f) >> 0

    if length != 12 and length != 20:
      # Should this be an exception?  Do we handle it?
      raise RuntimeError("Bad MP_CAPABLE option")
    offset += 4

    o.skey = buf[offset:offset+8]
    offset += 8
    if length == 20:
      o.rkey = buf[offset:offset+8]
      offset += 8

    return offset,o

  def pack (self):
    length = 20 if self.rkey else 12
    subver = (self.subtype << 4) | self.version

    assert len(self.skey) == 8
    if self.rkey: assert len(self.rkey) == 8

    r = struct.pack("!BBBB", self.type, length, subver, self.flags)
    r += self.skey
    if self.rkey: r += self.rkey

    return r


@_register_mptcp_opt(mptcp_opt.MP_JOIN)
class mp_join_opt (mptcp_opt):
  def __init__ (self):
    self.type = self.MPTCP
    self.subtype = self.MP_JOIN
    self.flags = 0
    self.address_id = None

    self.rtoken = None
    self.srand = None

    self.shmac = None

    self.phase = None
    # 1 -> SYN, 2 -> SYNACK, 3 -> ACK

  @property
  def SYN_expected (self):
    return self.phase in (1,2)

  @property
  def ACK_expected (self):
    return self.phase in (2,3)

  @property
  def backup (self):
    return self.flags & (1<<0)

  @property
  def has_full_hmac (self):
    if not self.shmac: return False
    return len(self.shmac) == 20

  @classmethod
  def unpack_new (cls, buf, offset = 0):
    o = cls()
    o.type,length,subflag,o.address_id = struct.unpack_from('!BBBB', buf, offset)
    o.subtype = (subflag & 0xf0) >> 4
    o.flags = (subflag & 0x0f) >> 0

    offset += 4

    if length == 12:
      o.phase = 1
      o.rtoken = buf[offset:offset+4]
      offset += 4
      o.srand = buf[offset:offset+4]
      offset += 4
    elif length == 16:
      o.phase = 2
      o.shmac = buf[offset:offset+8] # Truncated
      offset += 8
      o.srand = buf[offset:offset+4]
      offset += 4
    elif length == 24:
      o.phase = 3
      o.shmac = buf[offset:offset+20]
      offset += 20
    else:
      # Should this be an exception?  Do we handle it?
      raise RuntimeError("Bad MP_JOIN option")

    return offset,o

  def pack (self):
    length = {1:12,2:16,3:24}[self.phase]
    subflag = (self.subtype << 4) | self.flags

    r = struct.pack("!BBBB", self.type, length, subflag, self.address_id)

    if self.phase == 1:
      assert len(self.rtoken) == 4
      assert len(self.srand) == 4
      r += self.rtoken + self.srand

    elif self.phase == 2:
      assert len(self.shmac) in (8, 20)
      assert len(self.srand) == 4
      r += self.shmac[:8] + self.srand

    elif self.phase == 3:
      assert len(self.shmac) == 20
      r += self.shmac

    return r


@_register_mptcp_opt(mptcp_opt.MP_DSS)
class mp_dss_opt (mptcp_opt):
  def __init__ (self):
    self.type = self.MPTCP
    self.subtype = self.MP_DSS
    self.ack = None
    self.dsn = None
    self.seq = None
    self.length = None
    self.csum = None

  @property
  def has_ack (self):
    return self.flags & (1<<0)

  @property
  def ack_length (self):
    if not self.has_ack:
      return 0
    return 8 if self.flags & (1<<1) else 4

  @property
  def has_dsn (self):
    return self.flags & (1<<2)

  @property
  def dsn_length (self):
    if not self.has_dsn:
      return 0
    return 8 if self.flags & (1<<3) else 4

  @property
  def FIN (self):
    return self.flags & (1<<4)

  @classmethod
  def unpack_new (cls, buf, offset = 0):
    off = offset
    o = cls()
    o.type,length,subver,o.flags = struct.unpack_from('!BBBB', buf, offset)
    off += 4
    o.subtype = (subver & 0xf0) >> 4
    assert o.subtype == o.MP_DSS

    good_len = 4 + o.ack_length + o.dsn_length
    if o.has_dsn: good_len += 4 + 2 + 2
    if length != good_len:
      raise RuntimeError("Malformed mp_dss")

    if o.has_ack:
      if o.ack_length == 4:
        o.ack = struct.unpack_from("!I", buf, off)[0]
      else:
        o.ack = struct.unpack_from("!Q", buf, off)[0]
      off += o.ack_length

    if o.has_dsn:
      if o.dsn_length == 4:
        o.dsn = struct.unpack_from("!I", buf, off)[0]
      else:
        o.dsn = struct.unpack_from("!Q", buf, off)[0]
      off += o.ack_length

      o.seq,o.length,o.csum = struct.unpack_from("!IHH", buf, off)
      off += 4 + 2 + 2

      #TODO: Check csum?

    return off,o

  def pack (self):
    o = self
    good_len = 4 + o.ack_length + o.dsn_length
    if o.has_dsn: good_len += 4 + 2 + 2

    subver = (self.subtype << 4) | 0

    r = struct.pack("!BBBB", self.type, good_len, subver, self.flags)

    if o.has_ack:
      if o.ack_length == 4:
        r += struct.pack("!I", o.ack)
      else:
        r += struct.pack("!Q", o.ack)

    if o.has_dsn:
      if o.dsn_length == 4:
        r += struct.unpack_from("!I", o.dsn)
      else:
        r += struct.unpack_from("!Q", o.dsn)

      #TODO: Compute csum?
      r += struct.pack("!IHH", o.seq,o.length,o.csum)

    assert len(r) == good_len
    return r


class tcp (packet_base):
  """
  A TCP packet

  Note that flags can be individually read or written using attributes with
  the name of the flag in all caps.
  """

  MIN_LEN = 20

  FIN_flag = 0x01
  SYN_flag = 0x02
  RST_flag = 0x04
  PSH_flag = 0x08
  ACK_flag = 0x10
  URG_flag = 0x20
  ECN_flag = 0x40
  CWR_flag = 0x80

  @property
  def FIN (self): return True if self.flags & self.FIN_flag else False
  @property
  def SYN (self): return True if self.flags & self.SYN_flag else False
  @property
  def RST (self): return True if self.flags & self.RST_flag else False
  @property
  def PSH (self): return True if self.flags & self.PSH_flag else False
  @property
  def ACK (self): return True if self.flags & self.ACK_flag else False
  @property
  def URG (self): return True if self.flags & self.URG_flag else False
  @property
  def ECN (self): return True if self.flags & self.ECN_flag else False
  @property
  def CWR (self): return True if self.flags & self.CWR_flag else False

  @FIN.setter
  def FIN (self, value): self._setflag(self.FIN_flag, value)
  @SYN.setter
  def SYN (self, value): self._setflag(self.SYN_flag, value)
  @RST.setter
  def RST (self, value): self._setflag(self.RST_flag, value)
  @PSH.setter
  def PSH (self, value): self._setflag(self.PSH_flag, value)
  @ACK.setter
  def ACK (self, value): self._setflag(self.ACK_flag, value)
  @URG.setter
  def URG (self, value): self._setflag(self.URG_flag, value)
  @ECN.setter
  def ECN (self, value): self._setflag(self.ECN_flag, value)
  @CWR.setter
  def CWR (self, value): self._setflag(self.CWR_flag, value)

  def _setflag (self, flag, value):
    self.flags = (self.flags & ~flag) | (flag if value else 0)

  def __init__ (self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.srcport  = 0  # 16 bit
    self.dstport  = 0  # 16 bit
    self.seq      = 0  # 32 bit
    self.ack      = 0  # 32 bit
    self.off      = 0  # 4 bits
    self.res      = 0  # 4 bits
    self.flags    = 0  # reserved, 2 bits flags 6 bits
    self.win      = 0  # 16 bits
    self.csum     = 0  # 16 bits
    self.urg      = 0  # 16 bits
    self.tcplen   = 0  # Options? #TODO: FIXME
    self.options  = []
    self.next     = b''

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def __str__ (self):
    f = ''
    if self.SYN: f += 'S'
    if self.ACK: f += 'A'
    if self.FIN: f += 'F'
    if self.RST: f += 'R'
    if self.PSH: f += 'P'
    if self.URG: f += 'U'
    if self.ECN: f += 'E'
    if self.CWR: f += 'C'

    ops = ''
    if self.options:
      ops = ' opt:'+','.join(str(o) for o in self.options)

    s = '[TCP %s>%s seq:%s ack:%s f:%s%s]' % (self.srcport,
        self.dstport, self.seq, self.ack, f, ops)

    return s

  def find_option (self, option):
    for i,o in enumerate(self.options):
      if o.type == option:
        return i
    return None

  def get_option (self, option):
    i = self.find_option(option)
    if i is None: return None
    return self.options[i]

  def parse_options (self, raw):

    self.options = []
    dlen = len(raw)

    # option parsing
    i = tcp.MIN_LEN
    arr = raw

    while i < self.hdr_len:
      # Special case single-byte options
      if arr[i] == tcp_opt.EOL:
        break
      if arr[i] == tcp_opt.NOP:
        self.options.append(tcp_opt(tcp_opt.NOP,None))
        i += 1
        continue

      # Sanity checking
      if i + 2 > dlen:
        raise RuntimeError("Very truncated TCP option")
      if i + arr[i+1] > dlen:
        raise RuntimeError("Truncated TCP option")
      if arr[i+1] < 2:
        raise RuntimeError("Illegal TCP option length")

      i,opt = tcp_opt.unpack_new(arr, i)
      if opt:
        self.options.append(opt)

    return i

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.next = None # In case of unfinished parsing
    self.raw = raw
    dlen = len(raw)
    if dlen < tcp.MIN_LEN:
      self.msg('(tcp parse) warning TCP packet data too short to parse header: data len %u' % (dlen,))
      return

    (self.srcport, self.dstport, self.seq, self.ack, offres, self.flags,
    self.win, self.csum, self.urg) \
        = struct.unpack('!HHIIBBHHH', raw[:tcp.MIN_LEN])

    self.off = offres >> 4
    self.res = offres & 0x0f

    self.hdr_len = self.off * 4
    self.payload_len = dlen - self.hdr_len

    self.tcplen = dlen
    if dlen < self.tcplen:
      self.msg('(tcp parse) warning TCP packet data shorter than TCP len: %u < %u' % (dlen, self.tcplen))
      return
    if (self.off * 4) < self.MIN_LEN or (self.off * 4) > dlen :
      self.msg('(tcp parse) warning TCP data offset too long or too short %u' % (self.off,))
      return

    try:
      self.parse_options(raw)
    except Exception as e:
      self.msg(e)
      return

    self.next   = raw[self.hdr_len:]
    self.parsed = True

  @property
  def len (self):
    return self.tcplen - self.hdr_len

  def __len__ (self):
    return self.len

  def hdr (self, payload, calc_checksum = True, calc_off = True):
    if calc_checksum:
      self.csum = self.checksum(payload=payload)
      csum = self.csum
    else:
      csum = 0

    options_packed = b"".join(opt.pack() for opt in self.options)
    hdr_len = self.MIN_LEN
    hdr_len += len(options_packed)
    if hdr_len % 4:
        options_pad_len = 4 - (hdr_len % 4) # number of bytes to pad
        options_packed += b"\000" * options_pad_len
        hdr_len += options_pad_len
    assert hdr_len % 4 == 0

    if calc_off:
        self.off = hdr_len // 4

    offres = self.off << 4 | self.res
    header = struct.pack('!HHIIBBHHH',
        self.srcport, self.dstport, self.seq, self.ack,
        offres, self.flags,
        self.win, csum, self.urg)
    return header + options_packed

  def checksum (self, unparsed=False, payload=None):
    """
    Calculates the checksum

    If unparsed, calculates it on the raw, unparsed data.  This is
    useful for validating that it is correct on an incoming packet.
    """
    ip_ver = None
    if self.prev.__class__.__name__  == 'ipv4':
      ip_ver = 4
    elif self.prev.__class__.__name__  == 'ipv6':
      ip_ver = 6
    else:
      self.msg('packet not in IP; cannot calculate checksum ' +
                'over psuedo-header' )
      return 0

    if unparsed:
      payload_len = len(self.raw)
      payload = self.raw
    else:
      if payload is not None:
        pass
      elif isinstance(self.next, packet_base):
        payload = self.next.pack()
      elif self.next is None:
        payload = bytes()
      else:
        payload = self.next
      payload = self.hdr(None, calc_checksum = False) + payload
      payload_len = len(payload)

    if ip_ver == 4:
      ph = struct.pack('!IIBBH', self.prev.srcip.toUnsigned(),
                                 self.prev.dstip.toUnsigned(),
                                 0,
                                 self.prev.protocol,
                                 payload_len)

      return checksum(ph + payload, 0, 14)
    elif ip_ver == 6:
      ph = self.prev.srcip.raw + self.prev.dstip.raw
      ph += struct.pack('!IHBB', payload_len, 0, 0,
                        self.prev.next_header_type)

      return checksum(ph + payload, 0, 28)
