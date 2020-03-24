# Copyright 2011,2013 James McCauley
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
#                     DHCP Message Format
#
#  0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
#   +---------------+---------------+---------------+---------------+
#   |                            xid (4)                            |
#   +-------------------------------+-------------------------------+
#   |           secs (2)            |           flags (2)           |
#   +-------------------------------+-------------------------------+
#   |                          ciaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          yiaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          siaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          giaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          chaddr  (16)                         |
#   |                                                               |
#   |                                                               |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          sname   (64)                         |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          file    (128)                        |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          options (variable)                   |
#   +---------------------------------------------------------------+
#
#======================================================================
import struct
import string
from .packet_utils import *

from .packet_base import packet_base
import pox.lib.util as util
from pox.lib.util import is_subclass
from pox.lib.addresses import *

_dhcp_option_unpackers = {}


class dhcp(packet_base):
    "DHCP Packet struct"

    STRUCT_BOUNDARY = 28
    MIN_LEN = 240

    SERVER_PORT = 67
    CLIENT_PORT = 68

    BROADCAST_FLAG = 0x8000

    BOOTREQUEST = 1
    BOOTREPLY = 2

    MSG_TYPE_OPT = 53
    NUM_MSG_TYPES = 8
    DISCOVER_MSG = 1
    OFFER_MSG = 2
    REQUEST_MSG = 3
    DECLINE_MSG = 4
    ACK_MSG = 5
    NAK_MSG = 6
    RELEASE_MSG = 7
    INFORM_MSG = 8

    SUBNET_MASK_OPT = 1
    GATEWAY_OPT = 3
    ROUTERS_OPT = 3 # Synonym for above
    TIME_SERVERS_OPT = 4
    DNS_SERVER_OPT = 6
    HOST_NAME_OPT = 12
    DOMAIN_NAME_OPT = 15
    MTU_OPT = 26
    BCAST_ADDR_OPT = 28

    VENDOR_OPT = 43

    REQUEST_IP_OPT = 50
    REQUEST_LEASE_OPT = 51
    OVERLOAD_OPT = 52
    SERVER_ID_OPT = 54
    PARAM_REQ_OPT = 55
    ERROR_MSG_OPT = 56
    T1_OPT = 58
    T2_OPT = 59
    CLIENT_ID_OPT = 61
    PAD_OPT = 0
    END_OPT = 255

    MAGIC = b'\x63\x82\x53\x63'

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.op = 0
        self.htype = 0
        self.hlen = 0
        self.hops = 0
        self.xid = 0
        self.secs = 0
        self.flags = 0
        self.ciaddr = IP_ANY
        self.yiaddr = IP_ANY
        self.siaddr = IP_ANY
        self.giaddr = IP_ANY
        self.chaddr = None
        self.sname = b''
        self.file = b''
        self.magic = self.MAGIC
        self._raw_options = b''

        if raw is not None:
            self.parse(raw)
        else:
            self.options = util.DirtyDict()

        self._init(kw)

    def _to_str(self):
        s  = '[DHCP op:'+str(self.op)
        s += ' htype:'+str(self.htype)
        s += ' hlen:'+str(self.hlen)
        s += ' hops:'+str(self.hops)
        s += ' xid:'+str(self.xid)
        s += ' secs:'+str(self.secs)
        s += ' flags:'+str(self.flags)
        s += ' ciaddr:'+str(self.ciaddr)
        s += ' yiaddr:'+str(self.yiaddr)
        s += ' siaddr:'+str(self.siaddr)
        s += ' giaddr:'+str(self.giaddr)
        s += ' chaddr:'
        if isinstance(self.chaddr, EthAddr):
            s += str(self.chaddr)
        elif self.chaddr is not None:
            s += ' '.join(["{0:02x}".format(x) for x in self.chaddr])
        s += ' magic:'+' '.join(
            ["{0:02x}".format(ord(x)) for x in self.magic])
        #s += ' options:'+' '.join(["{0:02x}".format(ord(x)) for x in
        #                          self._raw_options])
        if len(self.options):
          s += ' options:'
          s += ','.join(repr(x) for x in self.options.values())
        s += ']'
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < dhcp.MIN_LEN:
            self.msg('(dhcp parse) warning DHCP packet data too short ' +
                     'to parse header: data len %u' % (dlen,))
            return None

        (self.op, self.htype, self.hlen, self.hops, self.xid,self.secs,
         self.flags, self.ciaddr, self.yiaddr, self.siaddr,
         self.giaddr) = struct.unpack('!BBBBIHHIIII', raw[:28])

        self.ciaddr = IPAddr(self.ciaddr)
        self.yiaddr = IPAddr(self.yiaddr)
        self.siaddr = IPAddr(self.siaddr)
        self.giaddr = IPAddr(self.giaddr)

        self.chaddr = raw[28:44]
        if self.hlen == 6:
            # Assume chaddr is ethernet
            self.chaddr = EthAddr(self.chaddr[:6])
        self.sname = raw[44:108]
        self.file = raw[102:236]
        self.magic = raw[236:240]

        self.hdr_len = dlen
        self.parsed = True

        if self.hlen > 16:
            self.warn('(dhcp parse) DHCP hlen %u too long' % (self.hlen),)
            return

        for i in range(4):
            if dhcp.MAGIC[i] != self.magic[i]:
                self.warn('(dhcp parse) bad DHCP magic value %s' %
                          str(self.magic))
                return

        self._raw_options = raw[240:]
        self.parseOptions()
        self.unpackOptions()
        self.parsed = True

    def unpackOptions(self):
      for k,v in self.options.items():
        unpack = _dhcp_option_unpackers.get(k, DHCPRawOption.unpack)
        try:
          self.options[k] = unpack(v,k)
        except Exception as e:
          self.warn("(dhcp parse) bad option %s: %s" % (k,e))
          #import traceback
          #traceback.print_exc()
          self.options[k] = DHCPRawOption.unpack(v,k,True)

    def parseOptions(self):
        self.options = util.DirtyDict()
        self.parseOptionSegment(self._raw_options)
        if dhcp.OVERLOAD_OPT in self.options:
            opt_val = self.options[dhcp.OVERLOAD_OPT]
            if len(opt_val) != 1:
                self.warn('DHCP overload option has bad len %u' %
                          (len(opt_val),))
                return
            if opt_val == 1 or opt_val == 3:
                self.parseOptionSegment(self.file)
            if opt_val == 2 or opt_val == 3:
                self.parseOptionSegment(self.sname)

    def parseOptionSegment(self, barr):
        ofs = 0;
        l = len(barr)
        while ofs < l:
            opt = ord(barr[ofs])
            if opt == dhcp.END_OPT:
                return
            ofs += 1
            if opt == dhcp.PAD_OPT:
                continue
            if ofs >= l:
                self.warn('DHCP option ofs extends past segment')
                return
            opt_len = ord(barr[ofs])
            ofs += 1         # Account for the length octet
            if ofs + opt_len > l:
                return False
            if opt in self.options:
                # Append option, per RFC 3396
                self.options[opt] += barr[ofs:ofs+opt_len]
            else:
                self.options[opt] = barr[ofs:ofs+opt_len]
            ofs += opt_len
        self.warn('DHCP end of option segment before END option')

    def packOptions (self):
        o = b''
        def addPart (k, v):
            o = b''
            o += chr(k)
            o += chr(len(v))
            o += bytes(v)
            if len(o) & 1: # Length is not even
                o += chr(dhcp.PAD_OPT)
            return o

        for k,v in self.options.items():
            if k == dhcp.END_OPT: continue
            if k == dhcp.PAD_OPT: continue
            if isinstance(v, DHCPOption):
                v = v.pack()
            if isinstance(v, bytes) and (len(v) > 255):
                # Long option, per RFC 3396
                v = [v[i:i+255] for i in range(0, len(v), 255)]
            if isinstance(v, list): # Better way to tell?
                for part in v:
                    o += addPart(k, part)
            else:
                o += addPart(k, v)
        o += chr(dhcp.END_OPT)
        self._raw_options = o

        if isinstance(self.options, util.DirtyDict):
            self.options.dirty = False

    def add_option(self, option, code=None):
      if code is None:
        code = option.CODE
      self.options[code] = option

    def hdr(self, payload):
        if isinstance(self.options, util.DirtyDict):
            if self.options.dirty:
                self.packOptions()
        else:
            self.packOptions()

        if isinstance(self.chaddr, EthAddr):
          chaddr = self.chaddr.toRaw() + (b'\x00' * 10)
        else:
          chaddr = self.chaddr
          if chaddr is None:chaddr = b'\x00' * 16
        fmt = '!BBBBIHHiiii16s64s128s4s'
        return struct.pack(fmt, self.op, self.htype, self.hlen,
                           self.hops, self.xid, self.secs, self.flags,
                           IPAddr(self.ciaddr).toSigned(),
                           IPAddr(self.yiaddr).toSigned(),
                           IPAddr(self.siaddr).toSigned(),
                           IPAddr(self.giaddr).toSigned(),
                           chaddr, self.sname, self.file,
                           self.magic) + self._raw_options

    def appendRawOption (self, code, val = None, length = None):
        """
        In general, a much better way to add options should just be
        to add them to the .options dictionary.
        """

        self._raw_options += chr(code)
        if length is None:
            if val is None:
                return
            length = len(val)
        self._raw_options += chr(length)
        self._raw_options += val

    @property
    def msg_type (self):
        """
        DHCP message type or None
        """
        opt = self.options.get(self.MSG_TYPE_OPT)
        if opt is None: return None
        return opt.type


def dhcp_option_def (msg_type):
  """
  DPCP Option decorator
  """
  def f (cls):
    _dhcp_option_unpackers[msg_type] = cls.unpack
    cls.CODE = msg_type
    return cls
  return f

class DHCPOption (object):
  CODE = None

  @classmethod
  def unpack (cls, data, code = None):
    pass

  def pack (self):
    return b''

  @property
  def _name (self):
    n = type(self).__name__
    if n.startswith("DHCP"): n = n[4:]
    if n.endswith("Option"): n = n[:-6]
    if n == "": return "Option"
    return n

class DHCPRawOption (DHCPOption):
  def __init__ (self, data = b'', bad = False):
    self.data = data
    self.bad = bad # True if option wasn't parsed right

  @classmethod
  def unpack (cls, data, code = None, bad = False):
    self = cls()
    self.data = data
    self.bad = bad
    self.CODE = code
    return self

  def pack (self):
    return self.data

  def __repr__ (self):
    data = self.data
    if not all(ord(c)<127 and c in string.printable for c in data):
      data = " ".join("%02x" % (ord(x),) for x in data)
    else:
      data = "".join(x if ord(x) >= 32 else "." for x in data)
    if len(data) > 30:
      data = data[:30] + "..."
    n = self._name
    if n == 'Raw': n += str(self.CODE)
    return "%s(%s)" % (n, data)

class DHCPIPOptionBase (DHCPOption):
  """
  Superclass for options which are an IP address
  """
  def __init__ (self, addr = None):
    self.addr = IPAddr(0) if addr is None else IPAddr(addr)

  @classmethod
  def unpack (cls, data, code = None):
    self = cls()
    if len(data) != 4: raise RuntimeError("Bad option length")
    self.addr = IPAddr(data)
    return self

  def pack (self):
    return self.addr.toRaw()

  def __repr__ (self):
    return "%s(%s)" % (self._name, self.addr)

class DHCPIPsOptionBase (DHCPOption):
  """
  Superclass for options which are a list of IP addresses
  """
  def __init__ (self, addrs=[]):
    if isinstance(addrs, (str,bytes,IPAddr)):
      self.addrs = [IPAddr(addrs)]
    else:
      self.addrs = [IPAddr(a) for a in addrs]

  @classmethod
  def unpack (cls, data, code = None):
    self = cls()
    if (len(data) % 4) != 0: raise RuntimeError("Bad option length")
    while len(data):
      self.addrs.append(IPAddr(data[:4]))
      data = data[4:]
    return self

  def pack (self):
    r = b''
    for addr in self.addrs:
      r += addr.toRaw()
    return r

  @property
  def addr (self):
    if len(self.addrs) == 0: return None
    return self.addrs[0]

  def __repr__ (self):
    return "%s(%s)" % (self._name, self.addrs)

class DHCPSecondsOptionBase (DHCPOption):
  """
  Superclass for options which are a number of seconds as 4 bytes
  """
  def __init__ (self, seconds = None):
    self.seconds = seconds

  @classmethod
  def unpack (cls, data, code = None):
    self = cls()
    if len(data) != 4: raise RuntimeError("Bad option length")
    self.seconds, = struct.unpack('!I', data)
    return self

  def pack (self):
    return struct.pack('!I', self.seconds)

  def __repr__ (self):
    return "%s(%s)" % (self._name, self.seconds)

@dhcp_option_def(dhcp.MSG_TYPE_OPT)
class DHCPMsgTypeOption (DHCPOption):
  def __init__ (self, type=None):
    self.type = type

  @classmethod
  def unpack (cls, data, code = None):
    self = cls()
    if len(data) != 1: raise RuntimeError("Bad option length")
    self.type = ord(data[0])
    return self

  def pack (self):
    return chr(self.type)

  def __repr__ (self):
    t = {
        1:'DISCOVER',
        2:'OFFER',
        3:'REQUEST',
        4:'DECLINE',
        5:'ACK',
        6:'NAK',
        7:'RELEASE',
        8:'INFORM',
    }.get(self.type, "TYPE"+str(self.type))
    return "%s(%s)" % (self._name, t)

@dhcp_option_def(dhcp.SUBNET_MASK_OPT)
class DHCPSubnetMaskOption (DHCPIPOptionBase):
  pass

@dhcp_option_def(dhcp.ROUTERS_OPT)
class DHCPRoutersOption (DHCPIPsOptionBase):
  pass

@dhcp_option_def(dhcp.TIME_SERVERS_OPT)
class DHCPTimeServersOption (DHCPIPsOptionBase):
  pass

@dhcp_option_def(dhcp.DNS_SERVER_OPT)
class DHCPDNSServersOption (DHCPIPsOptionBase):
  pass

@dhcp_option_def(dhcp.HOST_NAME_OPT)
class DHCPHostNameOption (DHCPRawOption):
  pass

@dhcp_option_def(dhcp.DOMAIN_NAME_OPT)
class DHCPDomainNameOption (DHCPRawOption):
  pass

@dhcp_option_def(dhcp.BCAST_ADDR_OPT)
class DHCPBroadcastAddressOption (DHCPIPOptionBase):
  pass

@dhcp_option_def(dhcp.VENDOR_OPT)
class DHCPVendorOption (DHCPRawOption):
  pass

@dhcp_option_def(dhcp.REQUEST_IP_OPT)
class DHCPRequestIPOption (DHCPIPOptionBase):
  pass

@dhcp_option_def(dhcp.REQUEST_LEASE_OPT)
class DHCPIPAddressLeaseTimeOption (DHCPSecondsOptionBase):
  pass

@dhcp_option_def(dhcp.OVERLOAD_OPT)
class DHCPOptionOverloadOption (DHCPOption):
  def __init__ (self, value = None):
    self.value = value

  @classmethod
  def unpack (cls, data, code = None):
    self = cls()
    if len(data) != 1: raise RuntimeError("Bad option length")
    self.value = ord(data[0])
    return self

  def pack (self):
    return chr(self.value)

  def __repr__ (self):
    return "%s(%s)" % (self._name, self.value)

@dhcp_option_def(dhcp.SERVER_ID_OPT)
class DHCPServerIdentifierOption (DHCPIPOptionBase):
  pass

@dhcp_option_def(dhcp.ERROR_MSG_OPT)
class DHCPErrorMessageOption (DHCPRawOption):
  pass

@dhcp_option_def(dhcp.T1_OPT)
class DHCPRenewalTimeOption (DHCPSecondsOptionBase):
  pass

@dhcp_option_def(dhcp.T2_OPT)
class DHCPRebindingTimeOption (DHCPSecondsOptionBase):
  pass

@dhcp_option_def(dhcp.PARAM_REQ_OPT)
class DHCPParameterRequestOption (DHCPOption):
  def __init__ (self, options = []):
    self.options = options

  @classmethod
  def unpack (cls, data, code = None):
    self = cls()
    self.options = [ord(x) for x in data]
    return self

  def pack (self):
    opt = ((o.CODE if is_subclass(o, DHCPOption) else o) for o in self.options)
    return b''.join(chr(x) for x in opt)

  def __repr__ (self):
    names = []
    for o in sorted(self.options):
      n = _dhcp_option_unpackers.get(o)
      if n is None or not hasattr(n, 'im_self'):
        n = "Opt/" + str(o)
      else:
        n = n.__self__.__name__
        if n.startswith("DHCP"): n = n[4:]
        if n.endswith("Option"): n = n[:-6]
        if n == "": n = "Opt"
        n += '/' + str(o)
      names.append(n)

    return "%s(%s)" % (self._name, " ".join(names))
