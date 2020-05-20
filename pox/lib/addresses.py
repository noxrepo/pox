# Copyright 2011,2012,2013,2014,2018 James McCauley
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

"""
Classes and utilities for addresses of various types.
"""

from __future__ import print_function
import struct
import socket

_eth_oui_to_name = {} # OUI (3 bytes) -> name

def _load_oui_names ():
  """
  Load OUI names from textfile

  Assumes the textfile is adjacent to this source file.
  """
  import inspect
  import os.path
  filename = os.path.join(os.path.dirname(inspect.stack()[0][1]), 'oui.txt')
  f = None
  try:
    f = open(filename, "r", encoding = "latin-1")
    for line in f.readlines():
      if len(line) < 1:
        continue
      if line[0].isspace():
        continue
      split = line.split(' ')
      if not '-' in split[0]:
        continue
      # grab 3-byte OUI
      oui  = bytes(int(x,16) for x in split[0].split('-'))
      # strip off (hex) identifer and keep rest of name
      end = ' '.join(split[1:]).strip()
      end = end.split('\t')
      end.remove('(hex)')
      oui_name = ' '.join(end)
      _eth_oui_to_name[oui] = oui_name.strip()
  except:
    raise
    import logging
    logging.getLogger().warn("Could not load OUI list")
  if f: f.close()
_load_oui_names()


def _compare_helper (self, other, f, rf):
  t = type(self)
  try:
    if isinstance(other, t): ov = other._value
    else: ov = t(other)._value
    return getattr(self._value, f)(ov)
  except Exception:
    return getattr(other, rf)(self)


class _AddrBase (object):
  def __eq__(self, other):
    return _compare_helper(self, other, '__eq__', '__eq__')

  def __ne__(self, other):
    return _compare_helper(self, other, '__ne__', '__ne__')

  def __lt__(self, other):
    return _compare_helper(self, other, '__lt__', '__ge__')

  def __gt__(self, other):
    return _compare_helper(self, other, '__gt__', '__le__')

  def __le__(self, other):
    return _compare_helper(self, other, '__le__', '__gt__')

  def __ge__(self, other):
    return _compare_helper(self, other, '__ge__', '__lt__')



class EthAddr (_AddrBase):
  """
  An Ethernet (MAC) address type.

  Internal storage is six raw bytes.
  """
  def __init__ (self, addr):
    """
    Constructor

    Understands Ethernet address is various forms.  Hex strings, raw byte
    strings, etc.
    """
    if isinstance(addr, str): addr = addr.encode()

    if isinstance(addr, bytes):
      if len(addr) == 6:
        # raw
        pass
      elif len(addr) == 17 or len(addr) == 12 or addr.count(b':') == 5:
        # hex
        if len(addr) == 17:
          if addr[2::3] != b':::::' and addr[2::3] != b'-----':
            raise RuntimeError("Bad format for ethernet address")
          # Address of form xx:xx:xx:xx:xx:xx
          # Pick out the hex digits only
          addr = b''.join((addr[x*3:x*3+2] for x in range(0,6)))
        elif len(addr) == 12:
          pass
        else:
          # Assume it's hex digits but they may not all be in two-digit
          # groupings (e.g., xx:x:x:xx:x:x). This actually comes up.
          addr = b''.join([b"%02x" % (int(x,16),) for x in addr.split(b":")])
        # We should now have 12 hex digits (xxxxxxxxxxxx).
        # Convert to 6 raw bytes.
        addr = bytes(int(addr[x*2:x*2+2], 16) for x in range(0,6))
      else:
        raise RuntimeError("Expected ethernet address string to be 6 raw "
                           "bytes or some hex")
      self._value = addr
    elif isinstance(addr, EthAddr):
      self._value = addr.toRaw()
    elif isinstance(addr, (list,tuple,bytearray)):
      self._value = bytes(addr)
    elif (hasattr(addr, '__len__') and len(addr) == 6
          and hasattr(addr, '__iter__')):
      # Pretty much same as above case, but for sequences we don't know.
      self._value = bytes(addr)
    elif addr is None:
      self._value = b'\x00' * 6
    else:
      raise RuntimeError("Expected ethernet address to be a string of 6 raw "
                         "bytes or some hex")

  def isBridgeFiltered (self):
    """
    Checks if address is an IEEE 802.1D MAC Bridge Filtered MAC Group Address

    This range is 01-80-C2-00-00-00 to 01-80-C2-00-00-0F. MAC frames that
    have a destination MAC address within this range are not relayed by
    bridges conforming to IEEE 802.1D
    """
    return  ((self._value[0] == 0x01)
         and (self._value[1] == 0x80)
         and (self._value[2] == 0xC2)
         and (self._value[3] == 0x00)
         and (self._value[4] == 0x00)
         and (self._value[5] <= 0x0F))

  @property
  def is_bridge_filtered (self):
    return self.isBridgeFiltered()

  def isGlobal (self):
    """
    Returns True if this is a globally unique (OUI enforced) address.
    """
    return not self.isLocal()

  def isLocal (self):
    """
    Returns True if this is a locally-administered (non-global) address.
    """
    return True if (self._value[0] & 2) else False

  @property
  def is_local (self):
    return self.isLocal()

  @property
  def is_global (self):
    return self.isGlobal()

  def isMulticast (self):
    """
    Returns True if this is a multicast address.
    """
    return True if (self._value[0] & 1) else False

  @property
  def is_multicast (self):
    return self.isMulticast()

  @property
  def is_broadcast (self):
    return self == self.BROADCAST

  def toRaw (self):
    return self.raw

  @property
  def raw (self):
    """
    Returns the address as a 6-long bytes object.
    """
    return self._value

  def toTuple (self):
    return self.to_tuple()

  def to_tuple (self):
    """
    Returns a 6-entry long tuple where each entry is the numeric value
    of the corresponding byte of the address.
    """
    return tuple((x for x in self._value))

  def toStr (self, separator = ':', resolveNames  = False):
    return self.to_str(separator, resolveNames)

  def to_str (self, separator = ':', resolve_names  = False):
    """
    Returns string representation of address

    Usually this is six two-digit hex numbers separated by colons.
    If resolve_names is True, it the first three bytes may be replaced by a
    string corresponding to the OUI.
    """
    if resolve_names and self.is_global:
      # Don't even bother for local (though it should never match and OUI!)
      name = _eth_oui_to_name.get(self._value[:3])
      if name:
        rest = separator.join('%02x' % (x,) for x in self._value[3:])
        return name + separator + rest

    return separator.join(('%02x' % (x,) for x in self._value))

  def __str__ (self):
    return self.toStr()

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return type(self).__name__ + "('" + self.to_str() + "')"

  def __len__ (self):
    return 6

  def __setattr__ (self, a, v):
    if hasattr(self, '_value'):
      raise TypeError("This object is immutable")
    object.__setattr__(self, a, v)


EthAddr.BROADCAST = EthAddr(b"\xff\xff\xff\xff\xff\xff")



class IPAddr (_AddrBase):
  """
  Represents an IPv4 address.

  Internal storage is a signed int in network byte order.
  """
  def __init__ (self, addr, networkOrder = False):
    """
    Initialize using several possible formats

    If addr is an int/long, then it is assumed to be in host byte order
    unless networkOrder = True

    We only handle dotted-quad textual representations.  That is, three dots
    and four numbers.  Oddball representations ("10.1") maybe not so much.
    """

    # Always stores as a signed network-order int
    if isinstance(addr, (bytes, bytearray)):
      if len(addr) != 4:
        # dotted quad
        self._value = struct.unpack('i', socket.inet_aton(addr.decode()))[0]
      else:
        self._value = struct.unpack('i', addr)[0]
    elif isinstance(addr, str):
      self._value = struct.unpack('i', socket.inet_aton(addr))[0]
    elif isinstance(addr, IPAddr):
      self._value = addr._value
    elif isinstance(addr, int):
      addr = addr & 0xffFFffFF # unsigned long
      self._value = struct.unpack("!i",
          struct.pack(('!' if networkOrder else '') + "I", addr))[0]
    else:
      raise RuntimeError("Unexpected IP address format")

  @staticmethod
  def parse_cidr (addr, infer=True, allow_host=False):
    return parse_cidr(addr, infer, allow_host)

  def toSignedN (self):
    """ A shortcut """
    return self.toSigned(networkOrder = True)

  def toUnsignedN (self):
    """ A shortcut """
    return self.toUnsigned(networkOrder = True)

  def toSigned (self, networkOrder = False):
    """ Return the address as a signed int """
    if networkOrder:
      return self._value
    v = socket.htonl(self._value & 0xffFFffFF)
    return struct.unpack("i", struct.pack("I", v))[0]

  def toRaw (self):
    return self.raw

  @property
  def raw (self):
    """
    Returns the address as a four-character byte string.
    """
    return struct.pack("i", self._value)

  def toUnsigned (self, networkOrder = False):
    """
    Returns the address as an integer in either network or host (the
    default) byte order.

    Deprecated.
    """
    if not networkOrder:
      return socket.htonl(self._value & 0xffFFffFF)
    return self._value & 0xffFFffFF

  @property
  def unsigned_h (self):
    """
    The address as an integer in host order.
    """
    return self.toUnsigned(networkOrder=False)

  @property
  def unsigned_n (self):
    """
    The address as an integer in network order.
    """
    return self.toUnsigned(networkOrder=True)

  def toStr (self):
    """ Return dotted quad representation """
    return socket.inet_ntoa(self.toRaw())

  def in_network (self, *args, **kw):
    return self.inNetwork(*args, **kw)

  def inNetwork (self, network, netmask = None):
    """
    Returns True if this network is in the specified network.
    network is a dotted quad (with or without a CIDR or normal style
    netmask, which can also be specified separately via the netmask
    parameter), or it can be a tuple of (address,network-bits) like that
    returned by parse_cidr().
    """
    if type(network) is not tuple:
      if netmask is not None:
        network = str(network)
        network += "/" + str(netmask)
      n,b = parse_cidr(network)
    else:
      n,b = network
      if type(n) is not IPAddr:
        n = IPAddr(n)

    return (self.toUnsigned() & ~((1 << (32-b))-1)) == n.toUnsigned()

  def get_network (self, netmask_or_bits):
    """
    Gets just the network part by applying a mask or prefix length

    Returns (IPAddr,preifx_bits)
    """
    prefix = parse_cidr("255.255.255.255/" + str(netmask_or_bits),
                        allow_host=True)[1]
    netmask = cidr_to_netmask(prefix).unsigned_h
    return (IPAddr(self.unsigned_h & netmask, networkOrder=False),prefix)

  @property
  def is_broadcast (self):
    return self == IP_BROADCAST

  @property
  def is_multicast (self):
    return ((self.toSigned(networkOrder = False) >> 24) & 0xe0) == 0xe0

  @property
  def multicast_ethernet_address (self):
    """
    Returns corresponding multicast EthAddr

    Assumes this is, in fact, a multicast IP address!
    """
    if not self.is_multicast:
      raise RuntimeError("No multicast EthAddr for non-multicast IPAddr!")
    n = self.toUnsigned(networkOrder = False) & 0x7fffff
    return EthAddr("01005e" + ("%06x" % (n)))

  def __str__ (self):
    return self.toStr()

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return self.__class__.__name__ + "('" + self.toStr() + "')"

  def __len__ (self):
    return 4

  def __setattr__ (self, a, v):
    if hasattr(self, '_value'):
      raise TypeError("This object is immutable")
    object.__setattr__(self, a, v)


IP_ANY       = IPAddr("0.0.0.0")
IP_BROADCAST = IPAddr("255.255.255.255")



class IPAddr6 (_AddrBase):
  """
  Represents an IPv6 address.

  Internally stored as 16 raw bytes.
  """
  @classmethod
  def from_raw (cls, raw):
    """
    Factory that creates an IPAddr6 from six raw bytes
    """
    return cls(raw, raw=True)

  @classmethod
  def from_num (cls, num):
    """
    Factory that creates an IPAddr6 from a large integer
    """
    return bytes( (num >> i) & 0xff for i in range(120,-8,-8) )

  def __init__ (self, addr = None, raw = False, network_order = False):
    """
    Construct IPv6 address

    We accept the following as inputs:
    Textual IPv6 representations as a str or unicode (including mixed notation
      with an IPv4-like component)
    Raw IPv6 addresses (128 bits worth of bytearray or, if raw=True, bytes)
    IPAddr (converted to IPv4-mapped IPv6 addresses)
    IPAddr6 (just copied)
    None (creates an "undefined" IPv6 address)
    """
    # When we move to Python 3, we can use bytes to infer raw.  For now, we
    # have the 'raw' argument, which we'll take as either a boolean indicating
    # that addr is raw, or we'll take it as the raw address itself.
    if addr is None and isinstance(raw, (bytes,bytearray)):
      # Allow passing in raw value using either addr=address + raw=True or
      # addr=None + raw=address
      addr = raw
      raw = True

    if addr is None:
      # Should we even allow this?  It's a weird case.
      self._value = self.UNDEFINED._value
    elif isinstance(addr, str) or (isinstance(addr, bytes) and not raw):
      # A textual IPv6 representation
      ip4part = None
      if '.' in addr:
        # It contains a dot, so it is in "mixed notation"
        addr,ip4part = addr.rsplit(':',1)
        if '.' in addr:
          # We don't implement this, which is probably fine because they are
          # deprecated.
          raise RuntimeError('IPv4-compatible representation unimplemented')
        if ':' in ip4part:
          raise RuntimeError('Bad address format')
        addr += ':0:0'

      segs = addr.split(':')
      if addr.count('::') > 1:
        raise RuntimeError("Bad address format " + str(addr))
      if len(segs) < 3 or len(segs) > 8:
        raise RuntimeError("Bad address format " + str(addr))

      # Parse the two "sides" of the address (left and right of the optional
      # dropped section)
      p = ([],[])
      side = 0
      for i,s in enumerate(segs):
        if len(s) == 0:
          #if side != 0:
            #if i != len(segs)-1:
            #  raise RuntimeError("Bad address format " + str(addr))
          side = 1
          continue
        s = int(s,16)
        if s < 0 or s > 0xffff:
          # Each chunk must be at most 16 bits!
          raise RuntimeError("Bad address format " + str(addr))
        p[side].append(s)

      # Add the zeroes (if any) between the sides
      o = p[0] + ([0] * (8-len(p[0])-len(p[1]))) + p[1]

      # Pack into raw format
      v = b''
      for b in o:
        v += struct.pack('!H', b)

      # Append IPv4 part which we chopped off earlier
      if ip4part is not None:
        v = v[:-4] + IPAddr(ip4part).toRaw()

      self._value = v
    elif isinstance(addr, type(self)):
      # Copy constructor
      self._value = addr._value
    elif isinstance(addr, IPAddr):
      # IPv4-mapped
      self._value = IPAddr6("::ffff:0:0:" + str(addr))._value
    elif isinstance(addr, bytearray):
      # Raw value
      if len(addr) != 16: raise ValueError("Raw IPv6 addresses are 16 bytes")
      self._value = bytes(addr)
    elif isinstance(addr, bytes):
      # Raw value
      if len(addr) != 16: raise ValueError("Raw IPv6 addresses are 16 bytes")
      self._value = addr
    else:
      raise RuntimeError("Unexpected IP address format")

  @property
  def raw (self):
    return self._value

  @property
  def ipv4 (self):
    return self.to_ipv4(check_ipv4=False)

  def to_ipv4 (self, check_ipv4 = True):
    """
    Convert to an IPAddr

    This only makes sense if this address is ipv4 mapped/compatible.  By
    default we check that this is the case.
    """
    if check_ipv4:
      if not self.is_ipv4:
        raise RuntimeError('Not an IPv4ish IPv6 address')
    return IPAddr(self._value[-4:])

  @property
  def num (self):
    o = 0
    for b in self._value:
      o = (o << 8) | b
    return o

  @property
  def is_multicast (self):
    return self.in_network('ff00::/8')

  @property
  def is_global_unicast (self):
    return self.in_network('2000::/3')

  @property
  def is_unique_local_unicast (self):
    return self.in_network('fc00::/7')

  @property
  def is_link_unicast (self):
    return self.in_network('fe80::/10')

  @property
  def is_ipv4 (self):
    return self.in_network('::/80')

  @property
  def is_ipv4_compatible (self):
    return self.in_network('::/96')

  @property
  def is_ipv4_mapped (self):
    return self.in_network('::ffff:0:0/96')

  @property
  def is_reserved (self):
    #TODO
    raise RuntimeError("Not implemented")

  @staticmethod
  def netmask_to_cidr (dq):
    """
    Takes a netmask as either an IPAddr or a string, and returns the number
    of network bits.  e.g., 255.255.255.0 -> 24
    Raise exception if subnet mask is not CIDR-compatible.
    """
    if isinstance(dq, str):
      dq = IPAddr6(dq)
    v = dq.num
    c = 0
    while v & (1<<127):
      c += 1
      v <<= 1
    v = v & ((1<<128)-1)
    if v != 0:
      raise RuntimeError("Netmask %s is not CIDR-compatible" % (dq,))
    return c

  @staticmethod
  def cidr_to_netmask (bits):
    """
    Takes a number of network bits, and returns the corresponding netmask
    as an IPAddr6.
    """
    v = (1 << bits) - 1
    v = v << (128-bits)
    return IPAddr6.from_num(v)

  @staticmethod
  def parse_cidr (addr_and_net, allow_host = False):
    """
    Parses addr/netbits or addr/netmask

    Returns (IPAddr6,netbits)
    """
    addr = addr_and_net
    def check (r0, r1):
      a = r0.num
      b = r1
      if (not allow_host) and (a & ((1<<b)-1)):
        raise RuntimeError("Host part of CIDR address is not zero (%s)"
                           % (addr,))
      return (r0,128-r1)
    addr = addr.split('/', 2)
    if len(addr) == 1:
      return check(IPAddr6(addr[0]), 0)
    try:
      wild = 128-int(addr[1])
    except:
      # Maybe they passed a netmask
      m = IPAddr6(addr[1]).num
      b = 0
      while m & (1<<127):
        b += 1
        m <<= 1
      if m & ((1<<127)-1) != 0:
        raise RuntimeError("Netmask " + str(addr[1])
                           + " is not CIDR-compatible")
      wild = 128-b
      assert wild >= 0 and wild <= 128
      return check(IPAddr6(addr[0]), wild)
    assert wild >= 0 and wild <= 128
    return check(IPAddr6(addr[0]), wild)

  def in_network (self, network, netmask = None):
    """
    Returns True if this address is in the specified network.

    network can be specified as:
    IPAddr6 with numeric netbits or netmask in netmask parameter
    textual network with numeric netbits or netmask in netmask parameter
    textual network with netbits or netmask separated by a slash
    tuple of textual address and numeric netbits
    tuple of IPAddr6 and numeric netbits
    """
    if type(network) is not tuple:
      if netmask is not None:
        network = str(network) + "/" + str(netmask)
      n,b = self.parse_cidr(network)
    else:
      n,b = network
      if type(n) is not IPAddr6:
        n = IPAddr6(n)

    return (self.num & ~((1 << (128-b))-1)) == n.num

  def to_str (self, zero_drop = True, section_drop = True, ipv4 = None):
    """
    Creates string representation of address

    There are many ways to represent IPv6 addresses.  You get some options.
    zero_drop and section_drop allow for creating minimized representations.
    ipv4 controls whether we print a "mixed notation" representation.  By
    default, we do this only for IPv4-mapped addresses.  You can stop this by
    passing ipv4=False.  You can also force mixed notation representation
    by passing ipv4=True; this probably only makes sense if .is_ipv4_compatible
    (or .is_ipv4_mapped, of course).
    """
    o = [lo | (hi<<8) for hi,lo in
         (self._value[i:i+2] for i in range(0,16,2))]

    if (ipv4 is None and self.is_ipv4_mapped) or ipv4:
      ip4part = o[-2:]
      o[-2:] = [1,1]
      def finalize (s):
        s = s.rsplit(':',2)[0]
        return s + ":" + str(IPAddr(self.raw[-4:]))
    else:
      def finalize (s):
        return s

    if zero_drop:
      def fmt (n):
        return ':'.join('%x' % (b,) for b in n)
    else:
      def fmt (n):
        return ':'.join('%04x' % (b,) for b in n)

    if section_drop:
      z = [] # [length,pos] of zero run
      run = None
      for i,b in enumerate(o):
        if b == 0:
          if run is None:
            run = [1,i]
            z.append(run)
          else:
            run[0] += 1
        else:
          run = None

      if len(z):
        # Sloppy!
        max_len = max([length for length,pos in z])
        if max_len > 1:
          z = [pos for length,pos in z if length == max_len]
          z.sort()
          pos = z[0]
          return finalize('::'.join((fmt(o[:pos]),fmt(o[pos+max_len:]))))

    return finalize(fmt(o))

  def __str__ (self):
    return self.to_str()

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return type(self).__name__ + "('" + self.to_str() + "')"

  def __len__ (self):
    return 16

  def __setattr__ (self, a, v):
    if hasattr(self, '_value'):
      raise TypeError("This object is immutable")
    object.__setattr__(self, a, v)

  def set_mac (self, eth):
    e = list(EthAddr(eth).toTuple())
    e[0] ^= 2
    e[3:3] = [0xff,0xfe]
    e = bytes(e)
    return IPAddr6.from_raw(self._value[:8]+e)


IPAddr6.UNDEFINED = IPAddr6('::')
IPAddr6.ALL_NODES_LINK_LOCAL = IPAddr6('ff02::1')
IPAddr6.ALL_ROUTERS_LINK_LOCAL = IPAddr6('ff02::2')
IPAddr6.ALL_NODES_INTERFACE_LOCAL = IPAddr6('ff01::1')
IPAddr6.ALL_ROUTERS_INTERFACE_LOCAL = IPAddr6('ff01::2')
#ff02::1:3 link local multicast name resolution
#ff02::1:ff00:0/104 solicited-node
#ff02::2:ff00:0/104 node information query



def netmask_to_cidr (dq):
  """
  Takes a netmask as either an IPAddr or a string, and returns the number
  of network bits.  e.g., 255.255.255.0 -> 24
  Raise exception if subnet mask is not CIDR-compatible.
  """
  if isinstance(dq, str):
    dq = IPAddr(dq)
  v = dq.toUnsigned(networkOrder=False)
  c = 0
  while v & 0x80000000:
    c += 1
    v <<= 1
  v = v & 0xffFFffFF
  if v != 0:
    raise RuntimeError("Netmask %s is not CIDR-compatible" % (dq,))
  return c


def cidr_to_netmask (bits):
  """
  Takes a number of network bits, and returns the corresponding netmask
  as an IPAddr.  e.g., 24 -> 255.255.255.0
  """
  v = (1 << bits) - 1
  v = v << (32-bits)
  return IPAddr(v, networkOrder = False)


def parse_cidr (addr, infer=True, allow_host=False):
  """
  Takes a CIDR address or plain dotted-quad, and returns a tuple of address
  and count-of-network-bits.
  Can infer the network bits based on network classes if infer=True.
  Can also take a string in the form 'address/netmask', as long as the
  netmask is representable in CIDR.

  FIXME: This function is badly named.
  """
  def check (r0, r1):
    a = r0.toUnsigned()
    b = r1
    if (not allow_host) and (a & ((1<<b)-1)):
      raise RuntimeError("Host part of CIDR address is not zero (%s)"
                         % (addr,))
    return (r0,32-r1)
  addr = addr.split('/', 2)
  if len(addr) == 1:
    if infer is False:
      return check(IPAddr(addr[0]), 0)
    addr = IPAddr(addr[0])
    b = 32-infer_netmask(addr)
    m = (1<<b)-1
    if (addr.toUnsigned() & m) == 0:
      # All bits in wildcarded part are 0, so we'll use the wildcard
      return check(addr, b)
    else:
      # Some bits in the wildcarded part are set, so we'll assume it's a host
      return check(addr, 0)
  try:
    wild = 32-int(addr[1])
  except:
    # Maybe they passed a netmask
    m = IPAddr(addr[1]).toUnsigned()
    b = 0
    while m & (1<<31):
      b += 1
      m <<= 1
    if m & 0x7fffffff != 0:
      raise RuntimeError("Netmask " + str(addr[1]) + " is not CIDR-compatible")
    wild = 32-b
    assert wild >= 0 and wild <= 32
    return check(IPAddr(addr[0]), wild)
  assert wild >= 0 and wild <= 32
  return check(IPAddr(addr[0]), wild)


def infer_netmask (addr):
  """
  Uses network classes to guess the number of network bits
  """
  addr = addr.toUnsigned()
  if addr == 0:
    # Special case -- default network
    return 32-32 # all bits wildcarded
  if (addr & (1 << 31)) == 0:
    # Class A
    return 32-24
  if (addr & (3 << 30)) == 2 << 30:
    # Class B
    return 32-16
  if (addr & (7 << 29)) == 6 << 29:
    # Class C
    return 32-8
  if (addr & (15 << 28)) == 14 << 28:
    # Class D (Multicast)
    return 32-0 # exact match
  # Must be a Class E (Experimental)
  return 32-0
