# Copyright 2011,2012,2013 James McCauley
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

# Slightly tested attempt at Python 3 friendliness
import sys
if 'long' not in sys.modules['__builtin__'].__dict__:
  long = int


"""
# Unfinished oui name stuff formerly from packet library.

    oui = int(a[0]) << 16 | int(a[1]) << 8 | int(a[2])

    # check if globally unique
    if resolve_name and not (a[0] & 0x2):
        if _ethoui2name.has_key(oui):
            return "(%s):%02x:%02x:%02x" %( _ethoui2name[oui], a[3],a[4],a[5])
"""
_eth_oui_to_name = {}

def _load_oui_names ():
    import inspect
    import os.path
    filename = os.path.join(os.path.dirname(inspect.stack()[0][1]), 'oui.txt')
    f = None
    try:
        f = open(filename)
        for line in f.readlines():
            if len(line) < 1:
                continue
            if line[0].isspace():
                continue
            split = line.split(' ')
            if not '-' in split[0]:
                continue
            # grab 3-byte OUI
            oui_str  = split[0].replace('-','')
            # strip off (hex) identifer and keep rest of name
            end = ' '.join(split[1:]).strip()
            end = end.split('\t')
            end.remove('(hex)')
            oui_name = ' '.join(end)
            # convert oui to int
            oui = int(oui_str, 16)
            _eth_oui_to_name[oui] = oui_name.strip()
    except:
        import logging
        logging.getLogger().warn("Could not load OUI list")
    if f: f.close()
_load_oui_names()


class EthAddr (object):
  """
  An Ethernet (MAC) address type.
  """
  def __init__ (self, addr):
    """
    Understands Ethernet address is various forms.  Hex strings, raw byte
    strings, etc.
    """
    # Always stores as a 6 character string
    if isinstance(addr, bytes) or isinstance(addr, basestring):
      if len(addr) == 6:
        # raw
        pass
      elif len(addr) == 17 or len(addr) == 12 or addr.count(':') == 5:
        # hex
        if len(addr) == 17:
          if addr[2::3] != ':::::' and addr[2::3] != '-----':
            raise RuntimeError("Bad format for ethernet address")
          # Address of form xx:xx:xx:xx:xx:xx
          # Pick out the hex digits only
          addr = ''.join((addr[x*3:x*3+2] for x in xrange(0,6)))
        elif len(addr) == 12:
          pass
        else:
          # Assume it's hex digits but they may not all be in two-digit
          # groupings (e.g., xx:x:x:xx:x:x). This actually comes up.
          addr = ''.join(["%02x" % (int(x,16),) for x in addr.split(":")])
        # We should now have 12 hex digits (xxxxxxxxxxxx).
        # Convert to 6 raw bytes.
        addr = b''.join((chr(int(addr[x*2:x*2+2], 16)) for x in range(0,6)))
      else:
        raise RuntimeError("Expected ethernet address string to be 6 raw "
                           "bytes or some hex")
      self._value = addr
    elif isinstance(addr, EthAddr):
      self._value = addr.toRaw()
    elif type(addr) == list or (hasattr(addr, '__len__') and len(addr) == 6
          and hasattr(addr, '__iter__')):
      self._value = b''.join( (chr(x) for x in addr) )
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
    return  ((ord(self._value[0]) == 0x01)
    	and (ord(self._value[1]) == 0x80)
    	and (ord(self._value[2]) == 0xC2)
    	and (ord(self._value[3]) == 0x00)
    	and (ord(self._value[4]) == 0x00)
    	and (ord(self._value[5]) <= 0x0F))

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
    return True if (ord(self._value[0]) & 2) else False

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
    return True if (ord(self._value[0]) & 1) else False

  @property
  def is_multicast (self):
    return self.isMulticast()

  def toRaw (self):
    return self.raw

  @property
  def raw (self):
    """
    Returns the address as a 6-long bytes object.
    """
    return self._value

  def toTuple (self):
    """
    Returns a 6-entry long tuple where each entry is the numeric value
    of the corresponding byte of the address.
    """
    return tuple((ord(x) for x in self._value))

  def toStr (self, separator = ':', resolveNames  = False):
    """
    Returns the address as string consisting of 12 hex chars separated
    by separator.
    If resolveNames is True, it may return company names based on
    the OUI. (Currently unimplemented)
    """
    #TODO: show OUI info from packet lib ?
    return separator.join(('%02x' % (ord(x),) for x in self._value))

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    #TODO: Revisit this and other __cmp__ in Python 3.4
    try:
      if type(other) == EthAddr:
        other = other._value
      elif type(other) == bytes:
        pass
      else:
        other = EthAddr(other)._value
      return cmp(self._value, other)
    except:
      return -cmp(other, self)

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return self.__class__.__name__ + "('" + self.toStr() + "')"

  def __len__ (self):
    return 6

  def __setattr__ (self, a, v):
    if hasattr(self, '_value'):
      raise TypeError("This object is immutable")
    object.__setattr__(self, a, v)


class IPAddr (object):
  """
  Represents an IPv4 address.
  """
  def __init__ (self, addr, networkOrder = False):
    """
    Initialize using several possible formats

    If addr is an int/long, then it is assumed to be in host byte order
    unless networkOrder = True
    Stored in network byte order as a signed int
    """

    # Always stores as a signed network-order int
    if isinstance(addr, basestring) or isinstance(addr, bytes):
      if len(addr) != 4:
        # dotted quad
        self._value = struct.unpack('i', socket.inet_aton(addr))[0]
      else:
        self._value = struct.unpack('i', addr)[0]
    elif isinstance(addr, IPAddr):
      self._value = addr._value
    elif isinstance(addr, int) or isinstance(addr, long):
      addr = addr & 0xffFFffFF # unsigned long
      self._value = struct.unpack("!i",
          struct.pack(('!' if networkOrder else '') + "I", addr))[0]
    else:
      raise RuntimeError("Unexpected IP address format")

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
    """
    if not networkOrder:
      return socket.htonl(self._value & 0xffFFffFF)
    return self._value & 0xffFFffFF

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

  def __cmp__ (self, other):
    if other is None: return 1
    try:
      if not isinstance(other, IPAddr):
        other = IPAddr(other)
      return cmp(self.toUnsigned(), other.toUnsigned())
    except:
      return -other.__cmp__(self)

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


class IPAddr6 (object):
  """
  Represents an IPv6 address.
  """
  @classmethod
  def from_raw (cls, raw):
    return cls(raw, raw=True)

  @classmethod
  def from_num (cls, num):
    o = b''
    for i in xrange(16):
      o = chr(num & 0xff) + o
      num >>= 8
    return cls.from_raw(o)

  def __init__ (self, addr = None, raw = False, network_order = False):
    # When we move to Python 3, we can use bytes to infer raw.
    if addr is None and isinstance(raw, (bytes,bytearray)):
      addr = raw
      raw = True
    if addr is None:
      return self.UNDEFINED
    if isinstance(addr, unicode) or (isinstance(addr, bytes) and not raw):
      ip4part = None
      if '.' in addr:
        addr,ip4part = addr.rsplit(':',1)
        if '.' in addr:
          raise RuntimeError('IPv4-compatible representation unimplemented')
        if ':' in ip4part:
          raise RuntimeError('Bad address format')
        addr += ':0:0'

      segs = addr.split(':')
      if addr.count('::') > 1:
        raise RuntimeError("Bad address format " + str(addr))
      if len(segs) < 3 or len(segs) > 8:
        raise RuntimeError("Bad address format " + str(addr))

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
          raise RuntimeError("Bad address format " + str(addr))
        p[side].append(s)

      o = p[0] + ([0] * (8-len(p[0])-len(p[1]))) + p[1]

      v = b''
      for b in o:
        v += struct.pack('!H', b)

      if ip4part is not None:
        v = v[:-4] + IPAddr(ip4part).toRaw()

      self._value = v
    elif isinstance(addr, type(self)):
      self._value = addr._value
    elif isinstance(addr, IPAddr):
      #FIXME: This is hacky.
      self._value = IPAddr6("::ffff:0:0:" + str(addr))
    elif isinstance(addr, bytearray):
      self._value = bytes(addr)
    elif isinstance(addr, bytes):
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
    Only makes sense if this address is ipv4 mapped/compatible
    """
    if check_ipv4:
      if not self.is_ipv4:
        raise RuntimeError('Not an IPv4ish IPv6 address')
    return IPAddr(self._value[-4:])

  @property
  def num (self):
    o = 0
    for b in self._value:
      o = (o << 8) | ord(b)
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
    if isinstance(dq, basestring):
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

    o = [ord(lo) | (ord(hi)<<8) for hi,lo in
         (self._value[i:i+2] for i in xrange(0,16,2))]

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

  def __cmp__ (self, other):
    if other is None: return 1
    try:
      if not isinstance(other, type(self)):
        other = type(self)(other)
      return cmp(self._value, other._value)
    except:
      return -cmp(other,self)

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
    e = ''.join(chr(b) for b in e)
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
  if isinstance(dq, basestring):
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


IP_ANY = IPAddr("0.0.0.0")
IP_BROADCAST = IPAddr("255.255.255.255")


if __name__ == '__main__':
  # A couple sanity checks
  #TODO: move to tests
  import code
  a = IPAddr('255.0.0.1')
  for v in [('255.0.0.1',True), (0xff000001, True), (0x010000ff, False)]:
    print("== " + str(v) + " =======================")
    a = IPAddr(v[0],v[1])
    print(a._value,-16777215)
    #print(hex(a._value),'ff000001')
    print(str(a),'255.0.0.1')
    print(hex(a.toUnsigned()),'010000ff')
    print(hex(a.toUnsigned(networkOrder=True)),'ff000001')
    print(a.toSigned(),16777471)
    print(a.toSigned(networkOrder=True),-16777215)
    print("----")
    print([parse_cidr(x)[1]==24 for x in
           ["192.168.101.0","192.168.102.0/24","1.1.168.103/255.255.255.0"]])
  code.interact(local=locals())
