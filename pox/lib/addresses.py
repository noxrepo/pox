# Copyright 2011 James McCauley
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

"""
Classes for addresses of various types.
"""

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
    strings, long integers, etc.
    """
    # Always stores as a 6 character string
    if isinstance(addr, int) or isinstance(addr, long):
      addr = long(addr)
      # Store the long as an array of 6 bytes
      # Struct puts the least significant byte at [0] though!
      # And Murphy puts the least significant byte at [-1]
      # So we pack ourselves one byte at a time
      val = []
      for _ in range(6):
        # This may not be machine-independent...
        val.insert(0, struct.pack("B", (addr & 0xFF)))
        addr >>= 8
      self._value = ''.join(val)
    elif isinstance(addr, bytes) or isinstance(addr, unicode):
      if len(addr) == 17 or len(addr) == 12 or addr.count(':') == 5:
        # hex
        if len(addr) == 17:
          if addr[2::3] != ':::::' and addr[2::3] != '-----':
            raise RuntimeError("Bad format for ethernet address")
          # TODOC: I have no clue what this is doing
          addr = ''.join((addr[x*3:x*3+2] for x in xrange(0,6)))
        elif len(addr) == 12:
          pass
        else:
          addr = ''.join(["%02x" % (int(x,16),) for x in addr.split(":")])
        # TODOC: I have no clue what this is doing
        addr = b''.join((chr(int(addr[x*2:x*2+2], 16)) for x in range(0,6)))
      elif len(addr) == 6:
        # raw
        pass
      else:
        raise RuntimeError("Expected ethernet address string to be 6 raw bytes or some hex")
      self._value = addr
    elif isinstance(addr, EthAddr):
      self._value = addr.toRaw()
    elif type(addr) == list or (hasattr(addr, '__len__') and len(addr) == 6 and hasattr(addr, '__iter__')):
      self._value = b''.join( (chr(x) for x in addr) )
    elif addr is None:
      self._value = b'\x00' * 6
    else:
      raise RuntimeError("Expected ethernet address to be a string of 6 raw bytes or some hex")

  def isBridgeFiltered (self):
    """
    Returns True if this is IEEE 802.1D MAC Bridge Filtered MAC Group Address,
    01-80-C2-00-00-00 to 01-80-C2-00-00-0F. MAC frames that have a destination MAC address
    within this range are not relayed by MAC bridges conforming to IEEE 802.1D
    """
    return  ((ord(self._value[0]) == 0x01)
    	and (ord(self._value[1]) == 0x80)
    	and (ord(self._value[2]) == 0xC2)
    	and (ord(self._value[3]) == 0x00)
    	and (ord(self._value[4]) == 0x00)
    	and (ord(self._value[5]) <= 0x0F))

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
    """
    Returns the address as a 6-long bytes object.
    """
    return self._value

  def toInt (self):
    '''
    Returns the address as an (unsigned) integer
    '''
    value = 0
    # Struct puts the least significant (bit|byte) leftmost, 
    # but Murphy puts least significant (bit|byte) rightmost
    # So we unpack ourselves, one byte at a time
    # most-significant byte is leftmost (self._value[0])
    for i in range(len(self._value)):
      byte_shift = 5-i
      byte = self._value[i]
      byte_value = struct.unpack("B", byte)[0]
      value += (byte_value << (8*byte_shift))
    return value

  def toTuple (self):
    """
    Returns a 6-entry long tuple where each entry is the numeric value
    of the corresponding byte of the address.
    """
    return tuple((ord(x) for x in self._value))

  def toStr (self, separator = ':', resolveNames  = False): #TODO: show OUI info from packet lib
    """
    Returns the address as string consisting of 12 hex chars separated
    by separator.
    If resolveNames is True, it may return company names based on
    the OUI. (Currently unimplemented)
    """
    return separator.join(('%02x' % (ord(x),) for x in self._value))

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    try:
      if type(other) == EthAddr:
        other = other._value
      elif type(other) == bytes:
        pass
      else:
        other = EthAddr(other)._value
      if self._value == other:
        return 0
      if self._value < other:
        return -1
      if self._value > other:
        return -1
      raise RuntimeError("Objects can not be compared?")
    except:
      return -other.__cmp__(self)

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
    """ Can be initialized with several formats.
        If addr is an int/long, then it is assumed to be in host byte order
        unless networkOrder = True
        Stored in network byte order as a signed int
    """

    # Always stores as a signed network-order int
    if isinstance(addr, str) or isinstance(addr, bytes):
      if len(addr) != 4:
        # dotted quad
        self._value = struct.unpack('i', socket.inet_aton(addr))[0]
      else:
        self._value = struct.unpack('i', addr)[0]
    elif isinstance(addr, IPAddr):
      self._value = addr._value
    elif isinstance(addr, int) or isinstance(addr, long):
      addr = addr & 0xffFFffFF # unsigned long
      self._value = struct.unpack("!i", struct.pack(('!' if networkOrder else '') + "I", addr))[0]
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

  def inNetwork (self, network, netmask = None):
    """
    Returns True if this network is in the specified network.
    network is a dotted quad (with or without a CIDR or normal style
    netmask, which can also be specified separately via the netmask parameter),
    or it can be a tuple of (address,wild-bits) like that returned by
    parseCIDR().
    """
    if type(network) is not tuple:
      if netmask is not None:
        network += "/" + str(netmask)
      n,b = parseCIDR(network)
    else:
      n,b = network
      if type(n) is not IPAddr:
        n = IPAddr(n)

    return (self.toUnsigned() & ~((1 << b)-1)) == n.toUnsigned()

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    if other is None: return 1
    try:
      if not isinstance(other, IPAddr):
        other = IPAddr(other)
      return cmp(self._value, other._value)
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



def parseCIDR (addr, infer=True):
  """
  Takes a CIDR address or plain dotted-quad, and returns a tuple of address
  and wildcard bits (suitable for a flow_mod).
  Can infer the wildcard bits based on network classes if infer=True.
  Can also take a string in the form 'address/netmask', as long as the
  netmask is representable in CIDR.
  """
  def check (r0, r1):
    a = r0.toUnsigned()
    b = r1
    if a & ((1<<b)-1):
      raise RuntimeError("Host part of CIDR address not compatible with " +
                         "network part")
    return (r0,r1)
  addr = addr.split('/', 2)
  if len(addr) == 1:
    if infer is False:
      return (IPAddr(addr[0]), 0)
    addr = IPAddr(addr[0])
    b = inferNetMask(addr)
    m = (1<<b)-1
    if (addr.toUnsigned() & m) == 0:
      # All bits in wildcarded part are 0, so we'll use the wildcard
      return check(addr, b)
    else:
      # Some bits in the wildcarded part were set, so we'll assume it was a host
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

def inferNetMask (addr):
  """
  Uses network classes to guess the number of wildcard bits, and returns
  that number in flow_mod-friendly format.
  """
  addr = addr.toUnsigned()
  if addr == 0:
    # Special case -- default network
    return 32 # all bits wildcarded
  if (addr & (1 << 31)) == 0:
    # Class A
    return 24
  if (addr & (3 << 30)) == 2 << 30:
    # Class B
    return 16
  if (addr & (7 << 29)) == 6 << 29:
    # Class C
    return 8
  if (addr & (15 << 28)) == 14 << 28:
    # Class D (Multicast)
    return 0 # exact match
  # Must be a Class E (Experimental)
    return 0

IP_ANY = IPAddr("0.0.0.0")
IP_BROADCAST = IPAddr("255.255.25.255")


if __name__ == '__main__':
  # A couple sanity checks
  import code
  a = IPAddr('255.0.0.1')
  for v in [('255.0.0.1',True), (0xff000001, True), (0x010000ff, False)]:
    print "== " + str(v) + " ======================="
    a = IPAddr(v[0],v[1])
    print a._value,-16777215
    #print hex(a._value),'ff000001'
    print str(a),'255.0.0.1'
    print hex(a.toUnsigned()),'010000ff'
    print hex(a.toUnsigned(networkOrder=True)),'ff000001'
    print a.toSigned(),16777471
    print a.toSigned(networkOrder=True),-16777215
    print "----"
    #print [parseCIDR(x)[1]==8 for x in
    #       ["192.168.101.0","192.168.102.0/24","1.1.168.103/255.255.255.0"]]
  code.interact(local=locals())

