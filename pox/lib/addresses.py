import struct
import socket

# Untested attempt at Python 3 friendliness
if not hasattr(globals()['__builtins__'], 'long'):
  long = int

class EthAddr (object):
  def __init__ (self, addr):

    # Always stores as a 6 character string

    if isinstance(addr, str):
      if len(addr) == 17 or len(addr) == 12:
        # hex
        if len(addr) == 17:
          if addr[2::3] != ':::::' and addr[2::3] != '-----':
            raise RuntimeError("Bad format for ethernet address")
          addr = ''.join((addr[x*3:x*3+2] for x in xrange(0,6)))
        addr = ''.join((chr(int(addr[x*2:x*2+2], 16)) for x in range(0,6)))
      elif len(addr) == 6:
        # raw
        pass
      else:
        raise RuntimeError("Expected ethernet address string to be 6 raw bytes or some hex")
      self._value = addr
    elif isinstance(addr, EthAddr):
      self._value = addr.toRaw()
    elif type(addr) == list or (hasattr(addr, '__len__') and len(addr) == 6 and hasattr(addr, '__iter__')):
      self._value = ''.join( (chr(x) for x in addr) )
    else:
      raise RuntimeError("Expected ethernet address to be a string of 6 raw bytes or some hex")
    #elif isinstance(addr, int) or isinstance(addr, long):
    #  addr = long(addr)

  def toRaw (self):
    return self._value

  #def toInt (self):

  def toTuple (self):
    return tuple((ord(x) for x in self._value))

  def toStr (self, separator = ':'): #TODO: show OUI info from packet lib
    def h (n):
      if n <= 0xf:
        return "0" + hex(n)[2:]
      return hex(n)[2:]
    return separator.join((h(ord(x)) for x in self._value))

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    try:
      if not isinstance(other, EthAddr):
        other = EthAddr(other)
      return self._value.__cmp__(other._value)
    except:
      return -other.__cmp__(self)

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return self.__class__.__name__ + "('" + self.toStr() + "')"

class IPAddr (object):
  def __init__ (self, addr, networkOrder = False):
    """ Can be initialized with several formats.
        If addr is an int/long, then it is assumed to be in host byte order
        unless networkOrder = True
    """

    # Always stores as a signed network-order int
    if isinstance(addr, str):
      if len(addr) != 4:
        # dotted quad
        self._value = struct.unpack('!i', socket.inet_aton(addr))[0]
      else:
        self._value = struct.unpack('!i', addr)[0]
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
    return self.toUnigned(networkOrder = True)

  def toSigned (self, networkOrder = False):
    """ Return the address as a signed int """
    if not networkOrder:
      v = socket.htonl(self._value & 0xffFFffFF)
      return struct.unpack("!i", struct.pack("!I", v))[0]
    return self._value

  def toRaw (self):
    return struct.pack("!i", self._value)

  def toUnsigned (self, networkOrder = False):
    if not networkOrder:
      return socket.htonl(self._value & 0xffFFffFF)
    return self._value & 0xffFFffFF

  def toStr (self):
    """ Return dotted quad representation """
    return socket.inet_ntoa(self.toRaw())

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    try:
      if not isinstance(other, IPAddr):
        other = IPAddr(other)
      return self._value.__cmp__(other._value)
    except:
      return -other.__cmp__(self)

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return self.__class__.__name__ + "('" + self.toStr() + "')"

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

  code.interact(local={'a' : a})