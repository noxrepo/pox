import struct

def _initHelper (obj, kw):
  for k,v in kw:
    if not hasattr(obj, k):
      if k == 'xid' and hasattr(obj, 'header'): # Special case
        obj.header.xid = v
        continue
      raise TypeError(obj.__class__.__name__ + " constructor got "
        + "unexpected keyword argument '" + k + "'")
    setattr(obj, k, v)
    
# Structure definitions

#1. Openflow Header
class ofp_header:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.version = OFP_VERSION
        self.type = 0
        self.length = 0
        self.xid = 0

    def __assert(self):
        """Sanity check
        """
        if (not (self.type in ofp_type_map.keys())):
            return (False, "type must have values from ofp_type_map.keys()")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!BBHL", self.version, self.type, self.length, self.xid)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.version, self.type, self.length, self.xid) = struct.unpack_from("!BBHL", binaryString, 0)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.version !=  other.version: return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.xid !=  other.xid: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'version: ' + str(self.version) + '\n'
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'length: ' + str(self.length) + '\n'
        outstr += prefix + 'xid: ' + str(self.xid) + '\n'
        return outstr

#2. Common Structures
##2.1 Port Structures
class ofp_phy_port:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.port_no = 0
        self.hw_addr= [0,0,0,0,0,0]
        self.name= ""
        self.config = 0
        self.state = 0
        self.curr = 0
        self.advertised = 0
        self.supported = 0
        self.peer = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.hw_addr, list)):
            return (False, "self.hw_addr is not list as expected.")
        if(len(self.hw_addr) != 6):
            return (False, "self.hw_addr is not of size 6 as expected.")
        if(not isinstance(self.name, str)):
            return (False, "self.name is not string as expected.")
        if(len(self.name) > 16):
            return (False, "self.name is not of size 16 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!H", self.port_no)
        packed += struct.pack("!BBBBBB", self.hw_addr[0], self.hw_addr[1], self.hw_addr[2], self.hw_addr[3], self.hw_addr[4], self.hw_addr[5])
        packed += self.name.ljust(16,'\0')
        packed += struct.pack("!LLLLLL", self.config, self.state, self.curr, self.advertised, self.supported, self.peer)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 48):
            return binaryString
        (self.port_no,) = struct.unpack_from("!H", binaryString, 0)
        (self.hw_addr[0], self.hw_addr[1], self.hw_addr[2], self.hw_addr[3], self.hw_addr[4], self.hw_addr[5]) = struct.unpack_from("!BBBBBB", binaryString, 2)
        self.name = binaryString[8:24].replace("\0","")
        (self.config, self.state, self.curr, self.advertised, self.supported, self.peer) = struct.unpack_from("!LLLLLL", binaryString, 24)
        return binaryString[48:]

    def __len__(self):
        """Return length of message
        """
        l = 48
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.port_no !=  other.port_no: return False
        if self.hw_addr !=  other.hw_addr: return False
        if self.name !=  other.name: return False
        if self.config !=  other.config: return False
        if self.state !=  other.state: return False
        if self.curr !=  other.curr: return False
        if self.advertised !=  other.advertised: return False
        if self.supported !=  other.supported: return False
        if self.peer !=  other.peer: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'port_no: ' + str(self.port_no) + '\n'
        outstr += prefix + 'hw_addr: ' + str(self.hw_addr) + '\n'
        outstr += prefix + 'name: ' + str(self.name) + '\n'
        outstr += prefix + 'config: ' + str(self.config) + '\n'
        outstr += prefix + 'state: ' + str(self.state) + '\n'
        outstr += prefix + 'curr: ' + str(self.curr) + '\n'
        outstr += prefix + 'advertised: ' + str(self.advertised) + '\n'
        outstr += prefix + 'supported: ' + str(self.supported) + '\n'
        outstr += prefix + 'peer: ' + str(self.peer) + '\n'
        return outstr

ofp_port_config = ['OFPPC_PORT_DOWN', 'OFPPC_NO_STP', 'OFPPC_NO_RECV', \
                   'OFPPC_NO_RECV_STP', 'OFPPC_NO_FLOOD', 'OFPPC_NO_FWD', \
                   'OFPPC_NO_PACKET_IN']
OFPPC_PORT_DOWN                     = 1
OFPPC_NO_STP                        = 2
OFPPC_NO_RECV                       = 4
OFPPC_NO_RECV_STP                   = 8
OFPPC_NO_FLOOD                      = 16
OFPPC_NO_FWD                        = 32
OFPPC_NO_PACKET_IN                  = 64
ofp_port_config_map = {
    1                               : 'OFPPC_PORT_DOWN',
    2                               : 'OFPPC_NO_STP',
    4                               : 'OFPPC_NO_RECV',
    8                               : 'OFPPC_NO_RECV_STP',
    16                              : 'OFPPC_NO_FLOOD',
    32                              : 'OFPPC_NO_FWD',
    64                              : 'OFPPC_NO_PACKET_IN'
}

ofp_port_state = ['OFPPS_LINK_DOWN', 'OFPPS_STP_LISTEN', 'OFPPS_STP_LEARN', \
                  'OFPPS_STP_FORWARD', 'OFPPS_STP_BLOCK', 'OFPPS_STP_MASK']
OFPPS_LINK_DOWN                     = 1
OFPPS_STP_LISTEN                    = 0
OFPPS_STP_LEARN                     = 256
OFPPS_STP_FORWARD                   = 512
OFPPS_STP_BLOCK                     = 768
OFPPS_STP_MASK                      = 768
ofp_port_state_map = {
    1                               : 'OFPPS_LINK_DOWN',
    0                               : 'OFPPS_STP_LISTEN',
    256                             : 'OFPPS_STP_LEARN',
    512                             : 'OFPPS_STP_FORWARD',
    768                             : 'OFPPS_STP_BLOCK',
    768                             : 'OFPPS_STP_MASK'
}

ofp_port_features = ['OFPPF_10MB_HD', 'OFPPF_10MB_FD', 'OFPPF_100MB_HD', \
                     'OFPPF_100MB_FD', 'OFPPF_1GB_HD', 'OFPPF_1GB_FD', \
                     'OFPPF_10GB_FD', 'OFPPF_COPPER', 'OFPPF_FIBER', \
                     'OFPPF_AUTONEG', 'OFPPF_PAUSE', 'OFPPF_PAUSE_ASYM']
OFPPF_10MB_HD                       = 1
OFPPF_10MB_FD                       = 2
OFPPF_100MB_HD                      = 4
OFPPF_100MB_FD                      = 8
OFPPF_1GB_HD                        = 16
OFPPF_1GB_FD                        = 32
OFPPF_10GB_FD                       = 64
OFPPF_COPPER                        = 128
OFPPF_FIBER                         = 256
OFPPF_AUTONEG                       = 512
OFPPF_PAUSE                         = 1024
OFPPF_PAUSE_ASYM                    = 2048
ofp_port_features_map = {
    1                               : 'OFPPF_10MB_HD',
    2                               : 'OFPPF_10MB_FD',
    4                               : 'OFPPF_100MB_HD',
    8                               : 'OFPPF_100MB_FD',
    16                              : 'OFPPF_1GB_HD',
    32                              : 'OFPPF_1GB_FD',
    64                              : 'OFPPF_10GB_FD',
    128                             : 'OFPPF_COPPER',
    256                             : 'OFPPF_FIBER',
    512                             : 'OFPPF_AUTONEG',
    1024                            : 'OFPPF_PAUSE',
    2048                            : 'OFPPF_PAUSE_ASYM'
}

##2.2 Queue Structures
class ofp_packet_queue:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.queue_id = 0
        self.length = 0
        self.pad= [0,0]
        self.properties= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 2):
            return (False, "self.pad is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!LH", self.queue_id, self.length)
        packed += struct.pack("!BB", self.pad[0], self.pad[1])
        for i in self.properties:
            packed += i.pack(assertstruct)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.queue_id, self.length) = struct.unpack_from("!LH", binaryString, 0)
        (self.pad[0], self.pad[1]) = struct.unpack_from("!BB", binaryString, 6)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        for i in self.properties:
            l += i.length()
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.queue_id !=  other.queue_id: return False
        if self.length !=  other.length: return False
        if self.pad !=  other.pad: return False
        if self.properties !=  other.properties: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'queue_id: ' + str(self.queue_id) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'properties: \n'
        for obj in self.properties:
            outstr += obj.show(prefix + '  ')
        return outstr

ofp_queue_properties = ['OFPQT_NONE', 'OFPQT_MIN_RATE']
OFPQT_NONE                          = 0
OFPQT_MIN_RATE                      = 0
ofp_queue_properties_map = {
    0                               : 'OFPQT_NONE',
    0                               : 'OFPQT_MIN_RATE'
}

class ofp_queue_prop_header:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.property = 0
        self.length = 0
        self.pad= [0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 4):
            return (False, "self.pad is not of size 4 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HH", self.property, self.length)
        packed += struct.pack("!BBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.property, self.length) = struct.unpack_from("!HH", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3]) = struct.unpack_from("!BBBB", binaryString, 4)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.property !=  other.property: return False
        if self.length !=  other.length: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'property: ' + str(self.property) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        return outstr

class ofp_queue_prop_min_rate:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.prop_header = ofp_queue_prop_header()
        self.rate = 0
        self.pad= [0,0,0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.prop_header, ofp_queue_prop_header)):
            return (False, "self.prop_header is not class ofp_queue_prop_header as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 6):
            return (False, "self.pad is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.prop_header.pack()
        packed += struct.pack("!H", self.rate)
        packed += struct.pack("!BBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 16):
            return binaryString
        self.prop_header.unpack(binaryString[0:])
        (self.rate,) = struct.unpack_from("!H", binaryString, 8)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5]) = struct.unpack_from("!BBBBBB", binaryString, 10)
        return binaryString[16:]

    def __len__(self):
        """Return length of message
        """
        l = 16
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.prop_header !=  other.prop_header: return False
        if self.rate !=  other.rate: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'prop_header: \n'
        self.prop_header.show(prefix + '  ')
        outstr += prefix + 'rate: ' + str(self.rate) + '\n'
        return outstr

##2.3 Flow Match Structures
class ofp_match:
    def __init__(self, **kw):
        """Initialize
        Declare members and default values
        """
        for k,v in ofp_match_data.iteritems():
          setattr(self, '_' + k, v)
        self.wildcards = self._normalize_wildcards(OFPFW_ALL)

        # This is basically _initHelper(), but tweaked slightly since this
        # class does some magic of its own.
        for k,v in kw:
          if not hasattr(self, '_'+k):
            raise TypeError(self.__class__.__name__ + " constructor got "
              + "unexpected keyword argument '" + k + "'")
          setattr(obj, k, v)

    def get_nw_dst (self):
      if (self.wildcards & OFPFW_NW_DST_ALL) == OFPFW_NW_DST_ALL: return (None, 0)

      w = (self.wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
      return (self._nw_dst,32-w if w <= 32 else 0)

    def get_nw_src (self):
      if (self.wildcards & OFPFW_NW_SRC_ALL) == OFPFW_NW_SRC_ALL: return (None, 0)

      w = (self.wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
      return (self._nw_src,32-w if w <= 32 else 0)

    def set_nw_dst (self, *args, **kw):
      a = self._make_addr(*args, **kw)
      self._nw_dst = a[0]
      self.wildcards &= ~OFPFW_NW_DST_MASK
      self.wildcards |= ((32-a[1]) << OFPFW_NW_DST_SHIFT)

    def set_nw_src (self, *args, **kw):
      a = self._make_addr(*args, **kw)
      self._nw_src = a[0]
      self.wildcards &= ~OFPFW_NW_SRC_MASK
      self.wildcards |= ((32-a[1]) << OFPFW_NW_SRC_SHIFT)

    def _make_addr (self, ipOrIPAndBits, bits=None):
      b = None
      if type(ipOrIPAndBits) is tuple:
        ip = ipOrIPAndBits[0]
        b = int(ipOrIPAndBits[1])

      if (type(ipOrIPAndBits) is str) and (len(ipOrIPAndBits) != 4):
        if ipOrIPAndBits.find('/') != -1:
          s = ipOrIPAndBits.split('/')
          ip = s[0]
          b = int(s[1]) if b is None else b
        else:
          ip = ipOrIPAndBits
          b = 32 if b is None else b
      else:
        ip = ipOrIPAndBits
        b = 32 if b is None else b

      #TODO: fix addr using IPAddress
      """
      if type(ip) is str:
        if len(ip) == 4:
          # It's a packed IP
      """

      if bits != None: b = bits
      if b > 32: b = 32
      elif b < 0: b = 0

      return (ip, b)

    def __setattr__ (self, name, value):
      self.__dict__[name] = value
      if name not in ofp_match_data: return

      if name == 'nw_dst' or name == 'nw_src':
        # Special handling
        getattr(self, 'set_' + name)(value)
        return value

      if value is None:
        setattr(self, '_' + name, ofp_match_data[name][0])
        self.wildcards |= ofp_match_data[name][1]
      else:
        setattr(self, '_' + name, value)
        self.wildcards = self.wildcards & ~ofp_match_data[name][1]

      return value

    def __getattr__ (self, name):
      if name in ofp_match_data:
        if (self.wildcards & ofp_match_data[name][1]) == ofp_match_data[name][1]:
          # It's wildcarded -- always return None
          return None
        if name == 'nw_dst' or name == 'nw_src':
          # Special handling
          return getattr(self, 'get_' + name)()[0]
        return self.__dict__['_' + name]
      raise AttributeError

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.dl_src, list)):
            return (False, "self.dl_src is not list as expected.")
        if(len(self.dl_src) != 6):
            return (False, "self.dl_src is not of size 6 as expected.")
        if(not isinstance(self.dl_dst, list)):
            return (False, "self.dl_dst is not list as expected.")
        if(len(self.dl_dst) != 6):
            return (False, "self.dl_dst is not of size 6 as expected.")
        if(not isinstance(self.pad1, list)):
            return (False, "self.pad1 is not list as expected.")
        if(len(self.pad1) != 1):
            return (False, "self.pad1 is not of size 1 as expected.")
        if(not isinstance(self.pad2, list)):
            return (False, "self.pad2 is not list as expected.")
        if(len(self.pad2) != 2):
            return (False, "self.pad2 is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=False):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None

        packed = ""
        packed += struct.pack("!LH", self.wildcards, self.in_port or 0)
        if self.dl_src == None:
          packed += '\x00\x00\x00\x00\x00\x00'
        else:
          packed += struct.pack("!BBBBBB", self.dl_src[0], self.dl_src[1], self.dl_src[2], self.dl_src[3], self.dl_src[4], self.dl_src[5])
        if self.dl_dst == None:
          packed += '\x00\x00\x00\x00\x00\x00'
        else:
          packed += struct.pack("!BBBBBB", self.dl_dst[0], self.dl_dst[1], self.dl_dst[2], self.dl_dst[3], self.dl_dst[4], self.dl_dst[5])
        packed += struct.pack("!HB", self.dl_vlan or 0, self.dl_vlan_pcp or 0)
        packed += '\x00' # Hardcode padding
        packed += struct.pack("!HBB", self.dl_type or 0, self.nw_tos or 0, self.nw_proto or 0)
        packed += '\x00\x00' # Hardcode padding
        packed += struct.pack("!LLHH", self.nw_src or 0, self.nw_dst or 0, self.tp_src or 0, self.tp_dst or 0)
        return packed

    def _normalize_wildcards (self, wildcards):
      """ nw_src and nw_dst values greater than 32 mean the same thing as 32.
          We normalize them here just to be clean and so that comparisons act
          as you'd want them to. """
      if ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT) > 32:
        wildcards &= ~OFPFW_NW_SRC_MASK
        wildcards |= (32 << OFPFW_NW_SRC_SHIFT)
      if ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT) > 32:
        wildcards &= ~OFPFW_NW_DST_MASK
        wildcards |= (32 << OFPFW_NW_DST_SHIFT)
      return wildcards

    def unpack (self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 40):
            return binaryString
        (wildcards, self._in_port) = struct.unpack_from("!LH", binaryString, 0)
        (self._dl_src[0], self._dl_src[1], self._dl_src[2], self._dl_src[3], self._dl_src[4], self._dl_src[5]) = struct.unpack_from("!BBBBBB", binaryString, 6)
        (self._dl_dst[0], self._dl_dst[1], self._dl_dst[2], self._dl_dst[3], self._dl_dst[4], self._dl_dst[5]) = struct.unpack_from("!BBBBBB", binaryString, 12)
        (self._dl_vlan, self._dl_vlan_pcp) = struct.unpack_from("!HB", binaryString, 18)
        (self._pad1[0]) = struct.unpack_from("!B", binaryString, 21)
        (self._dl_type, self._nw_tos, self._nw_proto) = struct.unpack_from("!HBB", binaryString, 22)
        (self._pad2[0], self._pad2[1]) = struct.unpack_from("!BB", binaryString, 26)
        (self._nw_src, self._nw_dst, self._tp_src, self._tp_dst) = struct.unpack_from("!LLHH", binaryString, 28)

        self.wildcards = self._normalize_wildcards(wildcards) # Override
        return binaryString[40:]

    def __len__(self):
        """Return length of message
        """
        l = 40
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.wildcards !=  other.wildcards: return False
        if self.in_port !=  other.in_port: return False
        if self.dl_src !=  other.dl_src: return False
        if self.dl_dst !=  other.dl_dst: return False
        if self.dl_vlan !=  other.dl_vlan: return False
        if self.dl_vlan_pcp !=  other.dl_vlan_pcp: return False
        if self.pad1 !=  other.pad1: return False
        if self.dl_type !=  other.dl_type: return False
        if self.nw_tos !=  other.nw_tos: return False
        if self.nw_proto !=  other.nw_proto: return False
        if self.pad2 !=  other.pad2: return False
        if self.nw_src !=  other.nw_src: return False
        if self.nw_dst !=  other.nw_dst: return False
        if self.tp_src !=  other.tp_src: return False
        if self.tp_dst !=  other.tp_dst: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        def binstr (n):
          s = ''
          while True:
            s = ('1' if n & 1 else '0') + s
            n >>= 1
            if n == 0: break
          return s
        outstr = ''
        outstr += prefix + 'wildcards: ' + binstr(self.wildcards) + ' (0x' + hex(self.wildcards) + ')\n'
        outstr += prefix + 'in_port: ' + str(self.in_port) + '\n'
        outstr += prefix + 'dl_src: ' + str(self.dl_src) + '\n'
        outstr += prefix + 'dl_dst: ' + str(self.dl_dst) + '\n'
        outstr += prefix + 'dl_vlan: ' + str(self.dl_vlan) + '\n'
        outstr += prefix + 'dl_vlan_pcp: ' + str(self.dl_vlan_pcp) + '\n'
        outstr += prefix + 'dl_type: ' + str(self.dl_type) + '\n'
        outstr += prefix + 'nw_tos: ' + str(self.nw_tos) + '\n'
        outstr += prefix + 'nw_proto: ' + str(self.nw_proto) + '\n'
        outstr += prefix + 'nw_src: ' + str(self.nw_src) + '\n'
        outstr += prefix + 'nw_dst: ' + str(self.nw_dst) + '\n'
        outstr += prefix + 'tp_src: ' + str(self.tp_src) + '\n'
        outstr += prefix + 'tp_dst: ' + str(self.tp_dst) + '\n'
        return outstr

ofp_flow_wildcards = ['OFPFW_IN_PORT', 'OFPFW_DL_VLAN', 'OFPFW_DL_SRC', \
                      'OFPFW_DL_DST', 'OFPFW_DL_TYPE', 'OFPFW_NW_PROTO', \
                      'OFPFW_TP_SRC', 'OFPFW_TP_DST', 'OFPFW_NW_SRC_SHIFT', \
                      'OFPFW_NW_SRC_BITS', 'OFPFW_NW_SRC_MASK', \
                      'OFPFW_NW_SRC_ALL', 'OFPFW_NW_DST_SHIFT', \
                      'OFPFW_NW_DST_BITS', 'OFPFW_NW_DST_MASK', \
                      'OFPFW_NW_DST_ALL', 'OFPFW_DL_VLAN_PCP', \
                      'OFPFW_NW_TOS', 'OFPFW_ALL']
OFPFW_IN_PORT                       = 1
OFPFW_DL_VLAN                       = 2
OFPFW_DL_SRC                        = 4
OFPFW_DL_DST                        = 8
OFPFW_DL_TYPE                       = 16
OFPFW_NW_PROTO                      = 32
OFPFW_TP_SRC                        = 64
OFPFW_TP_DST                        = 128
OFPFW_NW_SRC_SHIFT                  = 8
OFPFW_NW_SRC_BITS                   = 6
OFPFW_NW_SRC_MASK                   = 16128
OFPFW_NW_SRC_ALL                    = 8192
OFPFW_NW_DST_SHIFT                  = 14
OFPFW_NW_DST_BITS                   = 6
OFPFW_NW_DST_MASK                   = 1032192
OFPFW_NW_DST_ALL                    = 524288
OFPFW_DL_VLAN_PCP                   = 1048576
OFPFW_NW_TOS                        = 2097152
OFPFW_ALL                           = 4194303
ofp_flow_wildcards_map = {
    1                               : 'OFPFW_IN_PORT',
    2                               : 'OFPFW_DL_VLAN',
    4                               : 'OFPFW_DL_SRC',
    8                               : 'OFPFW_DL_DST',
    16                              : 'OFPFW_DL_TYPE',
    32                              : 'OFPFW_NW_PROTO',
    64                              : 'OFPFW_TP_SRC',
    128                             : 'OFPFW_TP_DST',
    8                               : 'OFPFW_NW_SRC_SHIFT',
    6                               : 'OFPFW_NW_SRC_BITS',
    16128                           : 'OFPFW_NW_SRC_MASK',
    8192                            : 'OFPFW_NW_SRC_ALL',
    14                              : 'OFPFW_NW_DST_SHIFT',
    6                               : 'OFPFW_NW_DST_BITS',
    1032192                         : 'OFPFW_NW_DST_MASK',
    524288                          : 'OFPFW_NW_DST_ALL',
    1048576                         : 'OFPFW_DL_VLAN_PCP',
    2097152                         : 'OFPFW_NW_TOS',
    4194303                         : 'OFPFW_ALL'
}

##2.4 Flow Action Structures
ofp_action_type = ['OFPAT_OUTPUT', 'OFPAT_SET_VLAN_VID', 'OFPAT_SET_VLAN_PCP', \
                   'OFPAT_STRIP_VLAN', 'OFPAT_SET_DL_SRC', 'OFPAT_SET_DL_DST', \
                   'OFPAT_SET_NW_SRC', 'OFPAT_SET_NW_DST', 'OFPAT_SET_NW_TOS', \
                   'OFPAT_SET_TP_SRC', 'OFPAT_SET_TP_DST', 'OFPAT_ENQUEUE', \
                   'OFPAT_VENDOR']
OFPAT_OUTPUT                        = 0
OFPAT_SET_VLAN_VID                  = 1
OFPAT_SET_VLAN_PCP                  = 2
OFPAT_STRIP_VLAN                    = 3
OFPAT_SET_DL_SRC                    = 4
OFPAT_SET_DL_DST                    = 5
OFPAT_SET_NW_SRC                    = 6
OFPAT_SET_NW_DST                    = 7
OFPAT_SET_NW_TOS                    = 8
OFPAT_SET_TP_SRC                    = 9
OFPAT_SET_TP_DST                    = 10
OFPAT_ENQUEUE                       = 11
OFPAT_VENDOR                        = 65535
ofp_action_type_map = {
    0                               : 'OFPAT_OUTPUT',
    1                               : 'OFPAT_SET_VLAN_VID',
    2                               : 'OFPAT_SET_VLAN_PCP',
    3                               : 'OFPAT_STRIP_VLAN',
    4                               : 'OFPAT_SET_DL_SRC',
    5                               : 'OFPAT_SET_DL_DST',
    6                               : 'OFPAT_SET_NW_SRC',
    7                               : 'OFPAT_SET_NW_DST',
    8                               : 'OFPAT_SET_NW_TOS',
    9                               : 'OFPAT_SET_TP_SRC',
    10                              : 'OFPAT_SET_TP_DST',
    11                              : 'OFPAT_ENQUEUE',
    65535                           : 'OFPAT_VENDOR'
}

class ofp_action_header:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = 0
        self.length = 0
        self.pad= [0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 4):
            return (False, "self.pad is not of size 4 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HH", self.type, self.length)
        packed += struct.pack("!BBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length) = struct.unpack_from("!HH", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3]) = struct.unpack_from("!BBBB", binaryString, 4)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        return outstr

class ofp_action_output:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = OFPAT_OUTPUT
        self.length = 0
        self.port = 0
        self.max_len = 0

    def __assert(self):
        """Sanity check
        """
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHHH", self.type, self.length, self.port, self.max_len)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.port, self.max_len) = struct.unpack_from("!HHHH", binaryString, 0)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.port !=  other.port: return False
        if self.max_len !=  other.max_len: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'port: ' + str(self.port) + '\n'
        outstr += prefix + 'max_len: ' + str(self.max_len) + '\n'
        return outstr

class ofp_action_enqueue:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = 0
        self.length = 0
        self.port = 0
        self.pad= [0,0,0,0,0,0]
        self.queue_id = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 6):
            return (False, "self.pad is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHH", self.type, self.length, self.port)
        packed += struct.pack("!BBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5])
        packed += struct.pack("!L", self.queue_id)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 16):
            return binaryString
        (self.type, self.length, self.port) = struct.unpack_from("!HHH", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5]) = struct.unpack_from("!BBBBBB", binaryString, 6)
        (self.queue_id,) = struct.unpack_from("!L", binaryString, 12)
        return binaryString[16:]

    def __len__(self):
        """Return length of message
        """
        l = 16
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.port !=  other.port: return False
        if self.pad !=  other.pad: return False
        if self.queue_id !=  other.queue_id: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'port: ' + str(self.port) + '\n'
        outstr += prefix + 'queue_id: ' + str(self.queue_id) + '\n'
        return outstr

class ofp_action_vlan_vid:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = OFPAT_SET_VLAN_VID
        self.length = 0
        self.vlan_vid = 0
        self.pad= [0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 2):
            return (False, "self.pad is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHH", self.type, self.length, self.vlan_vid)
        packed += struct.pack("!BB", self.pad[0], self.pad[1])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.vlan_vid) = struct.unpack_from("!HHH", binaryString, 0)
        (self.pad[0], self.pad[1]) = struct.unpack_from("!BB", binaryString, 6)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.vlan_vid !=  other.vlan_vid: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'vlan_vid: ' + str(self.vlan_vid) + '\n'
        return outstr

class ofp_action_vlan_pcp:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = OFPAT_SET_VLAN_PCP
        self.length = 0
        self.vlan_pcp = 0
        self.pad= [0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 3):
            return (False, "self.pad is not of size 3 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHB", self.type, self.length, self.vlan_pcp)
        packed += struct.pack("!BBB", self.pad[0], self.pad[1], self.pad[2])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.vlan_pcp) = struct.unpack_from("!HHB", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2]) = struct.unpack_from("!BBB", binaryString, 5)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.vlan_pcp !=  other.vlan_pcp: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'vlan_pcp: ' + str(self.vlan_pcp) + '\n'
        return outstr

class ofp_action_dl_addr:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = 0
        self.length = 0
        self.dl_addr= [0,0,0,0,0,0]
        self.pad= [0,0,0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.dl_addr, list)):
            return (False, "self.dl_addr is not list as expected.")
        if(len(self.dl_addr) != 6):
            return (False, "self.dl_addr is not of size 6 as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 6):
            return (False, "self.pad is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HH", self.type, self.length)
        packed += struct.pack("!BBBBBB", self.dl_addr[0], self.dl_addr[1], self.dl_addr[2], self.dl_addr[3], self.dl_addr[4], self.dl_addr[5])
        packed += struct.pack("!BBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 16):
            return binaryString
        (self.type, self.length) = struct.unpack_from("!HH", binaryString, 0)
        (self.dl_addr[0], self.dl_addr[1], self.dl_addr[2], self.dl_addr[3], self.dl_addr[4], self.dl_addr[5]) = struct.unpack_from("!BBBBBB", binaryString, 4)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5]) = struct.unpack_from("!BBBBBB", binaryString, 10)
        return binaryString[16:]

    def __len__(self):
        """Return length of message
        """
        l = 16
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.dl_addr !=  other.dl_addr: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'dl_addr: ' + str(self.dl_addr) + '\n'
        return outstr

class ofp_action_nw_addr:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = 0
        self.length = 0
        self.nw_addr = 0

    def __assert(self):
        """Sanity check
        """
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHL", self.type, self.length, self.nw_addr)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.nw_addr) = struct.unpack_from("!HHL", binaryString, 0)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.nw_addr !=  other.nw_addr: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'nw_addr: ' + str(self.nw_addr) + '\n'
        return outstr

class ofp_action_nw_tos:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = 0
        self.length = 0
        self.nw_tos = 0
        self.pad= [0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 3):
            return (False, "self.pad is not of size 3 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHB", self.type, self.length, self.nw_tos)
        packed += struct.pack("!BBB", self.pad[0], self.pad[1], self.pad[2])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.nw_tos) = struct.unpack_from("!HHB", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2]) = struct.unpack_from("!BBB", binaryString, 5)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.nw_tos !=  other.nw_tos: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'nw_tos: ' + str(self.nw_tos) + '\n'
        return outstr

class ofp_action_tp_port:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = 0
        self.length = 0
        self.tp_port = 0
        self.pad= [0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 2):
            return (False, "self.pad is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHH", self.type, self.length, self.tp_port)
        packed += struct.pack("!BB", self.pad[0], self.pad[1])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.tp_port) = struct.unpack_from("!HHH", binaryString, 0)
        (self.pad[0], self.pad[1]) = struct.unpack_from("!BB", binaryString, 6)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.tp_port !=  other.tp_port: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'tp_port: ' + str(self.tp_port) + '\n'
        return outstr

class ofp_action_vendor_header:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.type = OFPAT_VENDOR
        self.length = 0
        self.vendor = 0

    def __assert(self):
        """Sanity check
        """
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HHL", self.type, self.length, self.vendor)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.type, self.length, self.vendor) = struct.unpack_from("!HHL", binaryString, 0)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.type !=  other.type: return False
        if self.length !=  other.length: return False
        if self.vendor !=  other.vendor: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'len: ' + str(self.length) + '\n'
        outstr += prefix + 'vendor: ' + str(self.vendor) + '\n'
        return outstr

#3. Controller-to-Switch Messages

##3.1 Handshake
# was ofp_switch_features
class ofp_features_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_FEATURES_REPLY
        self.datapath_id = 0
        self.n_buffers = 0
        self.n_tables = 0
        self.pad= [0,0,0]
        self.capabilities = 0
        self.actions = 0
        self.ports= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 3):
            return (False, "self.pad is not of size 3 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!QLB", self.datapath_id, self.n_buffers, self.n_tables)
        packed += struct.pack("!BBB", self.pad[0], self.pad[1], self.pad[2])
        packed += struct.pack("!LL", self.capabilities, self.actions)
        for i in self.ports:
            packed += i.pack(assertstruct)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 32):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.datapath_id, self.n_buffers, self.n_tables) = struct.unpack_from("!QLB", binaryString, 8)
        (self.pad[0], self.pad[1], self.pad[2]) = struct.unpack_from("!BBB", binaryString, 21)
        (self.capabilities, self.actions) = struct.unpack_from("!LL", binaryString, 24)
        return binaryString[32:]

    def __len__(self):
        """Return length of message
        """
        l = 32
        for i in self.ports:
            l += i.length()
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.datapath_id !=  other.datapath_id: return False
        if self.n_buffers !=  other.n_buffers: return False
        if self.n_tables !=  other.n_tables: return False
        if self.pad !=  other.pad: return False
        if self.capabilities !=  other.capabilities: return False
        if self.actions !=  other.actions: return False
        if self.ports !=  other.ports: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'datapath_id: ' + str(self.datapath_id) + '\n'
        outstr += prefix + 'n_buffers: ' + str(self.n_buffers) + '\n'
        outstr += prefix + 'n_tables: ' + str(self.n_tables) + '\n'
        outstr += prefix + 'capabilities: ' + str(self.capabilities) + '\n'
        outstr += prefix + 'actions: ' + str(self.actions) + '\n'
        outstr += prefix + 'ports: \n'
        for obj in self.ports:
            outstr += obj.show(prefix + '  ')
        return outstr

ofp_capabilities = ['OFPC_FLOW_STATS', 'OFPC_TABLE_STATS', 'OFPC_PORT_STATS', \
                    'OFPC_STP', 'OFPC_RESERVED', 'OFPC_IP_REASM', \
                    'OFPC_QUEUE_STATS', 'OFPC_ARP_MATCH_IP']
OFPC_FLOW_STATS                     = 1
OFPC_TABLE_STATS                    = 2
OFPC_PORT_STATS                     = 4
OFPC_STP                            = 8
OFPC_RESERVED                       = 16
OFPC_IP_REASM                       = 32
OFPC_QUEUE_STATS                    = 64
OFPC_ARP_MATCH_IP                   = 128
ofp_capabilities_map = {
    1                               : 'OFPC_FLOW_STATS',
    2                               : 'OFPC_TABLE_STATS',
    4                               : 'OFPC_PORT_STATS',
    8                               : 'OFPC_STP',
    16                              : 'OFPC_RESERVED',
    32                              : 'OFPC_IP_REASM',
    64                              : 'OFPC_QUEUE_STATS',
    128                             : 'OFPC_ARP_MATCH_IP'
}

##3.2 Switch Configuration
class ofp_switch_config:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.flags = 0
        self.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!HH", self.flags, self.miss_send_len)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.flags, self.miss_send_len) = struct.unpack_from("!HH", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.flags !=  other.flags: return False
        if self.miss_send_len !=  other.miss_send_len: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'flags: ' + str(self.flags) + '\n'
        outstr += prefix + 'miss_send_len: ' + str(self.miss_send_len) + '\n'
        return outstr

ofp_config_flags = ['OFPC_FRAG_NORMAL', 'OFPC_FRAG_DROP', 'OFPC_FRAG_REASM', \
                    'OFPC_FRAG_MASK']
OFPC_FRAG_NORMAL                    = 0
OFPC_FRAG_DROP                      = 1
OFPC_FRAG_REASM                     = 2
OFPC_FRAG_MASK                      = 3
ofp_config_flags_map = {
    0                               : 'OFPC_FRAG_NORMAL',
    1                               : 'OFPC_FRAG_DROP',
    2                               : 'OFPC_FRAG_REASM',
    3                               : 'OFPC_FRAG_MASK'
}

##3.3 Modify State Messages
class ofp_flow_mod:
    def __init__(self, **kw):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_FLOW_MOD
        self.match = ofp_match()
        self.cookie = 0
        self.command = 0
        self.idle_timeout = 0
        self.hard_timeout = 0
        self.priority = OFP_DEFAULT_PRIORITY
        self.buffer_id = 0
        self.out_port = 0
        self.flags = 0
        self.actions= []

        _initHelper(self, kw)
          
    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.match, ofp_match)):
            return (False, "self.match is not class ofp_match as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        self.header.length = len(self)
        packed += self.header.pack()
        packed += self.match.pack()
        packed += struct.pack("!QHHHHLHH", self.cookie, self.command, self.idle_timeout, self.hard_timeout, self.priority, self.buffer_id, self.out_port, self.flags)
        for i in self.actions:
            packed += i.pack(assertstruct)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 72):
            return binaryString
        self.header.unpack(binaryString[0:])
        self.match.unpack(binaryString[8:])
        (self.cookie, self.command, self.idle_timeout, self.hard_timeout, self.priority, self.buffer_id, self.out_port, self.flags) = struct.unpack_from("!QHHHHLHH", binaryString, 48)
        return binaryString[72:]

    def __len__(self):
        """Return length of message
        """
        l = 72
        for i in self.actions:
            l += len(i)#.length()
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.match !=  other.match: return False
        if self.cookie !=  other.cookie: return False
        if self.command !=  other.command: return False
        if self.idle_timeout !=  other.idle_timeout: return False
        if self.hard_timeout !=  other.hard_timeout: return False
        if self.priority !=  other.priority: return False
        if self.buffer_id !=  other.buffer_id: return False
        if self.out_port !=  other.out_port: return False
        if self.flags !=  other.flags: return False
        if self.actions !=  other.actions: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'match: \n'
        self.match.show(prefix + '  ')
        outstr += prefix + 'cookie: ' + str(self.cookie) + '\n'
        outstr += prefix + 'command: ' + str(self.command) + '\n'
        outstr += prefix + 'idle_timeout: ' + str(self.idle_timeout) + '\n'
        outstr += prefix + 'hard_timeout: ' + str(self.hard_timeout) + '\n'
        outstr += prefix + 'priority: ' + str(self.priority) + '\n'
        outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
        outstr += prefix + 'out_port: ' + str(self.out_port) + '\n'
        outstr += prefix + 'flags: ' + str(self.flags) + '\n'
        outstr += prefix + 'actions: \n'
        for obj in self.actions:
            outstr += obj.show(prefix + '  ')
        return outstr

ofp_flow_mod_command = ['OFPFC_ADD', 'OFPFC_MODIFY', 'OFPFC_MODIFY_STRICT', \
                        'OFPFC_DELETE', 'OFPFC_DELETE_STRICT']
OFPFC_ADD                           = 0
OFPFC_MODIFY                        = 1
OFPFC_MODIFY_STRICT                 = 2
OFPFC_DELETE                        = 3
OFPFC_DELETE_STRICT                 = 4
ofp_flow_mod_command_map = {
    0                               : 'OFPFC_ADD',
    1                               : 'OFPFC_MODIFY',
    2                               : 'OFPFC_MODIFY_STRICT',
    3                               : 'OFPFC_DELETE',
    4                               : 'OFPFC_DELETE_STRICT'
}

ofp_flow_mod_flags = ['OFPFF_SEND_FLOW_REM', 'OFPFF_CHECK_OVERLAP', \
                      'OFPFF_EMERG']
OFPFF_SEND_FLOW_REM                 = 1
OFPFF_CHECK_OVERLAP                 = 2
OFPFF_EMERG                         = 4
ofp_flow_mod_flags_map = {
    1                               : 'OFPFF_SEND_FLOW_REM',
    2                               : 'OFPFF_CHECK_OVERLAP',
    4                               : 'OFPFF_EMERG'
}

class ofp_port_mod:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_PORT_MOD
        self.port_no = 0
        self.hw_addr= [0,0,0,0,0,0]
        self.config = 0
        self.mask = 0
        self.advertise = 0
        self.pad= [0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.hw_addr, list)):
            return (False, "self.hw_addr is not list as expected.")
        if(len(self.hw_addr) != 6):
            return (False, "self.hw_addr is not of size 6 as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 4):
            return (False, "self.pad is not of size 4 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!H", self.port_no)
        packed += struct.pack("!BBBBBB", self.hw_addr[0], self.hw_addr[1], self.hw_addr[2], self.hw_addr[3], self.hw_addr[4], self.hw_addr[5])
        packed += struct.pack("!LLL", self.config, self.mask, self.advertise)
        packed += struct.pack("!BBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 32):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.port_no,) = struct.unpack_from("!H", binaryString, 8)
        (self.hw_addr[0], self.hw_addr[1], self.hw_addr[2], self.hw_addr[3], self.hw_addr[4], self.hw_addr[5]) = struct.unpack_from("!BBBBBB", binaryString, 10)
        (self.config, self.mask, self.advertise) = struct.unpack_from("!LLL", binaryString, 16)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3]) = struct.unpack_from("!BBBB", binaryString, 28)
        return binaryString[32:]

    def __len__(self):
        """Return length of message
        """
        l = 32
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.port_no !=  other.port_no: return False
        if self.hw_addr !=  other.hw_addr: return False
        if self.config !=  other.config: return False
        if self.mask !=  other.mask: return False
        if self.advertise !=  other.advertise: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'port_no: ' + str(self.port_no) + '\n'
        outstr += prefix + 'hw_addr: ' + str(self.hw_addr) + '\n'
        outstr += prefix + 'config: ' + str(self.config) + '\n'
        outstr += prefix + 'mask: ' + str(self.mask) + '\n'
        outstr += prefix + 'advertise: ' + str(self.advertise) + '\n'
        return outstr

##3.4 Queue Configuration Messages
class ofp_queue_get_config_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.port = 0
        self.pad= [0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 2):
            return (False, "self.pad is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!H", self.port)
        packed += struct.pack("!BB", self.pad[0], self.pad[1])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.port,) = struct.unpack_from("!H", binaryString, 8)
        (self.pad[0], self.pad[1]) = struct.unpack_from("!BB", binaryString, 10)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.port !=  other.port: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'port: ' + str(self.port) + '\n'
        return outstr

class ofp_queue_get_config_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.port = 0
        self.pad= [0,0,0,0,0,0]
        self.queues= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 6):
            return (False, "self.pad is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!H", self.port)
        packed += struct.pack("!BBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5])
        for i in self.queues:
            packed += i.pack(assertstruct)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 16):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.port,) = struct.unpack_from("!H", binaryString, 8)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5]) = struct.unpack_from("!BBBBBB", binaryString, 10)
        return binaryString[16:]

    def __len__(self):
        """Return length of message
        """
        l = 16
        for i in self.queues:
            l += i.length()
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.port !=  other.port: return False
        if self.pad !=  other.pad: return False
        if self.queues !=  other.queues: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'port: ' + str(self.port) + '\n'
        outstr += prefix + 'queues: \n'
        for obj in self.queues:
            outstr += obj.show(prefix + '  ')
        return outstr

##3.5 Read State Messages
class ofp_stats_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_STATS_REQUEST
        self.type = 0
        self.flags = 0
        self.body= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!HH", self.type, self.flags)
        for i in self.body:
            packed += struct.pack("!B",i)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.type, self.flags) = struct.unpack_from("!HH", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        l += len(self.body)*1
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.type !=  other.type: return False
        if self.flags !=  other.flags: return False
        if self.body !=  other.body: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'flags: ' + str(self.flags) + '\n'
        outstr += prefix + 'body: ' + str(self.body) + '\n'
        return outstr

class ofp_stats_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_STATS_REPLY
        self.type = 0
        self.flags = 0
        self.body= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!HH", self.type, self.flags)
        for i in self.body:
            packed += struct.pack("!B",i)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.type, self.flags) = struct.unpack_from("!HH", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        l += len(self.body)*1
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.type !=  other.type: return False
        if self.flags !=  other.flags: return False
        if self.body !=  other.body: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'flags: ' + str(self.flags) + '\n'
        outstr += prefix + 'body: ' + str(self.body) + '\n'
        return outstr

ofp_stats_types = ['OFPST_DESC', 'OFPST_FLOW', 'OFPST_AGGREGATE', \
                   'OFPST_TABLE', 'OFPST_PORT', 'OFPST_QUEUE', 'OFPST_VENDOR']
OFPST_DESC                          = 0
OFPST_FLOW                          = 1
OFPST_AGGREGATE                     = 2
OFPST_TABLE                         = 3
OFPST_PORT                          = 4
OFPST_QUEUE                         = 5
OFPST_VENDOR                        = 65535
ofp_stats_types_map = {
    0                               : 'OFPST_DESC',
    1                               : 'OFPST_FLOW',
    2                               : 'OFPST_AGGREGATE',
    3                               : 'OFPST_TABLE',
    4                               : 'OFPST_PORT',
    5                               : 'OFPST_QUEUE',
    65535                           : 'OFPST_VENDOR'
}

ofp_stats_reply_flags = ['OFPSF_REPLY_MORE']
OFPSF_REPLY_MORE                    = 1
ofp_stats_reply_flags_map = {
    1                               : 'OFPSF_REPLY_MORE'
}

class ofp_desc_stats:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.mfr_desc= ""
        self.hw_desc= ""
        self.sw_desc= ""
        self.serial_num= ""
        self.dp_desc= ""

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.mfr_desc, str)):
            return (False, "self.mfr_desc is not string as expected.")
        if(len(self.mfr_desc) > 256):
            return (False, "self.mfr_desc is not of size 256 as expected.")
        if(not isinstance(self.hw_desc, str)):
            return (False, "self.hw_desc is not string as expected.")
        if(len(self.hw_desc) > 256):
            return (False, "self.hw_desc is not of size 256 as expected.")
        if(not isinstance(self.sw_desc, str)):
            return (False, "self.sw_desc is not string as expected.")
        if(len(self.sw_desc) > 256):
            return (False, "self.sw_desc is not of size 256 as expected.")
        if(not isinstance(self.serial_num, str)):
            return (False, "self.serial_num is not string as expected.")
        if(len(self.serial_num) > 32):
            return (False, "self.serial_num is not of size 32 as expected.")
        if(not isinstance(self.dp_desc, str)):
            return (False, "self.dp_desc is not string as expected.")
        if(len(self.dp_desc) > 256):
            return (False, "self.dp_desc is not of size 256 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.mfr_desc.ljust(256,'\0')
        packed += self.hw_desc.ljust(256,'\0')
        packed += self.sw_desc.ljust(256,'\0')
        packed += self.serial_num.ljust(32,'\0')
        packed += self.dp_desc.ljust(256,'\0')
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 1056):
            return binaryString
        self.mfr_desc = binaryString[0:256].replace("\0","")
        self.hw_desc = binaryString[256:512].replace("\0","")
        self.sw_desc = binaryString[512:768].replace("\0","")
        self.serial_num = binaryString[768:800].replace("\0","")
        self.dp_desc = binaryString[800:1056].replace("\0","")
        return binaryString[1056:]

    def __len__(self):
        """Return length of message
        """
        l = 1056
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.mfr_desc !=  other.mfr_desc: return False
        if self.hw_desc !=  other.hw_desc: return False
        if self.sw_desc !=  other.sw_desc: return False
        if self.serial_num !=  other.serial_num: return False
        if self.dp_desc !=  other.dp_desc: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'mfr_desc: ' + str(self.mfr_desc) + '\n'
        outstr += prefix + 'hw_desc: ' + str(self.hw_desc) + '\n'
        outstr += prefix + 'sw_desc: ' + str(self.sw_desc) + '\n'
        outstr += prefix + 'serial_num: ' + str(self.serial_num) + '\n'
        outstr += prefix + 'dp_desc: ' + str(self.dp_desc) + '\n'
        return outstr

class ofp_flow_stats_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.match = ofp_match()
        self.table_id = 0
        self.pad = 0
        self.out_port = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.match, ofp_match)):
            return (False, "self.match is not class ofp_match as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.match.pack()
        packed += struct.pack("!BBH", self.table_id, self.pad, self.out_port)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 44):
            return binaryString
        self.match.unpack(binaryString[0:])
        (self.table_id, self.pad, self.out_port) = struct.unpack_from("!BBH", binaryString, 40)
        return binaryString[44:]

    def __len__(self):
        """Return length of message
        """
        l = 44
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.match !=  other.match: return False
        if self.table_id !=  other.table_id: return False
        if self.pad !=  other.pad: return False
        if self.out_port !=  other.out_port: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'match: \n'
        self.match.show(prefix + '  ')
        outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
        outstr += prefix + 'out_port: ' + str(self.out_port) + '\n'
        return outstr

class ofp_flow_stats:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.length = 0
        self.table_id = 0
        self.pad = 0
        self.match = ofp_match()
        self.duration_sec = 0
        self.duration_nsec = 0
        self.priority = OFP_DEFAULT_PRIORITY
        self.idle_timeout = 0
        self.hard_timeout = 0
        self.pad2= [0,0,0,0,0,0]
        self.cookie = 0
        self.packet_count = 0
        self.byte_count = 0
        self.actions= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.match, ofp_match)):
            return (False, "self.match is not class ofp_match as expected.")
        if(not isinstance(self.pad2, list)):
            return (False, "self.pad2 is not list as expected.")
        if(len(self.pad2) != 6):
            return (False, "self.pad2 is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!HBB", self.length, self.table_id, self.pad)
        packed += self.match.pack()
        packed += struct.pack("!LLHHH", self.duration_sec, self.duration_nsec, self.priority, self.idle_timeout, self.hard_timeout)
        packed += struct.pack("!BBBBBB", self.pad2[0], self.pad2[1], self.pad2[2], self.pad2[3], self.pad2[4], self.pad2[5])
        packed += struct.pack("!QQQ", self.cookie, self.packet_count, self.byte_count)
        for i in self.actions:
            packed += i.pack(assertstruct)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 88):
            return binaryString
        (self.length, self.table_id, self.pad) = struct.unpack_from("!HBB", binaryString, 0)
        self.match.unpack(binaryString[4:])
        (self.duration_sec, self.duration_nsec, self.priority, self.idle_timeout, self.hard_timeout) = struct.unpack_from("!LLHHH", binaryString, 44)
        (self.pad2[0], self.pad2[1], self.pad2[2], self.pad2[3], self.pad2[4], self.pad2[5]) = struct.unpack_from("!BBBBBB", binaryString, 58)
        (self.cookie, self.packet_count, self.byte_count) = struct.unpack_from("!QQQ", binaryString, 64)
        return binaryString[88:]

    def __len__(self):
        """Return length of message
        """
        l = 88
        for i in self.actions:
            l += i.length()
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.length !=  other.length: return False
        if self.table_id !=  other.table_id: return False
        if self.pad !=  other.pad: return False
        if self.match !=  other.match: return False
        if self.duration_sec !=  other.duration_sec: return False
        if self.duration_nsec !=  other.duration_nsec: return False
        if self.priority !=  other.priority: return False
        if self.idle_timeout !=  other.idle_timeout: return False
        if self.hard_timeout !=  other.hard_timeout: return False
        if self.pad2 !=  other.pad2: return False
        if self.cookie !=  other.cookie: return False
        if self.packet_count !=  other.packet_count: return False
        if self.byte_count !=  other.byte_count: return False
        if self.actions !=  other.actions: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'length: ' + str(self.length) + '\n'
        outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
        outstr += prefix + 'match: \n'
        self.match.show(prefix + '  ')
        outstr += prefix + 'duration_sec: ' + str(self.duration_sec) + '\n'
        outstr += prefix + 'duration_nsec: ' + str(self.duration_nsec) + '\n'
        outstr += prefix + 'priority: ' + str(self.priority) + '\n'
        outstr += prefix + 'idle_timeout: ' + str(self.idle_timeout) + '\n'
        outstr += prefix + 'hard_timeout: ' + str(self.hard_timeout) + '\n'
        outstr += prefix + 'cookie: ' + str(self.cookie) + '\n'
        outstr += prefix + 'packet_count: ' + str(self.packet_count) + '\n'
        outstr += prefix + 'byte_count: ' + str(self.byte_count) + '\n'
        outstr += prefix + 'actions: \n'
        for obj in self.actions:
            outstr += obj.show(prefix + '  ')
        return outstr

class ofp_aggregate_stats_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.match = ofp_match()
        self.table_id = 0
        self.pad = 0
        self.out_port = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.match, ofp_match)):
            return (False, "self.match is not class ofp_match as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.match.pack()
        packed += struct.pack("!BBH", self.table_id, self.pad, self.out_port)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 44):
            return binaryString
        self.match.unpack(binaryString[0:])
        (self.table_id, self.pad, self.out_port) = struct.unpack_from("!BBH", binaryString, 40)
        return binaryString[44:]

    def __len__(self):
        """Return length of message
        """
        l = 44
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.match !=  other.match: return False
        if self.table_id !=  other.table_id: return False
        if self.pad !=  other.pad: return False
        if self.out_port !=  other.out_port: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'match: \n'
        self.match.show(prefix + '  ')
        outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
        outstr += prefix + 'out_port: ' + str(self.out_port) + '\n'
        return outstr

class ofp_aggregate_stats_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.packet_count = 0
        self.byte_count = 0
        self.flow_count = 0
        self.pad= [0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 4):
            return (False, "self.pad is not of size 4 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!QQL", self.packet_count, self.byte_count, self.flow_count)
        packed += struct.pack("!BBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 24):
            return binaryString
        (self.packet_count, self.byte_count, self.flow_count) = struct.unpack_from("!QQL", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3]) = struct.unpack_from("!BBBB", binaryString, 20)
        return binaryString[24:]

    def __len__(self):
        """Return length of message
        """
        l = 24
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.packet_count !=  other.packet_count: return False
        if self.byte_count !=  other.byte_count: return False
        if self.flow_count !=  other.flow_count: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'packet_count: ' + str(self.packet_count) + '\n'
        outstr += prefix + 'byte_count: ' + str(self.byte_count) + '\n'
        outstr += prefix + 'flow_count: ' + str(self.flow_count) + '\n'
        return outstr

class ofp_table_stats:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.table_id = 0
        self.pad= [0,0,0]
        self.name= ""
        self.wildcards = 0
        self.max_entries = 0
        self.active_count = 0
        self.lookup_count = 0
        self.matched_count = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 3):
            return (False, "self.pad is not of size 3 as expected.")
        if(not isinstance(self.name, str)):
            return (False, "self.name is not string as expected.")
        if(len(self.name) > 32):
            return (False, "self.name is not of size 32 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!B", self.table_id)
        packed += struct.pack("!BBB", self.pad[0], self.pad[1], self.pad[2])
        packed += self.name.ljust(32,'\0')
        packed += struct.pack("!LLLQQ", self.wildcards, self.max_entries, self.active_count, self.lookup_count, self.matched_count)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 64):
            return binaryString
        (self.table_id,) = struct.unpack_from("!B", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2]) = struct.unpack_from("!BBB", binaryString, 1)
        self.name = binaryString[4:36].replace("\0","")
        (self.wildcards, self.max_entries, self.active_count, self.lookup_count, self.matched_count) = struct.unpack_from("!LLLQQ", binaryString, 36)
        return binaryString[64:]

    def __len__(self):
        """Return length of message
        """
        l = 64
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.table_id !=  other.table_id: return False
        if self.pad !=  other.pad: return False
        if self.name !=  other.name: return False
        if self.wildcards !=  other.wildcards: return False
        if self.max_entries !=  other.max_entries: return False
        if self.active_count !=  other.active_count: return False
        if self.lookup_count !=  other.lookup_count: return False
        if self.matched_count !=  other.matched_count: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
        outstr += prefix + 'name: ' + str(self.name) + '\n'
        outstr += prefix + 'wildcards: ' + str(self.wildcards) + '\n'
        outstr += prefix + 'max_entries: ' + str(self.max_entries) + '\n'
        outstr += prefix + 'active_count: ' + str(self.active_count) + '\n'
        outstr += prefix + 'lookup_count: ' + str(self.lookup_count) + '\n'
        outstr += prefix + 'matched_count: ' + str(self.matched_count) + '\n'
        return outstr

class ofp_port_stats_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.port_no = 0
        self.pad= [0,0,0,0,0,0]

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 6):
            return (False, "self.pad is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!H", self.port_no)
        packed += struct.pack("!BBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5])
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.port_no,) = struct.unpack_from("!H", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5]) = struct.unpack_from("!BBBBBB", binaryString, 2)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.port_no !=  other.port_no: return False
        if self.pad !=  other.pad: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'port_no: ' + str(self.port_no) + '\n'
        return outstr

class ofp_port_stats:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.port_no = 0
        self.pad= [0,0,0,0,0,0]
        self.rx_packets = 0
        self.tx_packets = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_dropped = 0
        self.tx_dropped = 0
        self.rx_errors = 0
        self.tx_errors = 0
        self.rx_frame_err = 0
        self.rx_over_err = 0
        self.rx_crc_err = 0
        self.collisions = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 6):
            return (False, "self.pad is not of size 6 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!H", self.port_no)
        packed += struct.pack("!BBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5])
        packed += struct.pack("!QQQQQQQQQQQQ", self.rx_packets, self.tx_packets, self.rx_bytes, self.tx_bytes, self.rx_dropped, self.tx_dropped, self.rx_errors, self.tx_errors, self.rx_frame_err, self.rx_over_err, self.rx_crc_err, self.collisions)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 104):
            return binaryString
        (self.port_no,) = struct.unpack_from("!H", binaryString, 0)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5]) = struct.unpack_from("!BBBBBB", binaryString, 2)
        (self.rx_packets, self.tx_packets, self.rx_bytes, self.tx_bytes, self.rx_dropped, self.tx_dropped, self.rx_errors, self.tx_errors, self.rx_frame_err, self.rx_over_err, self.rx_crc_err, self.collisions) = struct.unpack_from("!QQQQQQQQQQQQ", binaryString, 8)
        return binaryString[104:]

    def __len__(self):
        """Return length of message
        """
        l = 104
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.port_no !=  other.port_no: return False
        if self.pad !=  other.pad: return False
        if self.rx_packets !=  other.rx_packets: return False
        if self.tx_packets !=  other.tx_packets: return False
        if self.rx_bytes !=  other.rx_bytes: return False
        if self.tx_bytes !=  other.tx_bytes: return False
        if self.rx_dropped !=  other.rx_dropped: return False
        if self.tx_dropped !=  other.tx_dropped: return False
        if self.rx_errors !=  other.rx_errors: return False
        if self.tx_errors !=  other.tx_errors: return False
        if self.rx_frame_err !=  other.rx_frame_err: return False
        if self.rx_over_err !=  other.rx_over_err: return False
        if self.rx_crc_err !=  other.rx_crc_err: return False
        if self.collisions !=  other.collisions: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'port_no: ' + str(self.port_no) + '\n'
        outstr += prefix + 'rx_packets: ' + str(self.rx_packets) + '\n'
        outstr += prefix + 'tx_packets: ' + str(self.tx_packets) + '\n'
        outstr += prefix + 'rx_bytes: ' + str(self.rx_bytes) + '\n'
        outstr += prefix + 'tx_bytes: ' + str(self.tx_bytes) + '\n'
        outstr += prefix + 'rx_dropped: ' + str(self.rx_dropped) + '\n'
        outstr += prefix + 'tx_dropped: ' + str(self.tx_dropped) + '\n'
        outstr += prefix + 'rx_errors: ' + str(self.rx_errors) + '\n'
        outstr += prefix + 'tx_errors: ' + str(self.tx_errors) + '\n'
        outstr += prefix + 'rx_frame_err: ' + str(self.rx_frame_err) + '\n'
        outstr += prefix + 'rx_over_err: ' + str(self.rx_over_err) + '\n'
        outstr += prefix + 'rx_crc_err: ' + str(self.rx_crc_err) + '\n'
        outstr += prefix + 'collisions: ' + str(self.collisions) + '\n'
        return outstr

class ofp_queue_stats_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.port_no = 0
        self.pad= [0,0]
        self.queue_id = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 2):
            return (False, "self.pad is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!H", self.port_no)
        packed += struct.pack("!BB", self.pad[0], self.pad[1])
        packed += struct.pack("!L", self.queue_id)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        (self.port_no,) = struct.unpack_from("!H", binaryString, 0)
        (self.pad[0], self.pad[1]) = struct.unpack_from("!BB", binaryString, 2)
        (self.queue_id,) = struct.unpack_from("!L", binaryString, 4)
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.port_no !=  other.port_no: return False
        if self.pad !=  other.pad: return False
        if self.queue_id !=  other.queue_id: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'port_no: ' + str(self.port_no) + '\n'
        outstr += prefix + 'queue_id: ' + str(self.queue_id) + '\n'
        return outstr

class ofp_queue_stats:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.port_no = 0
        self.pad= [0,0]
        self.queue_id = 0
        self.tx_bytes = 0
        self.tx_packets = 0
        self.tx_errors = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 2):
            return (False, "self.pad is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += struct.pack("!H", self.port_no)
        packed += struct.pack("!BB", self.pad[0], self.pad[1])
        packed += struct.pack("!LQQQ", self.queue_id, self.tx_bytes, self.tx_packets, self.tx_errors)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 32):
            return binaryString
        (self.port_no,) = struct.unpack_from("!H", binaryString, 0)
        (self.pad[0], self.pad[1]) = struct.unpack_from("!BB", binaryString, 2)
        (self.queue_id, self.tx_bytes, self.tx_packets, self.tx_errors) = struct.unpack_from("!LQQQ", binaryString, 4)
        return binaryString[32:]

    def __len__(self):
        """Return length of message
        """
        l = 32
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.port_no !=  other.port_no: return False
        if self.pad !=  other.pad: return False
        if self.queue_id !=  other.queue_id: return False
        if self.tx_bytes !=  other.tx_bytes: return False
        if self.tx_packets !=  other.tx_packets: return False
        if self.tx_errors !=  other.tx_errors: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'port_no: ' + str(self.port_no) + '\n'
        outstr += prefix + 'queue_id: ' + str(self.queue_id) + '\n'
        outstr += prefix + 'tx_bytes: ' + str(self.tx_bytes) + '\n'
        outstr += prefix + 'tx_packets: ' + str(self.tx_packets) + '\n'
        outstr += prefix + 'tx_errors: ' + str(self.tx_errors) + '\n'
        return outstr

##3.6 Send Packet Message
class ofp_packet_out:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_PACKET_OUT
        self.buffer_id = 4294967295
        self.in_port = 0
        self.actions_len = 0
        self.actions= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!LHH", self.buffer_id, self.in_port, self.actions_len)
        for i in self.actions:
            packed += i.pack(assertstruct)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 16):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.buffer_id, self.in_port, self.actions_len) = struct.unpack_from("!LHH", binaryString, 8)
        return binaryString[16:]

    def __len__(self):
        """Return length of message
        """
        l = 16
        for i in self.actions:
            l += i.length()
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.buffer_id !=  other.buffer_id: return False
        if self.in_port !=  other.in_port: return False
        if self.actions_len !=  other.actions_len: return False
        if self.actions !=  other.actions: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
        outstr += prefix + 'in_port: ' + str(self.in_port) + '\n'
        outstr += prefix + 'actions_len: ' + str(self.actions_len) + '\n'
        outstr += prefix + 'actions: \n'
        for obj in self.actions:
            outstr += obj.show(prefix + '  ')
        return outstr

##3.7 Barrier Message
class ofp_barrier_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_BARRIER_REPLY

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        return outstr

class ofp_barrier_request:
    def __init__(self, **kw):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_BARRIER_REQUEST

        _initHelper(self, kw)

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        return outstr

#4 Asynchronous Messages
class ofp_packet_in:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_PACKET_IN
        self.buffer_id = 0
        self.total_len = 0
        self.in_port = 0
        self.reason = 0
        self.pad = 0
        self.data= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!LHHBB", self.buffer_id, self.total_len, self.in_port, self.reason, self.pad)
        for i in self.data:
            packed += struct.pack("!B",i)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 18):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.buffer_id, self.total_len, self.in_port, self.reason, self.pad) = struct.unpack_from("!LHHBB", binaryString, 8)
        if (len(binaryString) < self.header.length):
            return binaryString
        self.data = binaryString[18:self.header.length]
        return binaryString[self.header.length:]

    def __len__(self):
        """Return length of message
        """
        l = 18
        l += len(self.data)*1
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.buffer_id !=  other.buffer_id: return False
        if self.total_len !=  other.total_len: return False
        if self.in_port !=  other.in_port: return False
        if self.reason !=  other.reason: return False
        if self.pad !=  other.pad: return False
        if self.data !=  other.data: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
        outstr += prefix + 'total_len: ' + str(self.total_len) + '\n'
        outstr += prefix + 'in_port: ' + str(self.in_port) + '\n'
        outstr += prefix + 'reason: ' + str(self.reason) + '\n'
        outstr += prefix + 'data: ' + str(self.data) + '\n'
        return outstr

ofp_packet_in_reason = ['OFPR_NO_MATCH', 'OFPR_ACTION']
OFPR_NO_MATCH                       = 0
OFPR_ACTION                         = 1
ofp_packet_in_reason_map = {
    0                               : 'OFPR_NO_MATCH',
    1                               : 'OFPR_ACTION'
}

class ofp_flow_removed:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_FLOW_REMOVED
        self.match = ofp_match()
        self.cookie = 0
        self.priority = 0
        self.reason = 0
        self.pad= [0]
        self.duration_sec = 0
        self.duration_nsec = 0
        self.idle_timeout = 0
        self.pad2= [0,0]
        self.packet_count = 0
        self.byte_count = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.match, ofp_match)):
            return (False, "self.match is not class ofp_match as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 1):
            return (False, "self.pad is not of size 1 as expected.")
        if(not isinstance(self.pad2, list)):
            return (False, "self.pad2 is not list as expected.")
        if(len(self.pad2) != 2):
            return (False, "self.pad2 is not of size 2 as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += self.match.pack()
        packed += struct.pack("!QHB", self.cookie, self.priority, self.reason)
        packed += struct.pack("!B", self.pad[0])
        packed += struct.pack("!LLH", self.duration_sec, self.duration_nsec, self.idle_timeout)
        packed += struct.pack("!BB", self.pad2[0], self.pad2[1])
        packed += struct.pack("!QQ", self.packet_count, self.byte_count)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 88):
            return binaryString
        self.header.unpack(binaryString[0:])
        self.match.unpack(binaryString[8:])
        (self.cookie, self.priority, self.reason) = struct.unpack_from("!QHB", binaryString, 48)
        (self.pad[0]) = struct.unpack_from("!B", binaryString, 59)
        (self.duration_sec, self.duration_nsec, self.idle_timeout) = struct.unpack_from("!LLH", binaryString, 60)
        (self.pad2[0], self.pad2[1]) = struct.unpack_from("!BB", binaryString, 70)
        (self.packet_count, self.byte_count) = struct.unpack_from("!QQ", binaryString, 72)
        return binaryString[88:]

    def __len__(self):
        """Return length of message
        """
        l = 88
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.match !=  other.match: return False
        if self.cookie !=  other.cookie: return False
        if self.priority !=  other.priority: return False
        if self.reason !=  other.reason: return False
        if self.pad !=  other.pad: return False
        if self.duration_sec !=  other.duration_sec: return False
        if self.duration_nsec !=  other.duration_nsec: return False
        if self.idle_timeout !=  other.idle_timeout: return False
        if self.pad2 !=  other.pad2: return False
        if self.packet_count !=  other.packet_count: return False
        if self.byte_count !=  other.byte_count: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'match: \n'
        self.match.show(prefix + '  ')
        outstr += prefix + 'cookie: ' + str(self.cookie) + '\n'
        outstr += prefix + 'priority: ' + str(self.priority) + '\n'
        outstr += prefix + 'reason: ' + str(self.reason) + '\n'
        outstr += prefix + 'duration_sec: ' + str(self.duration_sec) + '\n'
        outstr += prefix + 'duration_nsec: ' + str(self.duration_nsec) + '\n'
        outstr += prefix + 'idle_timeout: ' + str(self.idle_timeout) + '\n'
        outstr += prefix + 'packet_count: ' + str(self.packet_count) + '\n'
        outstr += prefix + 'byte_count: ' + str(self.byte_count) + '\n'
        return outstr

ofp_flow_removed_reason = ['OFPRR_IDLE_TIMEOUT', 'OFPRR_HARD_TIMEOUT', \
                           'OFPRR_DELETE']
OFPRR_IDLE_TIMEOUT                  = 0
OFPRR_HARD_TIMEOUT                  = 1
OFPRR_DELETE                        = 2
ofp_flow_removed_reason_map = {
    0                               : 'OFPRR_IDLE_TIMEOUT',
    1                               : 'OFPRR_HARD_TIMEOUT',
    2                               : 'OFPRR_DELETE'
}

class ofp_port_status:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_PORT_STATUS
        self.reason = 0
        self.pad= [0,0,0,0,0,0,0]
        self.desc = ofp_phy_port()

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        if(not isinstance(self.pad, list)):
            return (False, "self.pad is not list as expected.")
        if(len(self.pad) != 7):
            return (False, "self.pad is not of size 7 as expected.")
        if(not isinstance(self.desc, ofp_phy_port)):
            return (False, "self.desc is not class ofp_phy_port as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!B", self.reason)
        packed += struct.pack("!BBBBBBB", self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5], self.pad[6])
        packed += self.desc.pack()
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 64):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.reason,) = struct.unpack_from("!B", binaryString, 8)
        (self.pad[0], self.pad[1], self.pad[2], self.pad[3], self.pad[4], self.pad[5], self.pad[6]) = struct.unpack_from("!BBBBBBB", binaryString, 9)
        self.desc.unpack(binaryString[16:])
        return binaryString[64:]

    def __len__(self):
        """Return length of message
        """
        l = 64
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.reason !=  other.reason: return False
        if self.pad !=  other.pad: return False
        if self.desc !=  other.desc: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'reason: ' + str(self.reason) + '\n'
        outstr += prefix + 'desc: \n'
        self.desc.show(prefix + '  ')
        return outstr

ofp_port_reason = ['OFPPR_ADD', 'OFPPR_DELETE', 'OFPPR_MODIFY']
OFPPR_ADD                           = 0
OFPPR_DELETE                        = 1
OFPPR_MODIFY                        = 2
ofp_port_reason_map = {
    0                               : 'OFPPR_ADD',
    1                               : 'OFPPR_DELETE',
    2                               : 'OFPPR_MODIFY'
}

#WAS class ofp_error_msg: (why changed? it's still ofp_error_msg in 1.0/1.1 spec)
class ofp_error:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_ERROR
        self.type = 0
        self.code = 0
        self.data= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!HH", self.type, self.code)
        for i in self.data:
            packed += struct.pack("!B",i)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.type, self.code) = struct.unpack_from("!HH", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        l += len(self.data)*1
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.type !=  other.type: return False
        if self.code !=  other.code: return False
        if self.data !=  other.data: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'type: ' + str(self.type) + '\n'
        outstr += prefix + 'code: ' + str(self.code) + '\n'
        outstr += prefix + 'data: ' + str(self.data) + '\n'
        return outstr

ofp_error_type = ['OFPET_HELLO_FAILED', 'OFPET_BAD_REQUEST', \
                  'OFPET_BAD_ACTION', 'OFPET_FLOW_MOD_FAILED', \
                  'OFPET_PORT_MOD_FAILED', 'OFPET_QUEUE_OP_FAILED']
OFPET_HELLO_FAILED                  = 0
OFPET_BAD_REQUEST                   = 1
OFPET_BAD_ACTION                    = 2
OFPET_FLOW_MOD_FAILED               = 3
OFPET_PORT_MOD_FAILED               = 4
OFPET_QUEUE_OP_FAILED               = 5
ofp_error_type_map = {
    0                               : 'OFPET_HELLO_FAILED',
    1                               : 'OFPET_BAD_REQUEST',
    2                               : 'OFPET_BAD_ACTION',
    3                               : 'OFPET_FLOW_MOD_FAILED',
    4                               : 'OFPET_PORT_MOD_FAILED',
    5                               : 'OFPET_QUEUE_OP_FAILED'
}

ofp_hello_failed_code = ['OFPHFC_INCOMPATIBLE', 'OFPHFC_EPERM']
OFPHFC_INCOMPATIBLE                 = 0
OFPHFC_EPERM                        = 1
ofp_hello_failed_code_map = {
    0                               : 'OFPHFC_INCOMPATIBLE',
    1                               : 'OFPHFC_EPERM'
}

ofp_bad_request_code = ['OFPBRC_BAD_VERSION', 'OFPBRC_BAD_TYPE', \
                        'OFPBRC_BAD_STAT', 'OFPBRC_BAD_VENDOR', \
                        'OFPBRC_BAD_SUBTYPE', 'OFPBRC_EPERM', \
                        'OFPBRC_BAD_LEN', 'OFPBRC_BUFFER_EMPTY', \
                        'OFPBRC_BUFFER_UNKNOWN']
OFPBRC_BAD_VERSION                  = 0
OFPBRC_BAD_TYPE                     = 1
OFPBRC_BAD_STAT                     = 2
OFPBRC_BAD_VENDOR                   = 3
OFPBRC_BAD_SUBTYPE                  = 4
OFPBRC_EPERM                        = 5
OFPBRC_BAD_LEN                      = 6
OFPBRC_BUFFER_EMPTY                 = 7
OFPBRC_BUFFER_UNKNOWN               = 8
ofp_bad_request_code_map = {
    0                               : 'OFPBRC_BAD_VERSION',
    1                               : 'OFPBRC_BAD_TYPE',
    2                               : 'OFPBRC_BAD_STAT',
    3                               : 'OFPBRC_BAD_VENDOR',
    4                               : 'OFPBRC_BAD_SUBTYPE',
    5                               : 'OFPBRC_EPERM',
    6                               : 'OFPBRC_BAD_LEN',
    7                               : 'OFPBRC_BUFFER_EMPTY',
    8                               : 'OFPBRC_BUFFER_UNKNOWN'
}

ofp_bad_action_code = ['OFPBAC_BAD_TYPE', 'OFPBAC_BAD_LEN', \
                       'OFPBAC_BAD_VENDOR', 'OFPBAC_BAD_VENDOR_TYPE', \
                       'OFPBAC_BAD_OUT_PORT', 'OFPBAC_BAD_ARGUMENT', \
                       'OFPBAC_EPERM', 'OFPBAC_TOO_MANY', 'OFPBAC_BAD_QUEUE']
OFPBAC_BAD_TYPE                     = 0
OFPBAC_BAD_LEN                      = 1
OFPBAC_BAD_VENDOR                   = 2
OFPBAC_BAD_VENDOR_TYPE              = 3
OFPBAC_BAD_OUT_PORT                 = 4
OFPBAC_BAD_ARGUMENT                 = 5
OFPBAC_EPERM                        = 6
OFPBAC_TOO_MANY                     = 7
OFPBAC_BAD_QUEUE                    = 8
ofp_bad_action_code_map = {
    0                               : 'OFPBAC_BAD_TYPE',
    1                               : 'OFPBAC_BAD_LEN',
    2                               : 'OFPBAC_BAD_VENDOR',
    3                               : 'OFPBAC_BAD_VENDOR_TYPE',
    4                               : 'OFPBAC_BAD_OUT_PORT',
    5                               : 'OFPBAC_BAD_ARGUMENT',
    6                               : 'OFPBAC_EPERM',
    7                               : 'OFPBAC_TOO_MANY',
    8                               : 'OFPBAC_BAD_QUEUE'
}

ofp_flow_mod_failed_code = ['OFPFMFC_ALL_TABLES_FULL', 'OFPFMFC_OVERLAP', \
                            'OFPFMFC_EPERM', 'OFPFMFC_BAD_EMERG_TIMEOUT', \
                            'OFPFMFC_BAD_COMMAND', 'OFPFMFC_UNSUPPORTED']
OFPFMFC_ALL_TABLES_FULL             = 0
OFPFMFC_OVERLAP                     = 1
OFPFMFC_EPERM                       = 2
OFPFMFC_BAD_EMERG_TIMEOUT           = 3
OFPFMFC_BAD_COMMAND                 = 4
OFPFMFC_UNSUPPORTED                 = 5
ofp_flow_mod_failed_code_map = {
    0                               : 'OFPFMFC_ALL_TABLES_FULL',
    1                               : 'OFPFMFC_OVERLAP',
    2                               : 'OFPFMFC_EPERM',
    3                               : 'OFPFMFC_BAD_EMERG_TIMEOUT',
    4                               : 'OFPFMFC_BAD_COMMAND',
    5                               : 'OFPFMFC_UNSUPPORTED'
}

ofp_port_mod_failed_code = ['OFPPMFC_BAD_PORT', 'OFPPMFC_BAD_HW_ADDR']
OFPPMFC_BAD_PORT                    = 0
OFPPMFC_BAD_HW_ADDR                 = 1
ofp_port_mod_failed_code_map = {
    0                               : 'OFPPMFC_BAD_PORT',
    1                               : 'OFPPMFC_BAD_HW_ADDR'
}

ofp_queue_op_failed_code = ['OFPQOFC_BAD_PORT', 'OFPQOFC_BAD_QUEUE', \
                            'OFPQOFC_EPERM']
OFPQOFC_BAD_PORT                    = 0
OFPQOFC_BAD_QUEUE                   = 1
OFPQOFC_EPERM                       = 2
ofp_queue_op_failed_code_map = {
    0                               : 'OFPQOFC_BAD_PORT',
    1                               : 'OFPQOFC_BAD_QUEUE',
    2                               : 'OFPQOFC_EPERM'
}

#5. Symmetric Messages
class ofp_hello:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_HELLO
        self.header.length = len(self)

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        return outstr

class ofp_echo_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_ECHO_REQUEST
        self.body= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        for i in self.body:
            packed += struct.pack("!B",i)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        # Note that we trust the header to be correct here
        if len(binaryString) < self.header.length:
            return binaryString
        l = self.header.length - 8
        # Must be a better way to do this (array?)...
        self.body = list(struct.unpack_from(str(l) + "B", binaryString, 8))
        return binaryString[8 + l:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        l += len(self.body)*1
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.body !=  other.body: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'body: ' + str(self.body) + '\n'
        return outstr

class ofp_echo_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_ECHO_REPLY
        self.body= []

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        for i in self.body:
            packed += struct.pack("!B",i)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        # Note that we trust the header to be correct here
        if len(binaryString) < self.header.length:
            return binaryString
        l = self.header.length - 8
        # Must be a better way to do this (array?)...
        self.body = list(struct.unpack_from(str(l) + "B", binaryString, 8))
        return binaryString[8 + l:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        l += len(self.body)*1
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.body !=  other.body: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'body: ' + str(self.body) + '\n'
        return outstr

class ofp_vendor_header:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_VENDOR
        self.vendor = 0

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!L", self.vendor)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.vendor,) = struct.unpack_from("!L", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.vendor !=  other.vendor: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'vendor: ' + str(self.vendor) + '\n'
        return outstr

class ofp_vendor:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_VENDOR
        self.vendor = 0
        self.data = ''

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!L", self.vendor)
        packet += self.data
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.vendor,) = struct.unpack_from("!L", binaryString, 8)
        if len(binaryString < self.header.length):
            return binaryString
        self.data = binaryString[12:self.header.length]
        return binaryString[self.header.length:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        l += len(self.data)
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.vendor !=  other.vendor: return False
        if self.data != other.data: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'vendor: ' + str(self.vendor) + '\n'
        outstr += prefix + 'data: ' + data + '\n'
        return outstr

class ofp_features_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_FEATURES_REQUEST
        self.header.length = 8

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        return outstr

class ofp_get_config_request:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_GET_CONFIG_REQUEST

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 8):
            return binaryString
        self.header.unpack(binaryString[0:])
        return binaryString[8:]

    def __len__(self):
        """Return length of message
        """
        l = 8
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        return outstr

class ofp_get_config_reply:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_GET_CONFIG_REPLY
        self.flags = 0
        self.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!HH", self.flags, self.miss_send_len)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.flags, self.miss_send_len) = struct.unpack_from("!HH", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.flags !=  other.flags: return False
        if self.miss_send_len !=  other.miss_send_len: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'flags: ' + str(self.flags) + '\n'
        outstr += prefix + 'miss_send_len: ' + str(self.miss_send_len) + '\n'
        return outstr

class ofp_set_config:
    def __init__(self):
        """Initialize
        Declare members and default values
        """
        self.header = ofp_header()
        self.header.type = OFPT_SET_CONFIG
        self.flags = 0
        self.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN

    def __assert(self):
        """Sanity check
        """
        if(not isinstance(self.header, ofp_header)):
            return (False, "self.header is not class ofp_header as expected.")
        return (True, None)

    def pack(self, assertstruct=True):
        """Pack message
        Packs empty array used as placeholder
        """
        if(assertstruct):
            if(not self.__assert()[0]):
                return None
        packed = ""
        packed += self.header.pack()
        packed += struct.pack("!HH", self.flags, self.miss_send_len)
        return packed

    def unpack(self, binaryString):
        """Unpack message
        Do not unpack empty array used as placeholder
        since they can contain heterogeneous type
        """
        if (len(binaryString) < 12):
            return binaryString
        self.header.unpack(binaryString[0:])
        (self.flags, self.miss_send_len) = struct.unpack_from("!HH", binaryString, 8)
        return binaryString[12:]

    def __len__(self):
        """Return length of message
        """
        l = 12
        return l

    def __eq__(self, other):
        """Return True if self and other have same values
        """
        if type(self) != type(other): return False
        if self.header !=  other.header: return False
        if self.flags !=  other.flags: return False
        if self.miss_send_len !=  other.miss_send_len: return False
        return True

    def __ne__(self, other): return not self.__eq__(other)

    def show(self, prefix=''):
        """Generate string showing basic members of structure
        """
        outstr = ''
        outstr += prefix + 'header: \n'
        self.header.show(prefix + '  ')
        outstr += prefix + 'flags: ' + str(self.flags) + '\n'
        outstr += prefix + 'miss_send_len: ' + str(self.miss_send_len) + '\n'
        return outstr




ofp_port = ['OFPP_MAX', 'OFPP_IN_PORT', 'OFPP_TABLE', 'OFPP_NORMAL', \
            'OFPP_FLOOD', 'OFPP_ALL', 'OFPP_CONTROLLER', 'OFPP_LOCAL', \
            'OFPP_NONE']
OFPP_MAX                            = 65280
OFPP_IN_PORT                        = 65528
OFPP_TABLE                          = 65529
OFPP_NORMAL                         = 65530
OFPP_FLOOD                          = 65531
OFPP_ALL                            = 65532
OFPP_CONTROLLER                     = 65533
OFPP_LOCAL                          = 65534
OFPP_NONE                           = 65535
ofp_port_map = {
    65280                           : 'OFPP_MAX',
    65528                           : 'OFPP_IN_PORT',
    65529                           : 'OFPP_TABLE',
    65530                           : 'OFPP_NORMAL',
    65531                           : 'OFPP_FLOOD',
    65532                           : 'OFPP_ALL',
    65533                           : 'OFPP_CONTROLLER',
    65534                           : 'OFPP_LOCAL',
    65535                           : 'OFPP_NONE'
}

ofp_type = ['OFPT_HELLO', 'OFPT_ERROR', 'OFPT_ECHO_REQUEST', \
            'OFPT_ECHO_REPLY', 'OFPT_VENDOR', 'OFPT_FEATURES_REQUEST', \
            'OFPT_FEATURES_REPLY', 'OFPT_GET_CONFIG_REQUEST', \
            'OFPT_GET_CONFIG_REPLY', 'OFPT_SET_CONFIG', 'OFPT_PACKET_IN', \
            'OFPT_FLOW_REMOVED', 'OFPT_PORT_STATUS', 'OFPT_PACKET_OUT', \
            'OFPT_FLOW_MOD', 'OFPT_PORT_MOD', 'OFPT_STATS_REQUEST', \
            'OFPT_STATS_REPLY', 'OFPT_BARRIER_REQUEST', 'OFPT_BARRIER_REPLY', \
            'OFPT_QUEUE_GET_CONFIG_REQUEST', 'OFPT_QUEUE_GET_CONFIG_REPLY']
OFPT_HELLO                          = 0
OFPT_ERROR                          = 1
OFPT_ECHO_REQUEST                   = 2
OFPT_ECHO_REPLY                     = 3
OFPT_VENDOR                         = 4
OFPT_FEATURES_REQUEST               = 5
OFPT_FEATURES_REPLY                 = 6
OFPT_GET_CONFIG_REQUEST             = 7
OFPT_GET_CONFIG_REPLY               = 8
OFPT_SET_CONFIG                     = 9
OFPT_PACKET_IN                      = 10
OFPT_FLOW_REMOVED                   = 11
OFPT_PORT_STATUS                    = 12
OFPT_PACKET_OUT                     = 13
OFPT_FLOW_MOD                       = 14
OFPT_PORT_MOD                       = 15
OFPT_STATS_REQUEST                  = 16
OFPT_STATS_REPLY                    = 17
OFPT_BARRIER_REQUEST                = 18
OFPT_BARRIER_REPLY                  = 19
OFPT_QUEUE_GET_CONFIG_REQUEST       = 20
OFPT_QUEUE_GET_CONFIG_REPLY         = 21
ofp_type_map = {
    0                               : 'OFPT_HELLO',
    1                               : 'OFPT_ERROR',
    2                               : 'OFPT_ECHO_REQUEST',
    3                               : 'OFPT_ECHO_REPLY',
    4                               : 'OFPT_VENDOR',
    5                               : 'OFPT_FEATURES_REQUEST',
    6                               : 'OFPT_FEATURES_REPLY',
    7                               : 'OFPT_GET_CONFIG_REQUEST',
    8                               : 'OFPT_GET_CONFIG_REPLY',
    9                               : 'OFPT_SET_CONFIG',
    10                              : 'OFPT_PACKET_IN',
    11                              : 'OFPT_FLOW_REMOVED',
    12                              : 'OFPT_PORT_STATUS',
    13                              : 'OFPT_PACKET_OUT',
    14                              : 'OFPT_FLOW_MOD',
    15                              : 'OFPT_PORT_MOD',
    16                              : 'OFPT_STATS_REQUEST',
    17                              : 'OFPT_STATS_REPLY',
    18                              : 'OFPT_BARRIER_REQUEST',
    19                              : 'OFPT_BARRIER_REPLY',
    20                              : 'OFPT_QUEUE_GET_CONFIG_REQUEST',
    21                              : 'OFPT_QUEUE_GET_CONFIG_REPLY'
}

# Values from macro definitions
OFP_FLOW_PERMANENT = 0
OFP_DL_TYPE_ETH2_CUTOFF = 0x0600
DESC_STR_LEN = 256
OFPFW_ICMP_CODE = OFPFW_TP_DST
OFPQ_MIN_RATE_UNCFG = 0xffff
OFP_VERSION = 0x01
OFP_MAX_TABLE_NAME_LEN = 32
OFP_DL_TYPE_NOT_ETH_TYPE = 0x05ff
OFP_DEFAULT_MISS_SEND_LEN = 128
OFP_MAX_PORT_NAME_LEN = 16
OFP_SSL_PORT = 6633
OFPFW_ICMP_TYPE = OFPFW_TP_SRC
OFP_TCP_PORT = 6633
SERIAL_NUM_LEN = 32
OFP_DEFAULT_PRIORITY = 0x8000
OFP_ETH_ALEN = 6
OFP_VLAN_NONE = 0xffff
OFPQ_ALL = 0xffffffff

# Basic structure size definitions.
OFP_ACTION_DL_ADDR_BYTES = 16
OFP_ACTION_ENQUEUE_BYTES = 16
OFP_ACTION_HEADER_BYTES = 8
OFP_ACTION_NW_ADDR_BYTES = 8
OFP_ACTION_NW_TOS_BYTES = 8
OFP_ACTION_OUTPUT_BYTES = 8
OFP_ACTION_TP_PORT_BYTES = 8
OFP_ACTION_VENDOR_HEADER_BYTES = 8
OFP_ACTION_VLAN_PCP_BYTES = 8
OFP_ACTION_VLAN_VID_BYTES = 8
OFP_AGGREGATE_STATS_REPLY_BYTES = 24
OFP_AGGREGATE_STATS_REQUEST_BYTES = 44
OFP_DESC_STATS_BYTES = 1056
OFP_ERROR_MSG_BYTES = 12
OFP_FLOW_MOD_BYTES = 72
OFP_FLOW_REMOVED_BYTES = 88
OFP_FLOW_STATS_BYTES = 88
OFP_FLOW_STATS_REQUEST_BYTES = 44
OFP_HEADER_BYTES = 8
OFP_HELLO_BYTES = 8
OFP_MATCH_BYTES = 40
OFP_PACKET_IN_BYTES = 18
OFP_PACKET_OUT_BYTES = 16
OFP_PACKET_QUEUE_BYTES = 8
OFP_PHY_PORT_BYTES = 48
OFP_PORT_MOD_BYTES = 32
OFP_PORT_STATS_BYTES = 104
OFP_PORT_STATS_REQUEST_BYTES = 8
OFP_PORT_STATUS_BYTES = 64
OFP_QUEUE_GET_CONFIG_REPLY_BYTES = 16
OFP_QUEUE_GET_CONFIG_REQUEST_BYTES = 12
OFP_QUEUE_PROP_HEADER_BYTES = 8
OFP_QUEUE_PROP_MIN_RATE_BYTES = 16
OFP_QUEUE_STATS_BYTES = 32
OFP_QUEUE_STATS_REQUEST_BYTES = 8
OFP_STATS_REPLY_BYTES = 12
OFP_STATS_REQUEST_BYTES = 12
OFP_SWITCH_CONFIG_BYTES = 12
OFP_SWITCH_FEATURES_BYTES = 32
OFP_TABLE_STATS_BYTES = 64
OFP_VENDOR_HEADER_BYTES = 12

ofp_match_data = {
#  'wildcards' : (0, 0),
  'in_port' : (0, OFPFW_IN_PORT),
  'dl_src' : ([0,0,0,0,0,0], OFPFW_DL_SRC),
  'dl_dst' : ([0,0,0,0,0,0], OFPFW_DL_DST),
  'dl_vlan' : (0, OFPFW_DL_VLAN),
  'dl_vlan_pcp' : (0, OFPFW_DL_VLAN_PCP),
  'pad1' : ([0], 0),
  'dl_type' : (0, OFPFW_DL_TYPE),
  'nw_tos' : (0, OFPFW_NW_TOS),
  'nw_proto' : (0, OFPFW_NW_PROTO),
  'pad2' : ([0,0], 0),
  'nw_src' : (0, OFPFW_NW_SRC_ALL),
  'nw_dst' : (0, OFPFW_NW_DST_ALL),
  'tp_src' : (0, OFPFW_TP_SRC),
  'tp_dst' : (0, OFPFW_TP_DST),
}