# Copyright 2012 James McCauley
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

# For lots of documentation, see Open vSwitch's nicira-ext.h and ofp-msgs.h


from pox.core import core
from pox.lib.util import initHelper
from pox.lib.util import hexdump
from pox.lib.addresses import parse_cidr, IPAddr, EthAddr

import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import ofp_header, ofp_vendor_base
from pox.openflow.libopenflow_01 import _PAD, _PAD2, _PAD4, _PAD6
from pox.openflow.libopenflow_01 import _unpack, _read, _skip

import struct


NX_VENDOR_ID = 0x00002320

def _init_constants ():
  actions = [
    "NXAST_SNAT__OBSOLETE",
    "NXAST_RESUBMIT",
    "NXAST_SET_TUNNEL",
    "NXAST_DROP_SPOOFED_ARP__OBSOLETE",
    "NXAST_SET_QUEUE",
    "NXAST_POP_QUEUE",
    "NXAST_REG_MOVE",
    "NXAST_REG_LOAD",
    "NXAST_NOTE",
    "NXAST_SET_TUNNEL64",
    "NXAST_MULTIPATH",
    "NXAST_AUTOPATH__DEPRECATED",
    "NXAST_BUNDLE",
    "NXAST_BUNDLE_LOAD",
    "NXAST_RESUBMIT_TABLE",
    "NXAST_OUTPUT_REG",
    "NXAST_LEARN",
    "NXAST_EXIT",
    "NXAST_DEC_TTL",
    "NXAST_FIN_TIMEOUT",
    "NXAST_CONTROLLER",
    "NXAST_DEC_TTL_CNT_IDS",
  ]
  for i,name in enumerate(actions):
    globals()[name] = i

_init_constants()

NXT_ROLE_REQUEST = 10
NXT_ROLE_REPLY = 11
NXT_SET_FLOW_FORMAT = 12
NXT_FLOW_MOD = 13
NXT_FLOW_MOD_TABLE_ID = 15
NXT_SET_PACKET_IN_FORMAT = 16
NXT_FLOW_AGE = 18
NXT_SET_CONTROLLER_ID = 20
NXT_FLOW_MONITOR_CANCEL = 21
NXT_FLOW_MONITOR_PAUSED = 22
NXT_FLOW_MONITOR_RESUMED = 23
NXST_FLOW_MONITOR_REQUEST = 2
NXST_FLOW_MONITOR_REPLY = 2


def _issubclass (a, b):
  try:
    return issubclass(a, b)
  except TypeError:
    return False


class nicira_base (ofp_vendor_base):
  """
  Base class for Nicira extensions
  """
  _MIN_LENGTH = 16
  vendor = NX_VENDOR_ID
  #subtype = None # Set

  def _eq (self, other):
    """
    Return True if equal

    Overide this.
    """
    return True

  def _init (self, kw):
    """
    Initialize fields

    Overide this.
    """
    pass

  def _pack_body (self):
    """
    Pack body.
    """
    return b""

  def _unpack_body (self, raw, offset, avail):
    """
    Unpack body in raw starting at offset.

    Return new offset
    """
    return offset

  def _body_length (self):
    """
    Return length of body.

    Optionally override this.
    """
    return len(self._pack_body())

  def _show (self, prefix):
    """
    Format additional fields as text
    """
    return ""

  def __init__ (self, **kw):
    ofp_vendor_base.__init__(self)
    self._init(kw)
    assert hasattr(self, 'vendor')
    assert hasattr(self, 'subtype')
    initHelper(self, kw)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += ofp_vendor_base.pack(self)
    packed += struct.pack("!LL", self.vendor, self.subtype)
    packed += self._pack_body()
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset,(self.vendor,self.subtype) = _unpack("!LL", raw, offset)
    offset = self._unpack_body(raw, offset, length-16)
    return offset,length

  def __len__ (self):
    return 16 + self._body_length()

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not ofp_vendor_base.__eq__(self, other): return False
    if self.vendor != other.vendor: return False
    if self.subtype != other.subtype: return False
    return self._eq(other)

  def __ne__ (self, other): return not self.__eq__(other)

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += ofp_vendor_base.show(self, prefix + '  ')
    outstr += prefix + 'vendor: ' + str(self.vendor) + '\n'
    outstr += prefix + 'subtype: ' + len(self.subtype) + '\n'
    outstr += self._show(prefix)
    return outstr


class nx_flow_mod_table_id (nicira_base):
  """
  Used to enable the flow mod table ID extension

  When this is enabled, a slightly altered ofp_flow_mod can be used
  to set the table for a flow insertion.  A convenient version of this
  slightly altered flow_mod is available as ofp_flow_mod_table_id.
  """
  subtype = NXT_FLOW_MOD_TABLE_ID
  _MIN_LENGTH = 16 + 8

  def _init (self, kw):
    self.enable = True # Called "set" by OVS

  def _eq (self, other):
    """
    Return True if equal

    Overide this.
    """
    return self.enable == other.enable

  def _pack_body (self):
    """
    Pack body.
    """
    return struct.pack("!B", 1 if self.enable else 0) + (of._PAD * 7)

  def _unpack_body (self, raw, offset, avail):
    """
    Unpack body in raw starting at offset.

    Return new offset
    """
    offset,enable = of._unpack("!B", raw, offset)
    offset = of._skip(raw, offset, 7)
    self.enable = True if enable else False
    return offset

  def _body_length (self):
    """
    Return length of body.

    Optionally override this.
    """
    return len(self._pack_body())

  def _show (self, prefix):
    """
    Format additional fields as text
    """
    return prefix + "set: " + str(self.enable) + "\n"


class ofp_flow_mod_table_id (of.ofp_flow_mod):
  """
  A subclass of ofp_flow_mod which has a table_id

  This is for use with the NXT_FLOW_MOD_TABLE_ID extension.
  """
  #TODO: It'd be nice if this were a cleaner subclass of the original,
  #      but it didn't really lend itself to subclassing.
  def __init__ (self, **kw):
    self.table_id = 0xff
    of.ofp_flow_mod.__init__(self, **kw)

  @property
  def _command (self):
    return chr(self.table_id) + chr(self.command)

  @_command.setter
  def _command (self, v):
    self.table_id = ord(v[0])
    self.command = ord(v[1])

  # Unfortunately, there's no clean way to reuse a lot of the superclass,
  # so we copy and paste...  Gross.
  # (Might be worth tweaking the superclass to make this cleaner.)
  def pack (self):
    """
    Packs this object into its wire format.
    May normalize fields.
    NOTE: If "data" has been specified, this method may actually return
          *more than just a single ofp_flow_mod* in packed form.
          Specifically, it may also have a barrier and an ofp_packet_out.
    """
    po = None
    if self.data:
      #TODO: It'd be nice to log and then ignore if not data_is_complete.
      #      Unfortunately, we currently have no logging in here, so we
      #      assert instead which is a either too drastic or too quiet.
      assert self.data.is_complete
      assert self.buffer_id is None
      self.buffer_id = self.data.buffer_id
      if self.buffer_id is None:
        po = ofp_packet_out(data=self.data)
        po.in_port = self.data.in_port
        po.actions.append(ofp_action_output(port = OFPP_TABLE))
        # Should maybe check that packet hits the new entry...
        # Or just duplicate the actions? (I think that's the best idea)

    assert self._assert()
    packed = b""
    packed += ofp_header.pack(self)
    packed += self.match.pack(flow_mod=True)
    packed += struct.pack("!QHHHHLHH", self.cookie, self._command,
                          self.idle_timeout, self.hard_timeout,
                          self.priority, self._buffer_id, self.out_port,
                          self.flags)
    for i in self.actions:
      packed += i.pack()

    if po:
      packed += ofp_barrier_request().pack()
      packed += po.pack()
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset = self.match.unpack(raw, offset, flow_mod=True)
    offset,(self.cookie, self._command, self.idle_timeout,
            self.hard_timeout, self.priority, self._buffer_id,
            self.out_port, self.flags) = \
            _unpack("!QHHHHLHH", raw, offset)
    offset,self.actions = _unpack_actions(raw,
        length-(32 + len(self.match)), offset)
    assert length == len(self)
    return offset,length

  def __eq__ (self, other):
    r = of.ofp_flow_mod(self, other)
    if r:
      if self.table_id != other.table_id: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += ofp_header.show(self, prefix + '  ')
    outstr += prefix + 'match: \n'
    outstr += self.match.show(prefix + '  ')
    outstr += prefix + 'cookie: ' + str(self.cookie) + '\n'
    outstr += prefix + 'command: ' + str(self.command) + '\n'
    outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
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


class nx_flow_mod (of.ofp_flow_mod, of.ofp_vendor_base):
  """
  A flow mod command that uses Nicira extended matches

  This has a table_id attribute, which only works if you have enabled
  the nx_flow_mod_table_id option.
  """
  _MIN_LENGTH = 32
  header_type = of.OFPT_VENDOR
  vendor = NX_VENDOR_ID
  subtype = NXT_FLOW_MOD

  def __init__ (self, **kw):
    self.table_id = 0
    of.ofp_flow_mod.__init__(self, **kw)

    if 'match' not in kw:
      # Superclass created an ofp_match -- replace it
      self.match = nx_match()

  def _validate (self):
    if not isinstance(self.match, nx_match):
      return "match is not class ofp_match"
    return None

  def pack (self):
    """
    Packs this object into its wire format.
    May normalize fields.
    NOTE: If "data" has been specified, this method may actually return
          *more than just a single ofp_flow_mod* in packed form.
          Specifically, it may also have a barrier and an ofp_packet_out.
    """
    po = None
    if self.data:
      #TODO: It'd be nice to log and then ignore if not data_is_complete.
      #      Unfortunately, we currently have no logging in here, so we
      #      assert instead which is a either too drastic or too quiet.
      assert self.data.is_complete
      assert self.buffer_id is None
      self.buffer_id = self.data.buffer_id
      if self.buffer_id is None:
        po = ofp_packet_out(data=self.data)
        po.in_port = self.data.in_port
        po.actions.append(ofp_action_output(port = OFPP_TABLE))
        # Should maybe check that packet hits the new entry...
        # Or just duplicate the actions? (I think that's the best idea)

    assert self._assert()
    match = self.match.pack()
    match_len = len(match)

    command = self.command
    command |= (self.table_id << 8)

    packed = b""
    packed += ofp_header.pack(self)
    packed += struct.pack("!LL", self.vendor, self.subtype)
    packed += struct.pack("!QHHHHLHHH", self.cookie, command,
                          self.idle_timeout, self.hard_timeout,
                          self.priority, self._buffer_id, self.out_port,
                          self.flags, match_len)
    packed += _PAD6
    packed += match
    packed += _PAD * ((match_len + 7)/8*8 - match_len)
    for i in self.actions:
      packed += i.pack()

    if po:
      packed += ofp_barrier_request().pack()
      packed += po.pack()

    assert len(packed) == len(self)

    return packed

  def unpack (self, raw, offset=0):
    _o = offset
    offset,length = self._unpack_header(raw, offset)
    offset,(vendor,subtype) = _unpack("!LL", raw, offset)
    offset,(self.cookie, self.command, self.idle_timeout,
            self.hard_timeout, self.priority, self._buffer_id,
            self.out_port, self.flags, match_len) = \
            _unpack("!QHHHHLHHH", raw, offset)
    offset = self._skip(raw, offset, 6)
    offset = self.match.unpack(raw, offset, match_len)
    offset,self.actions = of._unpack_actions(raw,
        length-(offset - _o), offset)
    assert length == len(self)
    return offset,length

  def __len__ (self):
    match_len = len(self.match)
    l = 8 + 4 + 4
    l += 8 + 2 + 2 + 2 + 2 + 4 + 2 + 2
    l += 2 # match_len
    l += 6 # pad
    l += match_len
    l += (match_len + 7)//8*8 - match_len
    for i in self.actions:
      l += len(i)
    return l


# Packet_in formats
NXPIF_OPENFLOW10 = 0 # Standard OpenFlow 1.0 packet_in format
NXPIF_NXM = 1        # Nicira Extended packet_in format

class nx_packet_in_format (nicira_base):
  subtype = NXT_SET_PACKET_IN_FORMAT
  _MIN_LENGTH = 16 + 4

  def _init (self, kw):
    self.format = NXPIF_NXM # Extended packet_in format

  def _eq (self, other):
    """
    Return True if equal

    Overide this.
    """
    return self.format == other.format

  def _pack_body (self):
    """
    Pack body.
    """
    return struct.pack("!L", self.format)

  def _unpack_body (self, raw, offset, avail):
    """
    Unpack body in raw starting at offset.

    Return new offset
    """
    offset,self.format = of._unpack("!L", raw, offset)
    return offset

  def _show (self, prefix):
    """
    Format additional fields as text
    """
    s = prefix + "format: "
    if self.format == NXPIF_NXM:
      s += "NXM"
    elif self.format == NXPIF_OPENFLOW10:
      s += "OF1.0"
    else:
      s += str(self.format)
    return s + "\n"


class nx_output_reg (of.ofp_action_vendor_base):
  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_OUTPUT_REG
    self.offset = 0
    self.nbits = None
    self.reg = None # an nxm_entry class
    self.max_len = 0

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    if self.offset != other.offset: return False
    if self.nbits != other.nbits: return False
    if self.reg != other.reg: return False
    if self.max_len != other.max_len: return False
    return True

  def _pack_body (self):
    nbits = self.nbits - 1
    assert nbits >= 0 and nbits <= 63
    assert self.offset >= 0 and self.offset < (1 << 10)
    ofs_nbits = self.offset << 6 | nbits

    o = self.reg()
    o._force_mask = False
    reg = o.pack(omittable=False, header_only=True)

    p = struct.pack('!HH4sH', self.subtype, ofs_nbits, reg, self.max_len)
    p += _PAD6
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype, ofs_nbits, reg, self.max_len, _, _) = \
        of._unpack('!HH4sHHI', raw, offset)

    self.offset = ofs_nbits >> 6
    self.nbits = (ofs_nbits & 0x3f) + 1

    self.reg = _class_for_nxm_header(reg)

    return offset

  def _body_length (self):
    return 16

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    s += prefix + ('offset: %s\n' % (self.offset,))
    s += prefix + ('nbits: %s\n' % (self.nbits,))
    s += prefix + ('reg: %s\n' % (self.reg,))
    s += prefix + ('max_len: %s\n' % (self.max_len,))
    return s


class nx_reg_move (of.ofp_action_vendor_base):
  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_REG_MOVE
    self.nbits = None
    self.dst = None # an nxm_entry class
    self.dst_ofs = 0
    self.src = None # an nxm_entry_class
    self.src_ofs = 0

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    if self.nbits != other.nbits: return False
    if self.dst != other.dst: return False
    if self.dst_ofs != other.dst_ofs: return False
    if self.src != other.src: return False
    if self.src_ofs != other.src_ofs: return False
    return True

  def _pack_body (self):
    o = self.dst()
    o._force_mask = False
    dst = o.pack(omittable=False, header_only=True)

    o = self.src()
    o._force_mask = False
    src = o.pack(omittable=False, header_only=True)

    p = struct.pack('!HHHH4s4s', self.subtype, self.nbits, self.src_ofs, 
            self.dst_ofs, src, dst)
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype,self.nbits, self.src_ofs, self.dst_ofs, src, dst) = \
        of._unpack('!HHHH4s4s', raw, offset)

    self.dst = _class_for_nxm_header(dst)

    self.src = _class_for_nxm_header(src)

    return offset

  def _body_length (self):
    return 16

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    s += prefix + ('offset: %s\n' % (self.offset,))
    s += prefix + ('nbits: %s\n' % (self.nbits,))
    s += prefix + ('src_ofs: %s\n' % (self.src_ofs,))
    s += prefix + ('dst_ofs: %s\n' % (self.dst_ofs,))
    s += prefix + ('src: %s\n' % (self.src,))
    s += prefix + ('dst: %s\n' % (self.dst,))
    return s


class nx_reg_load (of.ofp_action_vendor_base):
  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_REG_LOAD
    self.offset = 0
    self.nbits = None
    self.dst = None # an nxm_entry class
    self.value = 0

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    if self.offset != other.offset: return False
    if self.nbits != other.nbits: return False
    if self.dst != other.dst: return False
    if self.value != other.value: return False
    return True

  def _pack_body (self):
    nbits = self.nbits - 1
    assert nbits >= 0 and nbits <= 63
    assert self.offset >= 0 and self.offset < (1 << 10)
    ofs_nbits = self.offset << 6 | nbits

    o = self.dst()
    o._force_mask = False
    dst = o.pack(omittable=False, header_only=True)

    p = struct.pack('!HH4sQ', self.subtype, ofs_nbits, dst, self.value)
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype,ofs_nbits, dst, self.value) = \
        of._unpack('!HH4sQ', raw, offset)

    self.offset = ofs_nbits >> 6
    self.nbits = (ofs_nbits & 0x3f) + 1

    self.dst = _class_for_nxm_header(dst)

    return offset

  def _body_length (self):
    return 16

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    s += prefix + ('offset: %s\n' % (self.offset,))
    s += prefix + ('nbits: %s\n' % (self.nbits,))
    s += prefix + ('dst: %s\n' % (self.dst,))
    s += prefix + ('value: %s\n' % (self.value,))
    return s


class nx_action_dec_ttl (of.ofp_action_vendor_base):
  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_DEC_TTL

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    return True

  def _pack_body (self):
    p = struct.pack('!H', self.subtype)
    p += of._PAD6
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype,) = of._unpack('!H', raw, offset)
    offset = of._skip(raw, offset, 6)
    return offset

  def _body_length (self):
    return 8

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    return s


class nx_action_resubmit (of.ofp_action_vendor_base):
  """
  Used with both resubmit and resubmit_table.

  Generally, you want to use one of the factory methods.
  """
  @classmethod
  def resubmit (cls, in_port = of.OFPP_IN_PORT):
    return cls(subtype = NXAST_RESUBMIT, in_port = in_port, table = 0)

  @classmethod
  def resubmit_table (cls, table = 255, in_port = of.OFPP_IN_PORT):
    return cls(subtype = NXAST_RESUBMIT_TABLE, in_port = in_port,
               table = table)

  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_RESUBMIT
    self.in_port = None # New in_port for checking flow table
    self.table = None   # NXAST_RESUBMIT_TABLE: table to use

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    if self.in_port != other.in_port: return False
    if self.table != other.table: return False
    return True

  def _pack_body (self):
    p = struct.pack('!HHB', self.subtype, self.in_port, self.table)
    p += of._PAD3
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype,self.in_port,self.table) = \
        of._unpack('!HHB', raw, offset)
    offset = of._skip(raw, offset, 3)
    return offset

  def _body_length (self):
    return 8

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    s += prefix + ('in_port: %s\n' % (self.in_port,))
    s += prefix + ('table: %s\n' % (self.table,))
    return s


class nx_action_fin_timeout (of.ofp_action_vendor_base):
  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_FIN_TIMEOUT
    self.fin_idle_timeout = 1 # New idle timeout, if nonzero.
    self.fin_hard_timeout = 1 # New hard timeout, if nonzero.

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    if self.fin_idle_timeout != other.fin_idle_timeout: return False
    if self.fin_hard_timeout != other.fin_hard_timeout: return False
    return True

  def _pack_body (self):
    p = struct.pack('!HHH', self.subtype, self.fin_idle_timeout,
                    self.fin_hard_timeout)
    p += of._PAD2
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype,self.fin_idle_timeout,self.fin_hard_timeout) = \
        of._unpack('!HHH', raw, offset)
    offset = of._skip(raw, offset, 2)
    return offset

  def _body_length (self):
    return 8

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    s += prefix + ('fin_idle_timeout: %s\n' % (self.fin_idle_timeout,))
    s += prefix + ('fin_hard_timeout: %s\n' % (self.fin_hard_timeout,))
    return s

class nx_action_exit (of.ofp_action_vendor_base):
  def _init (self, kw):
    self.vendor = NX_VENDOR_ID
    self.subtype = NXAST_EXIT

  def _eq (self, other):
    if self.subtype != other.subtype: return False
    return True

  def _pack_body (self):
    p = struct.pack('!H', self.subtype)
    p += of._PAD6
    return p

  def _unpack_body (self, raw, offset, avail):
    offset,(self.subtype,) = \
        of._unpack('!H', raw, offset)
    offset = of._skip(raw, offset, 6)
    return offset

  def _body_length (self):
    return 8

  def _show (self, prefix):
    s = ''
    s += prefix + ('subtype: %s\n' % (self.subtype,))
    return s



# -----------------------------------------------------------------------
# NXM support
# -----------------------------------------------------------------------

#def conv (n, s):
#  if s == 0: return b''
#  nn = struct.pack("B", n & 0xff)
#  n >>= 8
#  return conv(n, s - 1) + nn

class _nxm_raw (object):
  def _pack_value (self, v):
    return v
  def _unpack_value (self, v):
    return v


class _nxm_numeric (object):
  _size_table = [None, "!B", "!H", None, "!L", None, None, None, "!Q"]

  def _pack_value (self, v):
    size = self._size_table[self._nxm_length]
    return struct.pack(size, v)

  def _unpack_value (self, v):
    try:
      size = self._size_table[self._nxm_length]
      return struct.unpack(size, v)[0]
    except:
      raise RuntimeError("Can't unpack %i bytes for %s"
                         % (self._nxm_length, self.__class__.__name__))

class _nxm_ip (object):
  """
  Allows setting of IP address in many formats

  The value can be any format known by IPAddr.  If it's a string, it can
  also have a trailing /netmask or /cidr-bits.  If it's a tuple, the
  first is assumed to be any kind of IP address and the second is either
  a netmask or the number of network bits.
  """

  @property
  def value (self):
    return self._unpack_value(self._value)
  @value.setter
  def value (self, value):
    if isinstance(value, tuple) or isinstance(value, list):
      assert len(value) == 2
      ip = value[0]
      self.mask = value[1]
      if isinstance(mask, (int,long)):
        self.mask = mask
    elif isinstance(value, basestring) and len(value)>4 and '/' in value:
      temp = parse_cidr(value, infer=False)
      ip = temp[0]
      self.mask = 32 if temp[1] is None else temp[1]
    else:
      ip = value

    self._value = self._pack_value(ip)

  def _pack_value (self, v):
    return IPAddr(v, networkOrder=False).toRaw()
  def _unpack_value (self, v):
    return IPAddr(v, networkOrder=True)
  def _pack_mask (self, v):
    if isinstance(v, (int, long)):
      # Assume CIDR
      if v > 32: v = 32
      elif v < 0: v = 0
      n = (0xffFFffFF << (32-v)) & 0xffFFffFF
      return IPAddr(v, networkOrder=False).toRaw()
    else:
      return IPAddr(v).toRaw()
  #def _unpack_mask (self, v):
  #  # Special unpacking for CIDR-style?


class _nxm_ipv6 (object):
  """
  Placeholder until we have real IPv6 support

  Allows setting of IP address in many formats

  The value can be any format known by IPAddr.  If it's a string, it can
  also have a trailing /netmask or /cidr-bits.  If it's a tuple, the
  first is assumed to be any kind of IP address and the second is either
  a netmask or the number of network bits.
  """
  #TODO: Fix this when IPv6 is available

  @property
  def value (self):
    return self._unpack_value(self._value)
  @value.setter
  def value (self, value):
    if isinstance(value, tuple) or isinstance(value, list):
      assert len(value) == 2
      ip = value[0]
      self.mask = value[1]
      if isinstance(mask, long):
        self.mask = mask
    #TODO
    #elif isinstance(value, unicode) and u'/' in value:
    #  temp = parse_cidr6(value, infer=False)
    #  ip = temp[0]
    #  self.mask = 128 if temp[1] is None else temp[1]
    else:
      ip = value

    self._value = self._pack_value(value)

  def _pack_value (self, v):
    return v
    #return IPAddr6(v).raw
  def _unpack_value (self, v):
    return v
    #return IPAddr6(v, raw=True)
  def _pack_mask (self, v):
    return v
    #if isinstance(v, long):
    #  # Assume CIDR
    #  if v > 128: v = 128
    #  elif v < 0: v = 0
    #  n = (0xffFFffFF << (32-v)) & 0xffFFffFF
    #  return IPAddr6(v, networkOrder=False).toRaw()
    #else:
    #  #return IPAddr6(v).raw
  #def _unpack_mask (self, v):
  #  # Special unpacking for CIDR-style?


class _nxm_ether (object):
  def _pack_value (self, v):
    return EthAddr(v).toRaw()
  def _unpack_value (self, v):
    return EthAddr(v)


_nxm_type_to_class = {}
_nxm_name_to_type = {}

class nxm_entry (object):
  #_nxm_type = _make_type(0x, )
  #_nxm_length = # bytes of data not including mask (double for mask)
  _force_mask = False

  #TODO: make mask-omittable a class-level attribute?

  @property
  def nxm_vendor (self):
    return self._nxm_type >> 7
  @property
  def nxm_field (self):
    return self._nxm_type & 0x7f

  @staticmethod
  def unpack_header (raw, offset):
    """
    Parses the NXM_HEADER

    Returns (type,has_mask,length)
    """
    h, = struct.unpack_from("!L", raw, offset)
    offset += 4
    t = h >> 9
    has_mask = (h & (1<<8)) != 0
    length = h & 0x7f
    return t,has_mask,length

  @staticmethod
  def unpack_new (raw, offset):
    t,has_mask,length = nxm_entry.unpack_header(raw, offset)
    offset += 4
    offset,data = of._read(raw, offset, length)
    mask = None
    if has_mask:
      assert not (length & 1), "Odd length with mask"
      mask = data[length/2:]
      data = data[:length/2]

    #NOTE: Should use _class_for_nxm_header?
    c = _nxm_type_to_class.get(t)
    if c is None:
      e = NXM_GENERIC()
      e._nxm_length = length
      if has_mask:
        e._nxm_length /= 2
      e._nxm_type = t
    else:
      e = c()
    assert data is not None
    assert len(data) == e._nxm_length, "%s != %s" % (len(data), e._nxm_length)
    assert mask is None or len(mask) == e._nxm_length
    e._value = data
    e._mask = mask
    if mask is not None:
      e._force_mask = True

    return offset, e

  def clone (self):
    n = self.__class__()
    n._nxm_type = self._nxm_type
    n._nxm_length = self._nxm_length
    n._force_mask = self._force_mask
    n.mask = self.mask
    n.value = self.value

    return n

  def __init__ (self, value = None, mask = None):
    super(nxm_entry, self).__init__()
    self._value = None
    self._mask = None
    if value is None and mask is None: return # Sloppy
    self.mask = mask
    self.value = value # In case value overrides mask (IP), do value last

  def get_length (self, omittable = False):
    # Calculating length is slightly tricky with mask omission, etc.,
    # so just pack it and find out, rather than duplicate the logic
    # here.
    return len(self.pack(omittable))

  def __len__ (self):
    return self.get_length()

  def _unpack_mask (self, m):
    return self._unpack_value(m)
  def _pack_mask (self, m):
    return self._pack_value(m)

  @property
  def is_reg (self):
    return False
  @property
  def allow_mask (self):
    return False

  @property
  def value (self):
    return self._unpack_value(self._value)
  @value.setter
  def value (self, value):
    self._value = self._pack_value(value)

  @property
  def mask (self):
    if self._mask is None: return None
    return self._unpack_mask(self._mask)
  @mask.setter
  def mask (self, value):
    if self.allow_mask is False:
      if value is not None:
        raise RuntimeError("entry has no mask")
    if value is None:
      # This would normally be up to the pack function, but we add it
      # here as a special case
      self._mask = None
    else:
      self._mask = self._pack_mask(value)

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self._nxm_type != other._nxm_type: return False
    if self.value != other.value: return False
    if self.mask != other.mask: return False
    if self.is_reg != other.is_reg: return False
    return True

  def pack (self, omittable = False, header_only = False):
    h = self._nxm_type << 9
    mask = self._mask

    if mask is not None:
      assert len(mask) == self._nxm_length, "mask is wrong length"

      if (mask.count("\x00") == self._nxm_length) and omittable:
        return b''

      if (mask.count("\xff") == self._nxm_length):
        mask = None

    if mask is None and self._force_mask:
      mask = "\xff" * self._nxm_length

    if mask is not None:
      h |= (1 << 8)
      h |= (self._nxm_length * 2)
    else:
      h |= self._nxm_length

    r = struct.pack("!L", h)
    if header_only: return r

    value = self._value
    assert value is not None
    assert len(value) == self._nxm_length, "value is wrong length"

    r += value
    if mask is not None:
      assert 0 == sum(ord(v)&(0xff&~ord(m)) for v,m in zip(value,mask)), \
             "nonzero masked bits"
      r += mask

    return r

  def __str__ (self):
    r = self.__class__.__name__ + "(" + str(self.value)
    if self.mask is not None:
      if self.mask != ("\xff" * self._nxm_length):
        r += "/" + str(self.mask)
    #if self.is_reg: r += "[r]"
    return r + ")"

  def __repr__ (self):
    return str(self)


class _nxm_numeric_entry (_nxm_numeric, nxm_entry):
  pass

class _nxm_maskable (object):
  @property
  def allow_mask (self):
    return True

class _nxm_maskable_numeric_entry (_nxm_maskable, _nxm_numeric_entry):
  pass

class _nxm_reg (_nxm_maskable_numeric_entry):
  @property
  def is_reg (self):
    return True

class NXM_GENERIC (_nxm_raw, nxm_entry):
  @property
  def allow_mask (self):
    return True

  def __str__ (self):
    r = "NXM_%08x_%i" % (self.nxm_vendor, self.nxm_field)
    r += "("
    r += "".join("%02x" % (ord(x),) for x in self.value)
    #+ repr(self.value)
    if self.mask is not None:
      if self.mask != ("\xff" * self._nxm_length):
        r += "/" + repr(self.mask)
    return r + ")"


def _make_type (vendor, field):
  """
  Takes an NXM vendor and field and returns the whole type field
  """
  return (vendor << 7) | field


def _fix_types (t):
  """
  Helper for _make_nxm(_w)

  Normalizes lists of superclasses
  """
  try:
    _ = t[0]
    t = list(t)
  except:
    t = [t]
  ok = False
  for tt in t:
    if _issubclass(tt, nxm_entry):
      ok = True
      break
  if not ok:
    t.append(nxm_entry)
  #t = tuple(t)
  return t


def _make_nxm (__name, __vendor, __field, __len = None, type = None,
                 **kw):
  """
  Make a simple NXM entry class
  """
  if type is None:
    type = (_nxm_numeric_entry,)
  else:
    type = _fix_types(type)

  t = _make_type(__vendor, __field)
  kw['_nxm_type'] = t
  if __len is not None: kw['_nxm_length'] = __len
  import __builtin__
  typ = __builtin__.type
  c = typ(__name, tuple(type), kw)
  _nxm_type_to_class[t] = c
  _nxm_name_to_type[__name] = t
  assert __name not in globals()
  globals()[__name] = c
  return c


def _make_nxm_w (*args, **kw):
  """
  Make a simple wildcarded NXM entry class
  """
  t = _fix_types(kw.pop('type', _nxm_maskable_numeric_entry))
  ok = False
  for tt in t:
    if _issubclass(tt, _nxm_maskable):
      ok = True
      break
  if not ok:
    t.insert(0, _nxm_maskable)

  return _make_nxm(*args, type=t, **kw)


def _class_for_nxm_header (raw):
  """
  Given a raw nxm_entry header, return corresponding class

  If we don't have a class for this header type, we generate one.
  """
  t,has_mask,length = nxm_entry.unpack_header(raw, 0)
  c = _nxm_type_to_class.get(t)
  if c: return c

  # Need to generate a new nxm_entry type.
  # This code is totally untested.
  vendor = (t >> 7) & 0xffff
  field = t & 0x7f
  typename = "NXM_UNKNOWN_"
  typename += "%04x_%02x" % (vendor,field)
  if has_mask: typename += "_MASKABLE"
  types = [_nxm_raw]
  if has_mask:
    types.append(_nxm_maskable)
  return _make_nxm(typename, vendor, field, length, types)


# -----------------------------------------------------------------------
# OpenFlow 1.0-compatible nxm_entries
# -----------------------------------------------------------------------

_make_nxm("NXM_OF_IN_PORT", 0, 0, 2)

_make_nxm_w("NXM_OF_ETH_DST", 0, 1, 6, type=_nxm_ether)
_make_nxm_w("NXM_OF_ETH_SRC", 0, 2, 6, type=_nxm_ether)

# Packet ethertype
_make_nxm("NXM_OF_ETH_TYPE", 0, 3, 2)

_make_nxm_w("NXM_OF_VLAN_TCI", 0, 4, 2)

_make_nxm_w("NXM_OF_IP_TOS", 0, 5, 1)

_make_nxm_w("NXM_OF_IP_PROTO", 0, 6, 1)

_make_nxm_w("NXM_OF_IP_SRC", 0, 7, 4, type=_nxm_ip)
_make_nxm_w("NXM_OF_IP_DST", 0, 8, 4, type=_nxm_ip)

# Maskable in OVS 1.6+
_make_nxm_w("NXM_OF_TCP_SRC", 0, 9, 2)
_make_nxm_w("NXM_OF_TCP_DST", 0, 10, 2)

# Maskable in OVS 1.6+
_make_nxm_w("NXM_OF_UDP_SRC", 0, 11, 2)
_make_nxm_w("NXM_OF_UDP_DST", 0, 12, 2)

_make_nxm("NXM_OF_ICMP_TYPE", 0, 13, 1)
_make_nxm("NXM_OF_ICMP_CODE", 0, 14, 1)

_make_nxm("NXM_OF_ARP_OP", 0, 15, 2)

# The IP address in an ethernet+IP ARP packet
# Fully maskable in OVS 1.8+, only CIDR-compatible masks before that
_make_nxm_w("NXM_OF_ARP_SPA", 0, 16, 4, type=_nxm_ip)
_make_nxm_w("NXM_OF_ARP_TPA", 0, 17, 4, type=_nxm_ip)


# -----------------------------------------------------------------------
# Nicira register nxm_entries
# -----------------------------------------------------------------------

NXM_NX_MAX_REGS = 16

# Array with all the register entries indexed by their number
# (they are also available as NXM_NX_REG0, etc.)
NXM_NX_REG = []

def _init_regs ():
  for i in range(0, NXM_NX_MAX_REGS):
    assert len(NXM_NX_REG) == i
    n = "NXM_NX_REG" + str(i)
    r = _make_nxm_w(n, 1, i, 4, type=_nxm_reg)
    NXM_NX_REG.append(r)
    globals()[n] = r
_init_regs()

def NXM_IS_NX_REG (o):
  """
  Simulates macro from OVS
  """
  return o.is_reg


# -----------------------------------------------------------------------
# Nicira nxm_entries
# -----------------------------------------------------------------------

_make_nxm_w("NXM_NX_TUN_ID", 1, 16, 8)

# The ethernet address in an ethernet+IP ARP packet
_make_nxm("NXM_NX_ARP_SHA", 1, 17, 6, type=_nxm_ether)
_make_nxm("NXM_NX_ARP_THA", 1, 18, 6, type=_nxm_ether)

# Fully maskable in OVS 1.8+, only CIDR-compatible masks before that
_make_nxm_w("NXM_NX_IPV6_SRC", 1, 19, 16, type=_nxm_ipv6)
_make_nxm_w("NXM_NX_IPV6_DST", 1, 20, 16, type=_nxm_ipv6)

_make_nxm("NXM_NX_ICMPV6_TYPE", 1, 21, 1)
_make_nxm("NXM_NX_ICMPV6_CODE", 1, 22, 1)

# IPv6 Neighbor Discovery target address
_make_nxm_w("NXM_NX_ND_TARGET", 1, 23, 16, type=_nxm_ipv6)

# IPv6 Neighbor Discovery source link-layer address
_make_nxm("NXM_NX_ND_SLL", 1, 24, 6, type=_nxm_ether)

# IPv6 Neighbor Discovery target link-layer address
_make_nxm("NXM_NX_ND_TLL", 1, 25, 6, type=_nxm_ether)

# Bits for NXM_NX_IP_FRAG
NX_IP_FRAG_ANY = 1   # It's the first/only fragment
NX_IP_FRAG_LATER = 3 # It's not the first fragment

# IP fragment information
#TODO: A custom type or types would make this nicer to use.
#      For now, use with above flags.
_make_nxm_w("NXM_NX_IP_FRAG", 1, 26, 1)

# IPv6 flow label
_make_nxm("NXM_NX_IPV6_LABEL", 1, 27, 4)

# IP ECN bits
_make_nxm("NXM_NX_IP_ECN", 1, 28, 1)

_make_nxm("NXM_NX_IP_TTL", 1, 29, 1)

# Flow cookie
_make_nxm_w("NXM_NX_COOKIE", 1, 30, 8)


#@vendor_s_message('NXT_PACKET_IN', 17)
NXT_PACKET_IN = 17
class nxt_packet_in (nicira_base, of.ofp_packet_in):
  subtype = NXT_PACKET_IN
  _MIN_LENGTH = 34
  def _init (self, kw):
    ofp_header.__init__(self)

    self._buffer_id = None
    self.reason = 0
    self.data = None
    self._total_len = None
    self._match = None

    if 'total_len' in kw:
      self._total_len = kw.pop('total_len')

  def _validate (self):
    if self.data and (self.total_len < len(self.packed_data)):
      return "total len less than data len"

  @property
  def in_port (self):
    return self.match.of_in_port

  @property
  def match (self):
    if self._match is None:
      self._match = nx_match()
    return self._match
  @match.setter
  def match (self, v):
    self._match = v

  def pack (self):
    assert self._assert()

    match_len = len(self.match)

    packed = b""
    packed += ofp_header.pack(self)
    packed += struct.pack("!LL", NX_VENDOR_ID, self.subtype)
    packed += struct.pack("!LHBBQH", self._buffer_id, self.total_len,
                          self.reason, self.table_id, self.cookie,
                          match_len)
    packed += _PAD6
    packed += match.pack()
    packed += _PAD * ((match_len + 7)/8*8 - match_len)
    packed += _PAD2
    packed += self.packed_data
    return packed

  @property
  def packed_data (self):
    if self.data is None:
      return b''
    if hasattr(self.data, 'pack'):
      # I don't think this is ever encountered...
      return self.data.pack()
    else:
      return self.data

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,length = self._unpack_header(raw, offset)
    offset,(vendor,subtype) = _unpack("!LL", raw, offset)
    assert subtype == self.subtype
    #print "vendor %08x  subtype %i" % (vendor,subtype)
    offset,(self._buffer_id, self._total_len, self.reason, self.table_id,
            self.cookie, match_len) = _unpack("!LHBBQH", raw, offset)
    offset = _skip(raw, offset, 6)

    self.match = None
    offset = self.match.unpack(raw, offset, match_len)

    offset = _skip(raw, offset, (match_len + 7)//8*8 - match_len)
    offset = _skip(raw, offset, 2)

    offset,self.data = _read(raw, offset, length-(offset-_offset))
    assert length == len(self)
    return offset,length

  def __len__ (self):
    match_len = len(self.match)
    l = 8 + 4 + 4
    l += 4 + 2 + 1 + 1 + 8 + 2
    l += 6
    l += match_len
    l += (match_len + 7)//8*8 - match_len
    l += 2
    l += len(self.packed_data)
    return l

  def __eq__ (self, other):
    if not of.ofp_packet_in.__eq__(self, other): return False
    if self.table_id != other.table_id: return False
    if self.cookie != other.cookie: return False
    if self.match != other.match: return False
    return True

  def __ne__ (self, other): return not self.__eq__(other)

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += ofp_header.show(self, prefix + '  ')
    outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
    outstr += prefix + 'total_len: ' + str(self._total_len) + '\n'
    outstr += prefix + 'reason: ' + str(self.reason) + '\n'
    outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
    outstr += prefix + 'match: ' + str(self.match) + '\n'
    outstr += prefix + 'cookie: ' + str(self.cookie) + '\n'
    #from pox.lib.util import hexdump
    #outstr += prefix + 'data: ' + hexdump(self.data) + '\n'
    outstr += prefix + 'datalen: ' + str(len(self.data)) + '\n'
    return outstr

  def field (self, t):
    for i in self.match:
      if type(i) == t:
        return i
    return None


class nx_match (object):
  """
  A flexible match container

  This has some magic.  It acts as if it has properties for each
  registered nxm_entry type.  For example, there's a NXM_OF_IP_SRC
  nxm_entry type for the source IP address, so you can do:

    m = nx_match()
    m.of_tcp_src = IPAddr("192.168.1.1")

  Since nxm_entries can have masks, you actually get a number of pseudo-
  properties, by appending "_mask", "_with_mask", or "_entry":

    m.of_tcp_src_with_mask = ("192.168.1.0", "255.255.255.0")
    # or...
    m.of_tcp_src = "192.168.1.0"
    m.of_tcp_src_mask = "255.255.255.0"
    # or...
    m.of_tcp_src_entry = NXM_OF_IP_SRC("192.168.1.1", "255.255.255.0")

  nxm_entries themselves may have magic.  For example, IP address
  nxm_entries understand CIDR bits as part of the value, so you can do:

    m.of_tcp_src = "192.168.1.0/24"
    print m.of_tcp_src
    > NXM_OF_IP_SRC(192.168.1.0/255.255.255.0)

  *The order you add entries is significant*.  If you have an entry
  with a prerequisite, you must add the prerequisite first.  It would be
  really nice if nx_match could automatically adjust orderings to try to
  satisfy nxm_entry prerequisties, and throw an exception if it's not
  possible.  This is a TODO item.
  """
  #TODO: Test!
  #TODO: Handle prerequisites (as described above)

  def __init__ (self, *parts, **kw):
    """
    Initialize this match

    You can initialize either from a list of parts or from a bunch of
    key/value pairs which are just like a shortcut for setting individual
    properties.
    """
    self._parts = list(parts)
    self._dirty()
    for k,v in kw:
      setattr(self, k, v)

  def unpack (self, raw, offset, avail):
    del self._parts[:]
    self._dirty()
    stop = avail+offset
    while offset < stop:
      _o = offset
      offset,entry = nxm_entry.unpack_new(raw, offset)
      if offset == _o:
        raise RuntimeError("No progress unpacking nxm_entries")
      self._parts.append(entry)

    #assert offset == stop
    return offset

  def pack (self, omittable = False):
    return ''.join(x.pack(omittable) for x in self._parts)

  def __eq__ (self, other):
    if not isinstance(other, self.__class__): return False
    return self._parts == other.__parts

  def clone (self):
    n = nx_match()
    for p in self._parts:
      n.append(p.clone())
    return n

  def __str__ (self):
    return ','.join(str(m) for m in self._parts)

  def show (self, prefix = ''):
    return prefix + str(self)

  @property
  def _map (self):
    if self._cache is None:
      self._cache = {}
      for i in self._parts:
        assert i._nxm_type not in self._cache
        self._cache[i._nxm_type] = i
    return self._cache

  def __len__ (self):
    return sum(len(x) for x in self._parts)

  def __getitem__ (self, index):
    return self._parts[index]

  def remove (self, t):
    """
    Remove an entry
    """
    if isinstance(t, nxm_entry):
      t = t._nxm_type
    if t not in self._map:
      return
    t = self._map[t]
    self._parts.remove(t)
    self._dirty()

  def find (self, t):
    """
    Returns nxm_entry of given type
    """
    if isinstance(t, nxm_entry) or _issubclass(t, nxm_entry):
      t = t._nxm_type
    return self._map.get(t)

  def index (self, t):
    """
    Returns index of nxm_entry of given type
    """
    if isinstance(t, nxm_entry):
      t = t._nxm_type
    if t not in self._map:
      return -1 # Exception?  None?
    return self._parts.find(t)

  def _dirty (self):
    self._cache = None

  def insert (self, position, item):
    if isinstance(t, nxm_entry) or _issubclass(t, nxm_entry):
      position = self.find(position)
      if position == None:
        self.append(item)
        return
    self._parts.insert(position, item)

  def insert_after (self, position, item):
    if isinstance(t, nxm_entry) or _issubclass(t, nxm_entry):
      position = self.find(position)
      if position == None:
        self.append(item)
        return
    self._parts.insert(position+1, item)

  def append (self, item):
    """
    Add another nxm_entry to this match
    """
    #TODO: check prereqs
    if not isinstance(item, nxm_entry):
      raise ValueError("Not an nxm_entry")
    if self.find(item) is not None:
      raise ValueError("Type already exists in this match")
    self._parts.append(item)
    self._dirty()

  def __iadd__ (self, other):
    self.append(other)

  @staticmethod
  def _fixname (name):
    name = name.upper()
    if not name.startswith("NXM_"):
      name = "NXM_" + name

    is_mask = with_mask = is_entry = False
    if name.endswith("_MASK"):
      if name.endswith("_WITH_MASK"):
        with_mask = True
        name = name.rsplit("_WITH_MASK", 1)[0]
      else:
        is_mask = True
        name = name.rsplit("_MASK", 1)[0]
    elif name.endswith("_ENTRY"):
      name = name.rsplit("_ENTRY", 1)[0]
      is_entry = True

    nxt = _nxm_name_to_type.get(name)

    #print name, nxt, is_mask, with_mask, is_entry
    return name, nxt, is_mask, with_mask, is_entry

  def __getattr__ (self, name):
    name,nxt,is_mask,with_mask,is_entry = self._fixname(name)

    if nxt is None:
      raise AttributeError("No attribute " + name)

    if nxt not in self._map:
      if with_mask: return None,None
      if is_mask: return None # Exception?
      if is_entry: return None # Synthesize?
      return None

    v = self._map[nxt]
    if with_mask: return (v.value,v.mask)
    if is_mask: return v.mask
    if is_entry: return v
    return v.value

  def __setattr__ (self, name, value):
    if name.startswith('_'):
      return object.__setattr__(self, name, value)

    name,nxt,is_mask,with_mask,is_entry = self._fixname(name)

    if nxt is None:
      return object.__setattr__(self, name, value)
      #raise AttributeError("No attribute " + name)

    entry = self.find(nxt)

    if is_entry: assert isinstance(value, nxm_entry)

    if is_entry and (value is None) and (entry is not None):
      # Shortcut entry removal
      # Allow for non is_entry?  Doing so is ambiguous if there are
      # ever nxm_entries with None as a legal value.
      self.remove(nxt)
      return

    if isinstance(value, nxm_entry):
      if nxt != nxm_entry._nxm_type:
        raise ValueError("Unmatched types")
      if entry is None:
        self.append(value)
      else:
        # hacky
        entry.value = value.value
        entry.mask = value.mask
    else:
      if entry is None:
        entry = _nxm_type_to_class[nxt]()
        self.append(entry)
      # hacky
      if with_mask:
        entry.mask = value[1]
        entry.value = value[0]
      elif is_mask:
        entry.mask = value
      else:
        entry.value = value


#from pox.lib.revent import Event
#class NXPacketIn (Event):
#  def __init__ (self, connection, ofp):
#    Event.__init__(self)
#    self.connection = connection
#    self.ofp = ofp
#    self.port = ofp.in_port
#    self.data = ofp.data
#    self._parsed = None
#    self.dpid = connection.dpid
#
#  def parse (self):
#    if self._parsed is None:
#      self._parsed = ethernet(self.data)
#    return self._parsed
#
#  @property
#  def parsed (self):
#    """
#    The packet as parsed by pox.lib.packet
#    """
#    return self.parse()
#
#core.openflow._eventMixin_events.add(NXPacketIn)


_old_unpacker = None

def _unpack_nx_vendor (raw, offset):
  from pox.lib.util import hexdump
  v = _unpack("!L", raw, offset + 8)[1][0]
  if v != NX_VENDOR_ID:
    return _old_unpacker(raw, offset)
  subtype = _unpack("!L", raw, offset+8+4)[1][0]
  if subtype == NXT_PACKET_IN:
    npi = nxt_packet_in()
    return npi.unpack(raw, offset)[0], npi
  else:
    print "NO UNPACKER FOR",subtype
    return _old_unpacker(raw, offset)


def _init_unpacker ():
  global _old_unpacker
  from pox.openflow.of_01 import unpackers
  _old_unpacker = unpackers[of.OFPT_VENDOR]
  unpackers[of.OFPT_VENDOR] = _unpack_nx_vendor


_old_handler = None

from pox.openflow import PacketIn

def _handle_VENDOR (con, msg):
  if isinstance(msg, nxt_packet_in) and core.NX.convert_packet_in:
    e = con.ofnexus.raiseEventNoErrors(PacketIn, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(PacketIn, con, msg)
  else:
    _old_handler(con, msg)


def _init_handler ():
  global _old_handler
  from pox.openflow.of_01 import handlerMap, _set_handlers

  _old_handler = handlerMap.get(of.OFPT_VENDOR)
  handlerMap[of.OFPT_VENDOR] = _handle_VENDOR
  _set_handlers()


class NX (object):
  """
  Nicira extension component
  """
  convert_packet_in = False


def launch (convert_packet_in = False):
  _init_handler()
  _init_unpacker()

  core.registerNew(NX)

  if convert_packet_in:
    core.NX.convert_packet_in = True
