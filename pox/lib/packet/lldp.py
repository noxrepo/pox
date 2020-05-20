# Copyright 2012 James McCauley
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
# IEEE 802.1AB Link Layer Discovery Protocol (lldp) header
# (http://standards.ieee.org/getieee802/download/802.1AB-2005.pdf)
#
# Copyright (C) 2007 Nicira Networks
#
# Ethernet type = 0x88cc
# Destination MAC = 01:80:c2:00:00:0e (LLDP_MULTICAST)
#
# LLDPDU format
#
# +------+-----+-----+-------+-------+------+---------+---------------+
# | Chassis ID |   Port ID   | TTL   | Optional ......| End of LLDPDU |
# |    TLV     |    TLV      | TLV   |
# +------+-----+-----+-------+-------+------+---------+---------------+
#
# TLV Format
#
# +------------+---------------------+--------------------------------+
# |  TLV type  | TLV information     |  TLV information string        |
# |            | string length       |                                |
# +------------+---------------------+--------------------------------+
#
# TLV Types:
#
# 0   - end of LLDPDU
# 1   - Chassis ID
# 2   - Port ID
# 3   - TTL
# 4   - Port description (optional)
# 5   - System name
# 6   - System description
# 7   - System capabilities
# 8   - Management address
# 127 - Organization specific TLVs
# 9-126 - reserved
#
# TODO:
# Error handling (malformed packets will definately cause this to puke)
#
#======================================================================

import struct
import time
from .packet_utils import *

from .packet_base import packet_base
from pox.lib.addresses import EthAddr
from pox.lib.util import initHelper

import logging
lg = logging.getLogger('packet')

#======================================================================
#                        LLDP PDU
#======================================================================

class lldp (packet_base):
  "802.1 AB lldp pdu"

  # chassis ID min = 2 + 1 + 1
  # PORT    ID min = 2 + 1 + 1
  # TTL        min = 2 + 2
  # End        min = 2
  MIN_LEN = (4 + 4 + 4 + 2 )

  #TODO: Remove these from here (they should be at module scope)?
  END_TLV         = 0
  CHASSIS_ID_TLV  = 1
  PORT_ID_TLV     = 2
  TTL_TLV         = 3
  PORT_DESC_TLV   = 4
  SYSTEM_NAME_TLV = 5
  SYSTEM_DESC_TLV = 6
  SYSTEM_CAP_TLV  = 7
  MANAGEMENT_ADDR_TLV = 8
  ORGANIZATIONALLY_SPECIFIC_TLV = 127

  tlv_parsers = {}

  def __init__ (self, raw=None, prev=None, **kw):
    packet_base.__init__(self)

    self.prev = prev

    self.next = None
    self.tlvs = []

    if raw is not None:
      self.parse(raw)

    self._init(kw)

  def next_tlv(self, array):

    if len(array) < 2:
      self.msg('(lldp tlv parse) warning TLV data too short to read '
               + 'type/len (%u)' % (len(array),))
      return

    (typelen,) = struct.unpack("!H",array[0:2])

    type = typelen >> 9
    length = typelen & 0x01ff

    if len(array) < length:
      self.msg('(lldp tlv parse) warning TLV data too short to parse (%u)'
               % (len(array),))
      return

    if type in lldp.tlv_parsers:
      self.tlvs.append(lldp.tlv_parsers[type](array[0: 2 + length]))
      return 2 + length
    else:
      self.msg('(lldp tlv parse) warning unknown tlv type (%u)'
               % (type,))
      self.tlvs.append(unknown_tlv(array[0: 2 + length]))
      return 2 + length

  def parse (self, raw):
    assert isinstance(raw, bytes)
    self.raw = raw
    dlen = len(raw)
    if dlen < lldp.MIN_LEN:
      self.msg('(lldp parse) warning LLDP packet data too short to parse '
               + 'header: data len %u' % (dlen,))
      return

    # point to the beginning of the pdu
    pduhead = 0

    # get Chassis ID
    ret = self.next_tlv(raw)
    if ret == None:
      self.msg( '(lldp parse) error parsing chassis ID tlv' )
      return
    pduhead += ret
    if self.tlvs[len(self.tlvs)-1].tlv_type != lldp.CHASSIS_ID_TLV:
      self.msg( '(lldp parse) error CHASSIS ID TLV missing' )
      return

    # get PORT ID
    ret = self.next_tlv(raw[pduhead:])
    if ret is None:
      self.msg( '(lldp parse) error parsing port ID TLV' )
      return
    pduhead += ret
    if self.tlvs[len(self.tlvs)-1].tlv_type != lldp.PORT_ID_TLV:
      self.msg( '(lldp parse) error port ID TLV missing' )
      return

    # get  TTL
    ret = self.next_tlv(raw[pduhead:])
    if ret == None:
      self.msg( '(lldp parse) error parsing TTL TLV' )
      return
    pduhead += ret
    if self.tlvs[len(self.tlvs)-1].tlv_type != lldp.TTL_TLV:
      self.msg( '(lldp parse) error port TTL TLV missing' )
      return

    # Loop over all other TLVs
    arr_len = len(raw)
    while True:
      ret = self.next_tlv(raw[pduhead:])
      if ret == None:
        self.msg( '(lldp parse) error parsing TLV' )
        return
      if self.tlvs[len(self.tlvs)-1].tlv_type == lldp.END_TLV:
        break
      if (pduhead + ret) >= arr_len:
        self.msg( '(lldp parse) error end of TLV list without END TLV' )
        return
      pduhead += ret

    self.parsed = True

  def add_tlv (self, tlv):
    self.tlvs.append(tlv)

  def __str__ (self):
    lstr = ''
    for tlv in self.tlvs:
      lstr += str(tlv)
    return '[LLDP ' + lstr + ']'

  def hdr (self, payload):
    packet = b''
    for tlv in self.tlvs:
      packet += tlv.pack()
    return packet


#======================================================================
#                          TLV definitions
#======================================================================

#NOTE: As with a bunch of the packet library, it'd be nice if things
#      like TLVs inherited from some base class common to other
#      "sub-packets" (and maybe even packets).

class tlv_base (object):
  """
  Supertype for LLDP TLVs
  """
  pass


class simple_tlv (tlv_base):
  tlv_type = None # Purposely illegal

  def __init__ (self, raw = None, **kw):
    self._init(kw)
    self.parsed   = False

    if raw is not None:
      self.parse(raw)

    self._init_helper(kw)

  def _init_helper (self, kw):
    if len(kw):
      if 'payload' in kw:
        self.payload = None
      initHelper(self, kw)
      self.parsed = True

  def parse (self, raw):
    # assume lldp has done the type/len checking
    (typelen,) = struct.unpack("!H", raw[0:2])
    tlv_type = typelen >> 9
    if self.tlv_type is not None:
      assert self.tlv_type == tlv_type
    self.tlv_type = tlv_type

    strlen = typelen & 0x01ff

    data = raw[2:2+strlen]
    if len(data) < strlen:
      raise TruncatedException()

    self._parse_data(data)
    self.parsed = True

  @property
  def strlen (self):
    return self._data_len()

  def pack (self):
    typelen = self.tlv_type << 9
    data = self._pack_data()
    typelen |= (len(data) & 0x01ff)
    return struct.pack('!H', typelen) + data

  def __str__ (self):
    return "<" + self.__class__.__name__ + ">"


  def _init (self, kw):
    """
    Initialize subclass-specific fields

    Override this.
    """
    pass

  def _data_len (self):
    """
    Returns length of the TLV information string

    Override this.
    """
    return len(self._pack_data())

  def _parse_data (self, data):
    """
    Store TLV information string

    Override this.
    """
    self.payload = data

  def _pack_data (self):
    """
    Return TLV information string

    Override this.
    """
    return self.payload


class unknown_tlv (simple_tlv):
  """
  Unknown TLVs are parsed into this class
  """
  tlv_type = None


class chassis_id (simple_tlv):
  tlv_type = lldp.CHASSIS_ID_TLV

  SUB_CHASSIS  = 1 # IETF RFC 2737
  SUB_IF_ALIAS = 2 # IETF RFC 2863
  SUB_PORT     = 3 # IETF RFC 2737
  SUB_MAC      = 4 # IEEE Std 802-2001
  SUB_NETWORK  = 5 #
  SUB_IF_NAME  = 6 # IETF RFC 2863
  SUB_LOCAL    = 7

  subtype_to_str = {}
  subtype_to_str[SUB_CHASSIS]  = "chassis"
  subtype_to_str[SUB_IF_ALIAS] = "interface alias"
  subtype_to_str[SUB_PORT]     = "port"
  subtype_to_str[SUB_MAC]      = "mac"
  subtype_to_str[SUB_NETWORK]  = "network"
  subtype_to_str[SUB_IF_NAME]  = "interface name"
  subtype_to_str[SUB_LOCAL]    = "local"

  def _init (self, kw):
    self.subtype  = 0
    self.id       = None

  def _parse_data (self, data):
    if len(data) < 2:
      raise MalformedException("TLV has invalid strlen")

    (self.subtype,) = struct.unpack("!B",data[0:1])
    self.id = data[1:]

  def _pack_data (self):
    return struct.pack("!B", self.subtype) + self.id

  def __str__ (self):
    if self.subtype == chassis_id.SUB_MAC:
      assert len(self.id) == 6
      id_str = str(EthAddr(self.id))
    else:
      id_str = ":".join(["%02x" % (x,) for x in self.id])

    return ''.join(['<chasis ID:',id_str,'>'])


class port_id (simple_tlv):
  tlv_type = lldp.PORT_ID_TLV

  SUB_IF_ALIAS = 1 # IETF RFC 2863
  SUB_PORT     = 2 # IETF RFC 2737
  SUB_MAC      = 3 # IEEE Std 802-2001
  SUB_NETWORK  = 4 #
  SUB_IF_NAME  = 5 # IETF RFC 2863
  SUB_CIRC_ID  = 6 # IETF RFC 3046
  SUB_LOCAL    = 7

  subtype_to_str = {}
  subtype_to_str[SUB_IF_ALIAS] = "interface alias"
  subtype_to_str[SUB_PORT]     = "port"
  subtype_to_str[SUB_MAC]      = "mac"
  subtype_to_str[SUB_NETWORK]  = "network"
  subtype_to_str[SUB_IF_NAME]  = "interface name"
  subtype_to_str[SUB_CIRC_ID]  = "agent circuit ID"
  subtype_to_str[SUB_LOCAL]    = "local"

  def _init (self, kw):
    self.subtype = 0
    self.id      = None
    if isinstance(kw.get('id'), str):
      kw['id'] = kw['id'].encode()

  def _parse_data (self, data):
    if len(data) < 2:
      raise MalformedException("TLV has invalid strlen")

    (self.subtype,) = struct.unpack("!B",data[0:1])
    self.id = data[1:]

  def __str__ (self):
    if self.subtype == chassis_id.SUB_MAC:
      assert len(self.id) == 6
      id_str = str(EthAddr(self.id))
    else:
      id_str = ":".join(["%02x" % (x,) for x in self.id])

    return ''.join(['<port ID:',id_str,'>'])

  def _pack_data (self):
    return struct.pack("!B", self.subtype) + self.id


class ttl (simple_tlv):
  tlv_type = lldp.TTL_TLV

  def _init (self, kw):
    self.ttl = 0

  def _parse_data (self, data):
    if len(data) != 2:
      raise MalformedException("TLV has invalid strlen (!= 2)")
    (self.ttl,) = struct.unpack("!H",data[0:2])

  def __str__ (self):
    return ''.join(['<ttl:',str(self.ttl),'>'])

  def _pack_data (self):
    return struct.pack('!H', self.ttl)


class end_tlv (simple_tlv):
  tlv_type = lldp.END_TLV

  def _parse_data (self, data):
    if len(data) != 0:
      raise MalformedException("TLV has invalid strlen (!= 0)")

  def __str__ (self):
    return '<tlv end>'

  def _pack_data (self):
    return b''


class system_description (simple_tlv):
  tlv_type = lldp.SYSTEM_DESC_TLV


class management_address (simple_tlv):
  tlv_type = lldp.MANAGEMENT_ADDR_TLV

  def _init (self, kw):
    self.address_subtype = 0
    self.address = b''
    self.interface_numbering_subtype = 0
    self.interface_number = 0
    self.object_identifier = b''

  def _parse_data (self, data):
    asl = ord(data[0]) - 1
    self.address_subtype = ord(data[1])
    self.address = data[2:2+asl]

    self.interface_numbering_subtype = ord(data[2+asl])
    self.interface_number = struct.unpack("!L",
                                      data[2+asl+1:2+asl+1+4])[0]
    osl = ord(data[7+asl])
    self.object_identifier = data[7+asl+1:7+asl+1+osl]

  def _data_len (self):
    return 1+1+len(self.address)+1+4+1+len(self.object_identifier)

  def _pack_data (self):
    r = struct.pack('!BB', len(self.address)+1, self.address_subtype)
    r += self.address
    r += struct.pack("!BLB", self.interface_numbering_subtype,
                     self.interface_number,
                     len(self.object_identifier))
    r += self.object_identifier
    return r


class system_name (simple_tlv):
  tlv_type = lldp.SYSTEM_NAME_TLV


class organizationally_specific (simple_tlv):
  tlv_type = lldp.ORGANIZATIONALLY_SPECIFIC_TLV

  def _init (self, kw):
    self.oui = b'\x00\x00\x00'
    self.subtype = 0
    self.payload = b''

  def _parse_data (self, data):
    (self.oui,self.subtype) = struct.unpack("3sB", data[0:4])
    self.payload = data[4:]

  def _pack_data (self):
    return struct.pack('!3sB', self.oui, self.subtype) + self.payload


class port_description (simple_tlv):
  tlv_type = lldp.PORT_DESC_TLV


class system_capabilities (simple_tlv):
  tlv_type = lldp.SYSTEM_CAP_TLV

  cap_names = ["Other", "Repeater", "Bridge", "WLAN Access Point",
         "Router", "Telephone", "DOCSIS cable device",
         "Station Only"]

  def _init (self, kw):
    self.caps = [False] * 16
    self.enabled_caps = [False] * 16

  def _parse_data (self, data):
    (cap,en) = struct.unpack("!HH", data)
    del self.caps[:]
    del self.enabled_caps[:]
    for i in range(0, 16):
      self.caps.append(True if (cap & (1 << i)) else False)
      self.enabled_caps.append(True if (en & (1 << i)) else False)

  def _pack_data (self):
    cap = 0
    en = 0
    for i in range(0, 16):
      if self.caps[i]: cap |= (1 << i)
      if self.enabled_caps[i]: en |= (1 << i)
    return struct.pack('!HH', cap, en)

  def __str__ (self):
    r = []
    for i in range(0, 16):
      if self.caps[i]:
        if i < len(self.cap_names):
            s = self.cap_names[i]
        else:
            s = "Capability " + str(i)
        s += ":" + ("On" if self.enabled_caps[i] else "Off")
        r.append(s)
    return "<Capabilities: " + ', '.join(r) + ">"


# Add parsers to main lldp class
for t in [chassis_id, port_id, ttl, system_name, system_description,
      end_tlv, organizationally_specific, port_description,
      system_capabilities, management_address]:
  lldp.tlv_parsers[t.tlv_type] = t
