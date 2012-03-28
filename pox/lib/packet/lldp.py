# Copyright 2011 James McCauley
# Copyright 2008 (C) Nicira, Inc.
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
#   Error handling (malformed packetswill definately cause this to
#   puke)
#
#======================================================================

import struct
import time
from packet_utils       import *

from packet_base import packet_base
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

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.next = None
        self.tlvs = []

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def next_tlv(self, array):

        if len(array) < 2:
            self.msg('(lldp tlv parse) warning TLV data too short to read type/len (%u)' % (len(array),))
            return

        (typelen,) = struct.unpack("!H",array[0:2])

        type      = typelen >> 9
        length    = typelen & 0x01ff

        if len(array) < length:
            self.msg( '(lldp tlv parse) warning TLV data too short to parse (%u)' % (len(array),))
            return

        if type in lldp.tlv_parsers:
            self.tlvs.append(lldp.tlv_parsers[type](array[0: 2 + length]))
            return 2 + length
        else:
            self.msg( '(lldp tlv parse) warning unknown tlv type (%u)' % (type,) )
            # TODO: unknown_tlv is an undefined variable! Check me in?
            self.tlvs.append(unknown_tlv(array[0: 2 + length]))
            return 2 + length

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < lldp.MIN_LEN:
            self.msg( '(lldp parse) warning LLDP packet data too short to parse header: data len %u' % (dlen,))
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

    def add_tlv(self, tlv):
        self.tlvs.append(tlv)

    def __str__(self):
        lstr = ''
        for tlv in self.tlvs:
            lstr += str(tlv)
        return lstr

    def hdr(self, payload):
        packet = b''
        for tlv in self.tlvs:
            packet += tlv.pack()
        return packet


#======================================================================
#                          TLV definitions
#======================================================================
        
class chassis_id:
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

    # Construct from packet data
    def __init__(self, raw = None, **kw):
        self.parsed   = False
        self.strlen   = 0
        self.subtype  = 0
        self.id       = None
        self.arr      = None
        if raw is not None:
            self.arr = raw
            self.parse()
        initHelper(self, kw)
   
    def fill(self, _subtype, strval):
        self.strlen  = 1 + len(strval)
        self.subtype = _subtype
        self.id      = strval

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])

        self.tlv_type = typelen >> 9
        assert(self.tlv_type == 1)
        self.strlen = typelen & 0x01ff
        assert(self.strlen >= 2)
        (self.subtype,) = struct.unpack("!B",self.arr[2:3])
        self.id = self.arr[3:]
        self.parsed = True

    def hdr(self, payload):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.strlen & 0x01ff)
        pack_str = '!HB'+str(self.strlen-1)+'s'
        return struct.pack(pack_str, typelen, self.subtype, self.id)

    def pack(self):
        packet = self.hdr(0)
        return packet

    def __str__(self):
        if self.subtype == chassis_id.SUB_MAC:
            assert len(self.id) == 6
            id_str = str(EthAddr(self.id))
        else:
            id_str = ":".join(["%02x" % (ord(x),) for x in self.id])

        return ''.join(['<chasis ID:',id_str,'>'])

class port_id:
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

    def __init__(self, raw = None, **kw):
        self.parsed = False
        self.subtype = 0
        self.id      = None
        self.arr     = raw
        if raw is not None:
            self.parse()

    @property
    def strlen (self):
      return 1 + len(self.id)

    def fill(self, subtype, strval):
        self.subtype = subtype
        self.id      = strval

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])

        self.tlv_type = typelen >> 9
        assert(self.tlv_type == 2)
        strlen = typelen & 0x01ff
        assert(strlen >= 2)
        (self.subtype,) = struct.unpack("!B",self.arr[2:3])
        self.id = self.arr[3:]
        assert strlen == 1 + len(self.id)
        parsed = True

    def __str__(self):
        if self.subtype == chassis_id.SUB_MAC:
            assert len(self.id) == 6
            id_str = str(EthAddr(self.id))
        else:
            id_str = ":".join(["%02x" % (ord(x),) for x in self.id])

        return ''.join(['<port ID:',id_str,'>'])

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.strlen & 0x01ff)
        pack_str = '!HB'+str(self.strlen-1)+'s'
        return struct.pack(pack_str, typelen, self.subtype, self.id)

class ttl:
    tlv_type = lldp.TTL_TLV

    def __init__(self, raw = None, **kw):
        self.parsed = False
        self.strlen  = 2
        self.ttl     = 0
        self.arr     = raw

        if raw is not None:
            self.parse()

        initHelper(self, kw)

    def fill(self, ttl):
        self.ttl    = ttl

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])

        self.tlv_type = typelen >> 9
        assert(self.tlv_type == 3)
        self.strlen = typelen & 0x01ff
        if (self.strlen != 2):
            lg.info('(ttl tlv parse) length incorrect (should be 2) %u' % (self.strlen))
            return
        (self.ttl,) = struct.unpack("!H",self.arr[2:4])
        self.parsed = True

    def __str__(self):
        return ''.join(['<ttl:',str(self.ttl),'>'])

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.strlen & 0x01ff)
        pack_str = '!HB'+str(self.strlen-1)+'s'
        return struct.pack('!HH', typelen, self.ttl)

class end_tlv:
    tlv_type = lldp.END_TLV

    def __init__(self, raw = None):
        self.parsed = False
        self.strlen  = 0
        self.arr     = raw 
        if raw is not None:
            self.parse()

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])
        self.tlv_type = typelen >> 9
        assert(self.tlv_type == lldp.END_TLV)
        self.strlen = typelen & 0x01ff
        if self.strlen != 0:
            lg.info('(tl end parse) length incorrect (should be 0) %u' % (self.strlen))
            return
        self.parsed = True

    def __str__(self):
        return '<tlv end>'

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.strlen & 0x01ff)
        return struct.pack('!H', typelen)

class basic_tlv (object):
    #tlv_type = <type>
    def __init__(self, raw = None):
        self.parsed = False
        self.len    = 0
        self.arr    = raw
        self.next   = b''
        if raw is not None:
            self.parse()

    def fill(self, strval):
        self.len  = len(strval)
        self.next = strval

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])
        self.tlv_type = typelen >> 9
        self.len  = typelen & 0x01ff
        self.next = self.arr[2:]
        self.parsed = True

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.len & 0x01ff)
        return struct.pack('!H', typelen) + self.next

class unknown_tlv (basic_tlv):
    tlv_type = None

class system_description (basic_tlv):
    tlv_type = lldp.SYSTEM_DESC_TLV

class management_address (object):
    tlv_type = lldp.MANAGEMENT_ADDR_TLV

    def __init__ (self, raw = None):
        self.address_subtype = 0
        self.address = b''
        self.interface_numbering_subtype = 0
        self.interface_number = 0
        self.object_identifier = b''

        if raw is not None:
            self.parse(raw)

    def parse (self, data):
        typelen = struct.unpack("!H",data[0:2])[0]
        self.tlv_type = typelen >> 9
        length  = typelen & 0x01ff

        asl = ord(data[2]) - 1
        self.address_subtype = ord(data[3])
        self.address = data[4:4+asl]

        self.interface_numbering_subtype = ord(data[4+asl])
        self.interface_number = struct.unpack("!L",
                                              data[4+asl+1:4+asl+1+4])[0]
        osl = ord(data[9+asl])
        self.object_identifier = data[9+asl+1:9+asl+1+osl]

    def __len__ (self):
        return 2+1+1+len(self.address)+1+4+1+len(self.object_identifier)

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | ((len(self)-2) & 0x01ff)
        r = struct.pack('!H', typelen)
        r += struct.pack('!BB', len(self.address)+1, self.address_subtype)
        r += self.address
        r += struct.pack("!BLB", self.interface_numbering_subtype,
                         self.interface_number,
                         len(self.object_identifier))
        r += self.object_identifier
        return r

class system_name (basic_tlv):
    tlv_type = lldp.SYSTEM_NAME_TLV

class organizationally_specific (basic_tlv):
    tlv_type = lldp.ORGANIZATIONALLY_SPECIFIC_TLV
    def __init__ (self, raw = None):
        self.oui = '\x00\x00\x00'
        self.subtype = 0
        self.next = bytes()
        basic_tlv.__init__(self, raw)
      
    def parse (self):
        basic_tlv.parse(self)
        (self.oui,self.subtype) = struct.unpack("3sB", self.next[0:4])
        self.next = self.next[4:]

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.len & 0x01ff)
        return struct.pack('!H3sB', typelen, self.oui, self.subtype) + self.next

class port_description (basic_tlv):
    tlv_type = lldp.PORT_DESC_TLV

class system_capabilities (basic_tlv):
    tlv_type = lldp.SYSTEM_CAP_TLV

    cap_names = ["Other", "Repeater", "Bridge", "WLAN Access Point",
                 "Router", "Telephone", "DOCSIS cable device",
                 "Station Only"]

    def __init__ (self, raw = None):
        self.caps = [False] * 16
        self.enabled_caps = [False] * 16
        basic_tlv.__init__(self, raw)
      
    def parse (self):
        basic_tlv.parse(self)
        (cap,en) = struct.unpack("!HH", self.next)
        del self.caps[:]
        del self.enabled_caps[:]
        for i in range(0, 16):
            self.caps.append(True if (cap and (1 << i)) else False)
            self.enabled_caps.append(True if (en and (1 << i)) else False)

    def pack(self):
        typelen = 0
        typelen = self.tlv_type << 9
        typelen = typelen | (self.len & 0x01ff)
        cap = 0
        en = 0
        for i in range(0, 16):
            if self.caps[i]: cap |= (1 << i)
            if self.enabled_caps[i]: en |= (1 << i)
        return struct.pack('!HHH', typelen, cap, en)

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
