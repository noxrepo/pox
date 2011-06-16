# Copyright 2008 (C) Nicira, Inc.
# 
# This file is part of NOX.
# 
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
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
from packet_exceptions  import *
from array  import *

from packet_base import packet_base 

#======================================================================
#                          TLV definitions
#======================================================================

class chassis_id:

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
    def __init__(self, array = None):
        self.parsed = False
        self.type    = 0
        self.strlen  = 0
        self.subtype = 0
        self.id      = None 
        self.arr     = None 
        if array != None:
            self.arr = array
            self.parse()

    def fill(self, _subtype, strval):
        self.type    = 1 
        self.strlen  = 1 + len(strval)
        self.subtype = _subtype 
        self.id      = strval
            
    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])

        self.type   = typelen >> 9
        assert(self.type == 1)
        self.strlen = typelen & 0x01ff 
        assert(self.strlen >= 2)
        (self.subtype,) = struct.unpack("!B",self.arr[2:3])
        self.id = self.arr[3:]

    def hdr(self):
        typelen = 0
        typelen = self.type << 9
        typelen = typelen | (self.strlen & 0x01ff) 
        pack_str = '!HB'+str(self.strlen-1)+'s'
        return struct.pack(pack_str, typelen, self.subtype, self.id.tostring())

    def tostring(self):    
        packet = self.hdr()
        return packet

    def __str__(self): 
        id_str = array_to_octstr(self.id)

        if self.subtype == chassis_id.SUB_MAC:
            assert (len(self.id) == 6)
            id_str = mac_to_str(self.id, False)

        return ''.join(['<chassis ID:',id_str,'>'])

class port_id:

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

    def __init__(self, array = None):
        self.parsed = False
        self.type    = 0
        self.strlen  = 0
        self.subtype = 0
        self.id      = None 
        self.arr     = array
        if array != None:
            self.parse()

    def fill(self, _subtype, strval):
        self.type    = 2 
        self.strlen  = 1 + len(strval)
        self.subtype = _subtype 
        self.id      = strval

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])

        self.type   = typelen >> 9
        assert(self.type == 2)
        self.strlen = typelen & 0x01ff 
        assert(self.strlen >= 2)
        (self.subtype,) = struct.unpack("!B",self.arr[2:3])
        self.id = self.arr[3:]

    def __str__(self): 
        id_str = array_to_octstr(self.id)

        if self.subtype == chassis_id.SUB_MAC:
            assert (len(self.id) == 6)
            id_str = mac_to_str(self.id, True)

        return ''.join(['<port ID:',id_str,'>'])

    def tostring(self):    
        typelen = 0
        typelen = self.type << 9
        typelen = typelen | (self.strlen & 0x01ff) 
        pack_str = '!HB'+str(self.strlen-1)+'s'
        return struct.pack(pack_str, typelen, self.subtype, self.id.tostring())

class ttl:

    def __init__(self, array = None):
        self.parsed = False
        self.type    = 0
        self.strlen  = 0
        self.ttl     = 0
        self.arr     = array 

        if array != None:
            self.parse()

    def fill(self, _ttl):
        self.type   = 3
        self.strlen = 2
        self.ttl    = _ttl

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])

        self.type   = typelen >> 9
        assert(self.type == 3)
        self.strlen = typelen & 0x01ff 
        if (self.strlen != 2):
            self.msg('(ttl tlv parse) length incorrect (should be 2) %u' % (self.strlen))
            return
        (self.ttl,) = struct.unpack("!H",self.arr[2:4])

    def __str__(self): 
        return ''.join(['<ttl:',str(self.ttl),'>'])

    def tostring(self):    
        typelen = 0
        typelen = self.type << 9
        typelen = typelen | (self.strlen & 0x01ff) 
        pack_str = '!HB'+str(self.strlen-1)+'s'
        return struct.pack('!HH', typelen, self.ttl)

class end_tlv:

    def __init__(self, array = None):
        self.parsed = False
        self.type    = 0
        self.strlen  = 0
        self.arr     = array 
        if array != None:
            self.parse()

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])
        self.type   = typelen >> 9
        assert(self.type == 0)
        self.strlen = typelen & 0x01ff 
        if (self.strlen != 0):
            self.msg('(tl end parse) length incorrect (should be 0) %u' % (self.strlen))
            return

    def __str__(self): 
        return ''.join(['<tlv end>'])

    def tostring(self):    
        typelen = 0
        typelen = self.type << 9
        typelen = typelen | (self.strlen & 0x01ff) 
        return struct.pack('!H', typelen)


# tlv type we don't know how to handle 
class unknown_tlv:

    def __init__(self, array = None):
        self.parsed = False
        self.type   = 127 
        self.len    = 0
        self.arr    = array 
        self.next   = ''
        if array != None:
            self.parse()

    # assume lldp has done the type/len checking
    def parse(self):
        (typelen,) = struct.unpack("!H",self.arr[0:2])
        self.type   = typelen >> 9
        self.len  = typelen & 0x01ff 
        self.next = self.arr[2:].tostring()

    def tostring(self):    
        typelen = 0
        typelen = self.type << 9
        typelen = typelen | (self.len & 0x01ff) 
        return struct.pack('!H', typelen) + self.next

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

    END_TLV         = 0
    CHASSIS_ID_TLV  = 1
    PORT_ID_TLV     = 2
    TTL_TLV         = 3
    PORT_DESC_TLV   = 4
    SYSTEM_NAME_TLV = 5
    SYSTEM_DESC_TLV = 6
    SYSTEM_CAP_TLV  = 7
    MANAGEMENT_ADDR = 8

    tlv_parsers = {}
    tlv_parsers[CHASSIS_ID_TLV] = chassis_id
    tlv_parsers[PORT_ID_TLV]    = port_id
    tlv_parsers[TTL_TLV]        = ttl
    tlv_parsers[END_TLV]        = end_tlv

    def __init__(self, arr=None, prev=None):
        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.next = None
        self.parsed = False
        self.tlvs = []

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __nonzero__(self):
        return self.parsed == True

    def array(self):
        if self.prev == None:
            return None
        return self.prev.array()

    def next_tlv(self, array):

        if len(array) < 2:
            self.msg('(lldp tlv parse) warning TLV data too short to read type/len (%u)' % len(array))
            return 

        (typelen,) = struct.unpack("!H",array[0:2])

        type      = typelen >> 9
        length    = typelen & 0x01ff 

        if len(array) < (length):
            self.msg( '(lldp tlv parse) warning TLV data too short to parse (%u)' % len(array))
            return 

        if lldp.tlv_parsers.has_key(type):
            self.tlvs.append(lldp.tlv_parsers[type](array[0: 2 + length]))
            return 2 + length
        else:    
            self.msg( '(lldp tlv parse) warning unknown tlv type (%u)' % type )
            self.tlvs.append(unknown_tlv(array[0: 2 + length]))
            return 2 + length

    def parse(self):
        dlen = len(self.arr)
        if dlen < lldp.MIN_LEN:
            self.msg( '(lldp parse) warning LLDP packet data too short to parse header: data len %u' % dlen)
            return 

        # point to the beginning of the pdu
        pduhead = 0 

        # get Chassis ID
        ret = self.next_tlv(self.arr)
        if ret == None:
            self.msg( '(lldp parse) error parsing chassis ID tlv' )
            return
        pduhead += ret
        if self.tlvs[len(self.tlvs)-1].type != lldp.CHASSIS_ID_TLV:
            self.msg( '(lldp parse) error CHASSIS ID TLV missing' )
            return

        # get PORT ID
        ret = self.next_tlv(self.arr[pduhead:])
        if ret == None:
            self.msg( '(lldp parse) error parsing port ID TLV' )
            return
        pduhead += ret
        if self.tlvs[len(self.tlvs)-1].type != lldp.PORT_ID_TLV:
            self.msg( '(lldp parse) error port ID TLV missing' )
            return

        # get  TTL
        ret = self.next_tlv(self.arr[pduhead:])
        if ret == None:
            self.msg( '(lldp parse) error parsing TTL TLV' )
            return
        pduhead += ret
        if self.tlvs[len(self.tlvs)-1].type != lldp.TTL_TLV:
            self.msg( '(lldp parse) error port TTL TLV missing' )
            return

        # Loop over all other TLVs 
        arr_len = len(self.arr) 
        while 1:
            ret = self.next_tlv(self.arr[pduhead:])
            if ret == None:
                break
            if self.tlvs[len(self.tlvs)-1].type == lldp.END_TLV:
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

    def hdr(self):
        packet = ''
        for tlv in self.tlvs:
            packet += tlv.tostring()
        return packet    
