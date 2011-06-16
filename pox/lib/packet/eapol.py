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
#
# EAPOL Header Format (see IEEE 802.1X-2004):
#
# Octet 0: Protocol version (1 or 2).
# Octet 1: Packet type:
#   0 = EAP packet
#   1 = EAPOL-Start
#   2 = EAPOL-Logoff
#   3 = EAPOL-Key
#   4 = EAPOL-Encapsulated-ASF-Alert
# Octets 2-3: Length of packet body field (0 if packet body is absent)
# Octets 4-end: Packet body (present only for packet types 0, 3, 4)
#
#======================================================================
import struct
from packet_utils       import *
from packet_exceptions  import *
from array import *

from packet_base import packet_base 

from eap import *

class eapol(packet_base):
    "EAP over LAN packet"

    MIN_LEN = 4

    V1_PROTO = 1
    V2_PROTO = 2

    EAP_TYPE = 0
    EAPOL_START_TYPE = 1
    EAPOL_LOGOFF_TYPE = 2
    EAPOL_KEY_TYPE = 3
    EAPOL_ENCAPSULATED_ASF_ALERT = 4
    type_names = {EAP_TYPE: "EAP",
                  EAPOL_START_TYPE: "EAPOL-Start",
                  EAPOL_LOGOFF_TYPE: "EAPOL-Logoff",
                  EAPOL_KEY_TYPE: "EAPOL-Key",
                  EAPOL_ENCAPSULATED_ASF_ALERT: "EAPOL-Encapsulated-ASF-Alert"}
    def type_name(type):
        return eapol.type_names.get(type, "type%d" % type)
    type_name = staticmethod(type_name)

    def __init__(self, arr=None,prev=None):
        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.version = self.V1_PROTO
        self.type = self.EAP_TYPE
        self.bodylen = 0

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def __str__(self):
        s = '{ EAPOL v%d %s }' % (self.version, self.type_name(self.type))
        if self.next != None:
            s += str(self.next)
        return s

    def parse(self):
        dlen = len(self.arr)
        if dlen < self.MIN_LEN:
            self.msg('(eapol parse) warning EAPOL packet data too short to parse header: data len %u' % dlen)
            return

        (self.version, self.type, self.bodylen) \
            = struct.unpack('!BBH', self.arr[:self.MIN_LEN])

        self.parsed = True

        if self.type == self.EAP_TYPE:
            self.next = eap(arr=self.arr[self.MIN_LEN:], prev=self)
        elif (self.type == self.EAPOL_START_TYPE
              or self.type == self.EAPOL_LOGOFF_TYPE):
            pass                # These types have no payloads.
        else:
            self.msg('warning unsupported EAPOL type: ' % self.type_name(self.type))

    def set_payload(self, payload):
        self.next = payload


    def hdr(self):    
        return struct.pack('!BBH', self.version, self.type, self.bodylen)
