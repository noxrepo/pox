# Copyright 2011 James McCauley
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
from .packet_utils       import *

from .packet_base import packet_base

from .eap import *

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

    @staticmethod
    def type_name(type):
        return eapol.type_names.get(type, "type%d" % type)

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.version = self.V1_PROTO
        self.type = self.EAP_TYPE
        self.bodylen = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[EAPOL v%d %s]' % (self.version, self.type_name(self.type))
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(eapol parse) warning EAPOL packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.version, self.type, self.bodylen) \
            = struct.unpack('!BBH', raw[:self.MIN_LEN])

        self.parsed = True

        if self.type == self.EAP_TYPE:
            self.next = eap(raw=raw[self.MIN_LEN:], prev=self)
        elif (self.type == self.EAPOL_START_TYPE
              or self.type == self.EAPOL_LOGOFF_TYPE):
            pass                # These types have no payloads.
        else:
            self.msg('warning unsupported EAPOL type: %s' % (self.type_name(self.type),))

    def hdr(self, payload):
        return struct.pack('!BBH', self.version, self.type, self.bodylen)
