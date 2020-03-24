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
# From RFC 3748 "Extensible Authentication Protocol (EAP)":
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Code      |  Identifier   |            Length             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Data ...
#   +-+-+-+-+
#
#   Code
#
#      The Code field is one octet and identifies the Type of EAP packet.
#      EAP Codes are assigned as follows:
#
#         1       Request
#         2       Response
#         3       Success
#         4       Failure
#
#      Since EAP only defines Codes 1-4, EAP packets with other codes
#      MUST be silently discarded by both authenticators and peers.
#
#
#   Identifier
#
#      The Identifier field is one octet and aids in matching Responses
#      with Requests.
#
#   Length
#
#      The Length field is two octets and indicates the length, in
#      octets, of the EAP packet including the Code, Identifier, Length,
#      and Data fields.  Octets outside the range of the Length field
#      should be treated as Data Link Layer padding and MUST be ignored
#      upon reception.  A message with the Length field set to a value
#      larger than the number of received octets MUST be silently
#      discarded.
#
#   Data
#
#      The Data field is zero or more octets.  The format of the Data
#      field is determined by the Code field.
#
# Request and response packets have the following format.
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |     Code      |  Identifier   |            Length             |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |     Type      |  Type-Data ...
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#
# Valid type values are as follows:
#
#       1       Identity
#       2       Notification
#       3       Nak (Response only)
#       4       MD5-Challenge
#       5       One Time Password (OTP)
#       6       Generic Token Card (GTC)
#     254       Expanded Types
#     255       Experimental use
#
#======================================================================
import struct
from .packet_utils       import *

from .packet_base import packet_base

class eap(packet_base):
    "Extensible Authentication Protocol packet"

    MIN_LEN = 4

    REQUEST_CODE = 1
    RESPONSE_CODE = 2
    SUCCESS_CODE = 3
    FAILURE_CODE = 4

    IDENTITY_TYPE     = 1
    NOTIFICATION_TYPE = 2
    NAK_TYPE          = 3
    MD5_TYPE          = 4
    OTP_TYPE          = 5
    GTC_TYPE          = 6
    EXPANDED_TYPE     = 254
    EXPERIMENTAL_TYPE = 255

    code_names = {REQUEST_CODE: "request",
                  RESPONSE_CODE: "response",
                  SUCCESS_CODE: "success",
                  FAILURE_CODE: "failure"}

    type_names = { IDENTITY_TYPE : "identity",
                   NOTIFICATION_TYPE : "notification",
                   NAK_TYPE         : "nak",
                   MD5_TYPE  : "md5-challenge",
                   OTP_TYPE  : "OTP",
                   GTC_TYPE  : "GTC",
                   EXPANDED_TYPE  : "expanded",
                   EXPERIMENTAL_TYPE : "experimental"
                 }

    @staticmethod
    def code_name(code):
        return eap.code_names.get(code, "code%d" % code)

    @staticmethod
    def type_name(type):
        return eap.type_names.get(type, "type%d" % type)

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.code = self.REQUEST_CODE
        self.id = 0
        self.length = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[EAP %s id=%d' % (eap.code_name(self.code), self.id)
        if hasattr(self, 'type'):
            s += ' type=%s' % (eap.type_names[self.type],)
        return s + "]"

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(eapol parse) warning EAP packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.code, self.id, self.length) \
            = struct.unpack('!BBH', raw[:self.MIN_LEN])

        self.hdr_len = self.length
        self.payload_len = 0
        self.parsed = True

        if self.code == self.REQUEST_CODE:
            (self.type,) \
                = struct.unpack('!B', raw[self.MIN_LEN:self.MIN_LEN + 1 ])
            # not yet implemented
        elif self.code == self.RESPONSE_CODE:
            (self.type,) \
                = struct.unpack('!B', raw[self.MIN_LEN:self.MIN_LEN + 1 ])
            # not yet implemented
        elif self.code == self.SUCCESS_CODE:
            self.next = None    # Success packets have no payload
        elif self.code == self.REQUEST_CODE:
            self.next = None    # Failure packets have no payload
        else:
            self.msg('warning unsupported EAP code: %s' %
                     (eap.code_name(self.code),))

    def hdr(self, payload):
        return struct.pack('!BBH', self.code, self.id, self.length)
