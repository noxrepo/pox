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
#
#                           TCP Header Format
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Data |           |U|A|P|R|S|F|                               |
#  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
#  |       |           |G|K|H|T|N|N|                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           Checksum            |         Urgent Pointer        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Options                    |    Padding    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct
from packet_utils       import *
from socket import htons
from socket import htonl

from packet_base import packet_base

import logging
lg = logging.getLogger('packet')

class tcp_opt:

    EOL      = 0
    NOP      = 1
    MSS      = 2
    WSOPT    = 3
    SACKPERM = 4
    SACK     = 5
    TSOPT    = 8

    def __init__(self, type, val):
        self.type = type
        self.val  = val

    def to_bytes(self):
        if self.type == tcp_opt.EOL or self.type == tcp_opt.NOP:
            return struct.pack('B',self.type)
        elif self.type == tcp_opt.MSS:
            return struct.pack('!BBH',self.type,4,self.val)
        elif self.type == tcp_opt.WSOPT:
            return struct.pack('!BBB',self.type,3,self.val)
        elif self.type == tcp_opt.SACKPERM:
            return struct.pack('!BB',self.type,2)
        elif self.type == tcp_opt.SACK:
            return struct.pack("!" + "II" * len(self.val),
                               *[x for p in self.val for x in p])
        elif self.type == tcp_opt.TSOPT:
            return struct.pack('!BBII',self.type,10,self.val[0],self.val[1])
        else:
            lg.info('(tcp_opt to_bytes) warning, unknown option type ' +
                    str(self.type))
            return ''

class tcp(packet_base):
    "TCP packet struct"

    MIN_LEN = 20

    FIN_flag = 0x01
    SYN_flag = 0x02
    RST_flag = 0x04
    PSH_flag = 0x08
    ACK_flag = 0x10
    URG_flag = 0x20
    ECN_flag = 0x40
    CWR_flag = 0x80

    @property
    def FIN (self): return True if self.flags & self.FIN_flag else False
    @property
    def SYN (self): return True if self.flags & self.SYN_flag else False
    @property
    def RST (self): return True if self.flags & self.RST_flag else False
    @property
    def PSH (self): return True if self.flags & self.PSH_flag else False
    @property
    def ACK (self): return True if self.flags & self.ACK_flag else False
    @property
    def URG (self): return True if self.flags & self.URG_flag else False
    @property
    def ECN (self): return True if self.flags & self.ECN_flag else False
    @property
    def CWR (self): return True if self.flags & self.CWR_flag else False

    @FIN.setter
    def FIN (self, value): self._setflag(self.FIN_flag, value)
    @SYN.setter
    def SYN (self, value): self._setflag(self.SYN_flag, value)
    @RST.setter
    def RST (self, value): self._setflag(self.RST_flag, value)
    @PSH.setter
    def PSH (self, value): self._setflag(self.PSH_flag, value)
    @ACK.setter
    def ACK (self, value): self._setflag(self.ACK_flag, value)
    @URG.setter
    def URG (self, value): self._setflag(self.URG_flag, value)
    @ECN.setter
    def ECN (self, value): self._setflag(self.ECN_flag, value)
    @CWR.setter
    def CWR (self, value): self._setflag(self.CWR_flag, value)

    def _setflag (self, flag, value):
      self.flags = (self.flags & ~flag) | (flag if value else 0)

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.srcport  = 0  # 16 bit
        self.dstport  = 0  # 16 bit
        self.seq      = 0  # 32 bit
        self.ack      = 0  # 32 bit
        self.off      = 0  # 4 bits
        self.res      = 0  # 4 bits
        self.flags    = 0  # reserved, 2 bits flags 6 bits
        self.win      = 0  # 16 bits
        self.csum     = 0  # 16 bits
        self.urg      = 0  # 16 bits
        self.tcplen   = 0  # Options? #TODO: FIXME
        self.options  = []
        self.next     = b''

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = ''.join(('{', str(self.srcport), '>',
                         str(self.dstport), '} seq:',
                         str(self.seq), ' ack:', str(self.ack), ' f:',
                         hex(self.flags)))
        if self.next is None or type(self.next) is bytes:
            return s
        return ''.join((s, str(self.next)))

    def parse_options(self, raw):

        self.options = []
        dlen = len(raw)

        # option parsing
        i = tcp.MIN_LEN
        arr = raw

        while i < self.hdr_len:
            # Single-byte options
            if ord(arr[i]) == tcp_opt.EOL:
                break
            if ord(arr[i]) == tcp_opt.NOP:
                self.options.append(tcp_opt(tcp_opt.NOP,None))
                i += 1
                continue

            # Sanity checking
            if i + 2 > dlen:
                raise RuntimeError("Very truncated TCP option")
            if i + ord(arr[i+1]) > dlen:
                raise RuntimeError("Truncated TCP option")
            if ord(arr[i+1]) < 2:
                raise RuntimeError("Illegal TCP option length")

            # Actual option parsing
            if ord(arr[i]) == tcp_opt.MSS:
                if ord(arr[i+1]) != 4:
                    raise RuntimeError("MSS option length != 4")
                val = struct.unpack('!H',arr[i+2:i+4])[0]
                self.options.append(tcp_opt(tcp_opt.MSS,val))
            elif ord(arr[i]) == tcp_opt.WSOPT:
                if ord(arr[i+1]) != 3:
                    raise RuntimeError("WSOPT option length != 3")
                self.options.append(tcp_opt(tcp_opt.WSOPT, ord(arr[i+2])))
            elif ord(arr[i]) == tcp_opt.SACKPERM:
                if ord(arr[i+1]) != 2:
                    raise RuntimeError("SACKPERM option length != 2")
                self.options.append(tcp_opt(tcp_opt.SACKPERM, None))
            elif ord(arr[i]) == tcp_opt.SACK:
                if ord(arr[i+1]) >= 2 and ((ord(arr[i+1])-2) % 8) == 0:
                    num = (ord(arr[i+1]) - 2) / 8
                    val = struct.unpack("!" + "II" * num, arr[i+2:])
                    val = [(x,y) for x,y in zip(val[0::2],val[1::2])]
                    self.options.append(tcp_opt(tcp_opt.SACK, val))
                else:
                    raise RuntimeError("Invalid SACK option")
            elif ord(arr[i]) == tcp_opt.TSOPT:
                if ord(arr[i+1]) != 10:
                    raise RuntimeError("TSOPT option length != 10")
                (val1,val2) = struct.unpack('!II',arr[i+2:i+10])
                self.options.append(tcp_opt(tcp_opt.TSOPT,(val1,val2)))
            else:
                self.msg('(tcp parse_options) warning, unknown option %x '
                         % (ord(arr[i]),))
                self.options.append(tcp_opt(ord(arr[i]), arr[i+2:i+2+ord(arr[i+1])]))

            i += ord(arr[i+1])
        return i

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < tcp.MIN_LEN:
            self.msg('(tcp parse) warning TCP packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.srcport, self.dstport, self.seq, self.ack, offres, self.flags,
        self.win, self.csum, self.urg) \
            = struct.unpack('!HHIIBBHHH', raw[:tcp.MIN_LEN])

        self.off = offres >> 4
        self.res = offres & 0x0f

        self.hdr_len = self.off * 4
        self.payload_len = dlen - self.hdr_len

        self.tcplen = dlen
        if dlen < self.tcplen:
            self.msg('(tcp parse) warning TCP packet data shorter than TCP len: %u < %u' % (dlen, self.tcplen))
            return
        if (self.off * 4) < self.MIN_LEN or (self.off * 4) > dlen :
            self.msg('(tcp parse) warning TCP data offset too long or too short %u' % (self.off,))
            return

        try:
            self.parse_options(raw)
        except Exception as e:
            self.msg(e)
            return

        self.next   = raw[self.hdr_len:]
        self.parsed = True

    def hdr(self, payload, calc_checksum = True):
        if calc_checksum:
            self.csum = self.checksum(payload=payload)
            csum = self.csum
        else:
            csum = 0

        offres = self.off << 4 | self.res
        packet = struct.pack('!HHIIBBHHH',
            self.srcport, self.dstport, self.seq, self.ack,
            offres, self.flags,
            self.win, csum, self.urg)
        for option in self.options:
            packet += option.to_bytes()
        return packet

    def checksum(self, unparsed=False, payload=None):
        """
        Calculates the checksum.
        If unparsed, calculates it on the raw, unparsed data.  This is
        useful for validating that it is correct on an incoming packet.
        """
        if self.prev.__class__.__name__ != 'ipv4':
            self.msg('packet not in ipv4, cannot calculate checksum ' +
                     'over psuedo-header' )
            return 0

        if unparsed:
            payload_len = len(self.raw)
            payload = self.raw
        else:
            if payload is not None:
                pass
            elif isinstance(self.next, packet_base):
                payload = self.next.pack()
            elif self.next is None:
                payload = bytes()
            else:
                payload = self.next
            payload = self.hdr(None, calc_checksum = False) + payload
            payload_len = len(payload)

        ippacket = struct.pack('!IIBBH', self.prev.srcip.toUnsigned(),
                                         self.prev.dstip.toUnsigned(),
                                         0,
                                         self.prev.protocol,
                                         payload_len)

        return checksum(ippacket + payload, 0, 14)
