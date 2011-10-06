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
#                     DNS Message Format
#
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                      ID                       |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                 Total Questions               |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                 Total Answerrs                |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |              Total Authority RRs              |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |               Total Additional RRs            |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                 Questions ...                 |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |               Answer RRs  ...                 |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |               Authority RRs..                 |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |               Additional RRs.                 |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
# Question format:
#
#                                   1  1  1  1  1  1
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                                               |
#   /                     QNAME                     /
#   /                                               /
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     QTYPE                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     QCLASS                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
#
#
# All RRs have the following format:
#                                   1  1  1  1  1  1
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                                               |
#   /                                               /
#   /                      NAME                     /
#   |                                               |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                      TYPE                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     CLASS                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                      TTL                      |
#   |                                               |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                   RDLENGTH                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#   /                     RDATA                     /
#   /                                               /
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
#
# TODO:
#   SOA data
#   CNAME data
#   MX data
#======================================================================

import struct
from packet_utils       import *

from packet_base import packet_base

from pox.lib.addresses import IPAddr

rrtype_to_str = {
   1: "A",  # host address
   2: "NS", #an authoritative name server
   3: "MD",        # a mail destination (Obsolete - use MX)
   4: "MF",        # a mail forwarder (Obsolete - use MX)
   5: "CNAME",     # the canonical name for an alias
   6: "SOA",       # marks the start of a zone of authority
   7: "MB" ,       # a mailbox domain name (EXPERIMENTAL)
   8: "MG" ,       # a mail group member (EXPERIMENTAL)
   9: "MR" ,       # a mail rename domain name (EXPERIMENTAL)
   10: "NULL" ,    # a null RR (EXPERIMENTAL)
   11: "WKS"  ,    # a well known service description
   12: "PTR"  ,    # a domain name pointer
   13: "HINFO",    # host information
   14: "MINFO",    # mailbox or mail list information
   15: "MX"   ,    # mail exchange
   16: "TXT",      # text strings
   28: "AAAA" # IPV6 address request
}

rrclass_to_str = {
  1   :"IN", #  1 the Internet
  2   :"CS", #  2 the CSNET class (Obsolete)
  3   :"CH", #  3 the CHAOS class
  4   :"HS", #  4 Hesiod [Dyer 87]
  255 :"* "  #  255 any class
}


class dns(packet_base):
    "DNS Packet struct"

    SERVER_PORT = 53
    MIN_LEN     = 12

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.questions   = []
        self.answers     = []
        self.authorities = []
        self.additional  = []

        self.id = 0
        self.qr = False # Is Query
        self.opcode = 0
        self.aa = False # Authoritative Answer
        self.tc = False # Truncated
        self.rd = False # Recursion Desired
        self.ra = False # Recursion Available
        self.z = False
        self.ad = False
        self.cd = False
        self.rcode = 0
        # TODO: everything else here

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def hdr (self, payload):
        bits0 = 0
        if self.qr: bits0 |= 0x80
        bits0 |= (self.opcode & 0x7) << 4
        if self.rd: bits0 |= 1
        if self.tc: bits0 |= 2
        if self.aa: bits0 |= 4
        bits1 = 0
        if self.ra: bits1 |= 0x80
        if self.z: bits1 |= 0x40
        if self.ad: bits1 |= 0x20
        if self.cd: bits1 |= 0x10
        bits1 |= (self.rcode & 0xf)

        s = struct.pack("!HBBHHHH", self.id, bits0, bits1,
                        len(self.questions), len(self.answers), 
                        len(self.authorities), len(self.additional))

        def makeName (labels, term):
          o = '' #TODO: unicode
          for l in labels.split('.'):
            o += chr(len(l))
            o += l
          if term: o += '\x00'
          return o

        def putName (name):
          pre = ''
          post = name
          while True:
            at = s.find(makeName(post, True))
            if at == -1:
              post = post.split('.', 1)
              pre = '.'.join(pre, post[0])
              if len(post) == 1:
                if len(pre) == 0:
                  s += '\x00'
                else:
                  s += makeName(pre, True)
                break
              post = post[1]
            else:
              if len(pre) > 0:
                s += makeName(pre, False)
              s += struct.pack("!H", at | 0xc0)
              break

        for r in self.questions:
          putName(r.name)
          s += struct.pack("!HH", r.qtype, r.qclass)

        for r in self.answers:
          putName(r.name)
          s += struct.pack("!HHIH", r.qtype, r.qclass, r.ttl, len(r.rddata))
          s += r.rddata

        for r in self.authorities:
          putName(r.name)
          s += struct.pack("!HHIH", r.qtype, r.qclass, r.ttl, len(r.rddata))
          s += r.rddata

        for r in self.additional:
          putName(r.name)
          s += struct.pack("!HHIH", r.qtype, r.qclass, r.ttl, len(r.rddata))
          s += r.rddata


    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < dns.MIN_LEN:
            self.msg('(dns parse) warning DNS packet data too short to '
                     + 'parse header: data len %u' % (dlen,))
            return None

        bits0 = 0
        bits1 = 0
        total_questions = 0
        total_answers = 0
        total_auth_rr = 0
        total_add_rr = 0
        (self.id, bits0,bits1, total_questions, total_answers,
         total_auth_rr, total_add_rr)\
             = struct.unpack('!HBBHHHH', raw[:12])

        self.qr = True if (bits0 & 0x80) else False
        self.opcode = (bits0 >> 4) & (0x07)
        self.aa     = True if (bits0 & (0x04)) else False
        self.tc     = True if (bits0 & (0x02)) else False
        self.rd     = True if (bits0 & (0x01)) else False
        self.ra     = True if (bits1 & 0x80) else False
        self.z      = True if (bits1 & 0x40) else False
        self.ad     = True if (bits1 & 0x20) else False
        self.cd     = True if (bits1 & 0x10) else False
        self.rcode  = bits1 & 0x0f

        query_head = 12

        # questions
        for i in range(0,total_questions):
            try:
                query_head = self.next_question(raw, query_head)
            except Exception, e:
                self.err('(dns) parsing questions: ' + str(e))
                return None

        # answers
        for i in range(0,total_answers):
            try:
                query_head = self.next_rr(raw, query_head, self.answers)
            except Exception, e:
                self.err('(dns) parsing answers: ' + str(e))
                return None

        # authoritative name servers
        for i in range(0,total_auth_rr):
            try:
                query_head = self.next_rr(raw, query_head, self.authorities)
            except Exception, e:
                self.err('(dns) parsing authoritative name servers: '
                         + str(e))
                return None

        # additional resource records
        for i in range(0,total_add_rr):
            try:
                query_head = self.next_rr(raw, query_head, self.additional)
            except Exception, e:
                self.err('(dns) parsing additional resource records: '
                         + str(e))
                return None

        self.parsed = True

    def __str__(self):
        flags = "|"

        if self.qr != 0:
            flags += "QR "
        if self.tc != 0:
            flags += "TR "
        if self.rd != 0:
            flags += "RD "
        if self.ra != 0:
            flags += "RA "
        if self.z != 0:
            flags += "Z "

        flags += "|"

        s = "(id:%x fl:%s op:%d nq:%d na:%d nath:%d nadd:%d)" % (self.id,
         flags, self.opcode, len(self.questions), len(self.answers),
         len(self.authorities), len(self.additional))

        if len(self.questions) > 0:
            for q in self.questions:
                s += "(q? "+str(q)+")"

        if len(self.answers) > 0:
            for a in self.answers:
                s += "(answ: "+str(a)+")"

        if len(self.authorities) > 0:
            for a in self.authorities:
                s += "(auth: "+str(a)+")"

        if len(self.additional) > 0:
            for a in self.additional:
                s += "(add: "+str(a)+")"

        if self.next == None:
            return s
        return ''.join((s, str(self.next)))

    # Utility methods for parsing.  Generally these would be pulled out
    # into a separate class. However, because the lengths are not known
    # until the fields have been parsed, it is more convenient to keep
    # them in the DNS class

    def _read_dns_name_from_index(self, l, index, retlist):
        while True:
            chunk_size = ord(l[index])

            # check whether we have in internal pointer
            if (chunk_size & 0xc0) == 0xc0:
                # pull out offset from last 14 bits
                offset = ((ord(l[index]) & 0x3) << 8 ) | ord(l[index+1])
                self._read_dns_name_from_index(l, offset, retlist)
                index += 1
                break
            if chunk_size == 0:
                break
            index += 1
            retlist.append(l[index : index + chunk_size])
            index += chunk_size
        return index

    def read_dns_name_from_index(self, l, index):
        retlist = []
        next = self._read_dns_name_from_index(l, index, retlist)
        return (next + 1, ".".join(retlist))

    def next_rr(self, l, index, rr_list):
        array_len = len(l)

        # verify whether name is offset within packet
        if index > array_len:
            raise Exception("next_rr: name truncated")

        index,name = self.read_dns_name_from_index(l, index)

        if index + 10 > array_len:
            raise Exception("next_rr: truncated")

        (qtype,qclass,ttl,rdlen) = struct.unpack('!HHIH', l[index:index+10])
        if index+10+rdlen > array_len:
            raise Exception("next_rr: data truncated")

        rddata = self.get_rddata(l, qtype, rdlen, index + 10)
        rr_list.append(dns.rr(name, qtype, qclass,ttl,rdlen,rddata))

        return index + 10 + rdlen

    def get_rddata(self, l, type, dlen, beg_index):
        if beg_index + dlen > len(l):
            raise Exception('(dns) truncated rdata')
        # A
        if type == 1:
            if dlen != 4:
                raise Exception('(dns) invalid a data size',system='packet')
            return IPAddr(l[beg_index : beg_index + 4])
        # NS
        elif type == 2:
            return self.read_dns_name_from_index(l, beg_index)[1]
        # PTR
        elif type == 12:
            return  self.read_dns_name_from_index(l, beg_index)[1]
        # MX
        elif type == 15:
            # Jump past priorit (this should really be saves XXX)
            return self.read_dns_name_from_index(l, beg_index + 2)[1]
        else:
            return l[beg_index : beg_index + dlen]

    def next_question(self, l, index):
        array_len = len(l)

        index,name = self.read_dns_name_from_index(l, index)

        if index + 4 > array_len:
            raise Exception("next_question: truncated")

        (qtype,qclass) = struct.unpack('!HH', l[index:index+4])
        self.questions.append(dns.question(name, qtype, qclass))
        return index + 4

    # Utility classes for questions and RRs

    class question:

        def __init__(self, name, qtype, qclass):
            self.name   = name
            self.qtype  = qtype
            self.qclass = qclass

        def __str__(self):
            s = self.name
            if self.qtype in rrtype_to_str:
                s += " " + rrtype_to_str[self.qtype]
            else:
                s += " ??? "
            if self.qclass in rrclass_to_str:
                s += " " + rrclass_to_str[self.qclass]
            else:
                s += " ??? "

            return s

    class rr:

        A_TYPE     = 1
        NS_TYPE    = 2
        MD_TYPE    = 3
        MF_TYPE    = 4
        CNAME_TYPE = 5
        SOA_TYPE   = 6
        MB_TYPE    = 7
        MG_TYPE    = 8
        MR_TYPE    = 9
        NULL_TYPE  = 10
        WKS_TYPE   = 11
        PTR_TYPE   = 12
        HINFO_TYPE = 13
        MINFO_TYPE = 14
        MX_TYPE    = 15
        TXT_TYPE   = 16
        AAAA_TYPE  = 28

        def __init__(self, _name, _qtype, _qclass, _ttl, _rdlen, _rddata):
            self.name   = _name
            self.qtype  = _qtype
            self.qclass = _qclass
            self.ttl    = _ttl
            self.rdlen  = _rdlen
            self.rddata = _rddata

        def __str__(self):
            s = self.name
            if self.qtype in rrtype_to_str:
                s += " " + rrtype_to_str[self.qtype]
            else:
                s += " ??? "
            if self.qclass in rrclass_to_str:
                s += " " + rrclass_to_str[self.qclass]
            else:
                s += " ??? "
            s += " ttl:"+str(self.ttl)
            s += " rdlen:"+str(self.rdlen)
            s += " data: "+str(self.rddata)

            return s
