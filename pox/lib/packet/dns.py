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
from packet_exceptions  import *
from array import *

from packet_base import packet_base 

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

    def __init__(self,arr=None, prev=None):
        self.prev = prev
        if type(arr) == type(''):
            arr = array('B', arr)

        self.questions   = []
        self.answers     = []
        self.authorities = []
        self.additional  = []

        self.id = 0
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.ra = 0
        self.z = 0
        self.ad = 0
        self.cd = 0
        self.rcode = 0
        self.total_questions = 0
        self.total_answers   = 0
        self.total_auth_rr   = 0
        self.total_add_rr    = 0
        # TODO: everything else here

        if arr != None:
            assert(type(arr) == array)
            self.arr = arr
            self.parse()

    def parse(self):
        dlen = len(self.arr)
        if dlen < dns.MIN_LEN:
            self.msg('(dns parse) warning DNS packet data too short to parse header: data len %u' % dlen)
            return None

        bits = 0
        (self.id, bits0,bits1, self.total_questions, self.total_answers,\
        self.total_auth_rr, self.total_add_rr)\
             = struct.unpack('!HBBHHHH', self.arr[:12])

        if (bits0 & 0x80) == 0:
            self.qr = 0
        else:
            self.qr = 1
        self.opcode = (bits0 >> 4) & (0x07)
        self.aa     = bits0 & (0x04)
        self.tc     = bits0 & (0x02)
        self.rd     = bits0 & (0x01)
        self.ra     = bits1 & 0x80
        self.z      = bits1 & 0x40
        self.ad     = bits1 & 0x20
        self.cd     = bits1 & 0x10
        self.rcode  = bits1 & 0x0f

        query_head = 12

        # questions
        for i in range(0,self.total_questions):
            try:
                query_head = self.next_question(query_head)
            except Exception, e:
                self.err('(dns) parsing questions: ' + str(e))
                return None

        # answers 
        for i in range(0,self.total_answers):        
            try:
                query_head = self.next_rr(query_head, self.answers)
            except Exception, e:
                self.err('(dns) parsing answers: ' + str(e))
                return None

        # authoritative name servers
        for i in range(0,self.total_auth_rr):        
            try:
                query_head = self.next_rr(query_head, self.authorities)
            except Exception, e:
                self.err('(dns) parsing authoritative name servers: ' + str(e))
                return None

        # additional resource records
        for i in range(0,self.total_add_rr):        
            try:
                query_head = self.next_rr(query_head, self.additional)
            except Exception, e:
                self.err('(dns) parsing additional resource records: ' + str(e))
                return None

        self.parsed = True

    def __str__(self): 

        if self.parsed == False:
            return ""

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

        s = "(id:%x fl:%s op:%d nq:%d na:%d nath:%d nadd:%d)" %(self.id,
        flags, self.opcode, self.total_questions, self.total_answers,
        self.total_auth_rr, self.total_auth_rr)

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

    def _read_dns_name_from_index(self, index, retlist):
        l = self.arr

        while 1:
            chunk_size = l[index]

            # check whether we have in internal pointer
            if (chunk_size & 0xc0) == 0xc0:
                # pull out offset from last 14 bits
                offset = ((l[index] & 0x3) << 8 ) | l[index+1]
                self._read_dns_name_from_index(offset, retlist)
                index += 1
                break
            if chunk_size == 0:
                break
            index += 1    
            retlist.append(l[index : index + chunk_size].tostring())
            index += chunk_size
        return index

    def read_dns_name_from_index(self, index):
        retlist = []
        next =  self._read_dns_name_from_index(index, retlist)
        return (next + 1, ".".join(retlist))

    def next_rr(self, index, rr_list):        
        l = self.arr
        array_len = len(l)

        # verify whether name is offset within packet 
        if index > array_len:
            raise Exception("next_rr: name truncated") 

        index,name = self.read_dns_name_from_index(index)

        if index + 10 > array_len:
            raise Exception("next_rr: truncated") 

        (qtype,qclass,ttl,rdlen) = struct.unpack('!HHIH', l[index:index+10])
        if index+10+rdlen > array_len:
            raise Exception("next_rr: data truncated") 
            
        rddata = self.get_rddata(qtype, rdlen, index + 10)
        rr_list.append(dns.rr(name, qtype, qclass,ttl,rdlen,rddata))

        return index + 10 +rdlen

    def get_rddata(self, type, dlen, beg_index):
        l = self.arr
        if beg_index + dlen > len(l):
            raise Exception('(dns) truncated rdata')
        # A
        if type == 1:
            if dlen != 4:
                raise Exception('(dns) invalid a data size',system='packet')
            return array_to_ipstr(l[beg_index : beg_index + 4])
        # NS
        elif type == 2:    
            return self.read_dns_name_from_index(beg_index)[1]
        # PTR
        elif type == 12:    
            return  self.read_dns_name_from_index(beg_index)[1]
        # MX
        elif type == 15:    
            # Jump past priorit (this should really be saves XXX)
            return self.read_dns_name_from_index(beg_index + 2)[1]
        else:
            return l[beg_index : beg_index + dlen] 

    def next_question(self, index):        
        l = self.arr

        array_len = len(l)

        index,name = self.read_dns_name_from_index(index)

        if index + 4 > array_len:
            raise Exception("next_question: truncated") 

        (qtype,qclass) = struct.unpack('!HH', self.arr[index:index+4])
        self.questions.append(dns.question(name, qtype, qclass))
        return index + 4 

    # Utility classes for questions and RRs

    class question: 
        
        def __init__(self, _name, _qtype, _qclass):
            self.name   = _name
            self.qtype  = _qtype 
            self.qclass = _qclass 

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
