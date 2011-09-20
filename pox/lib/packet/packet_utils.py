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
# Utility functions to support construction and printing of Ethernet/IP
# packets
#======================================================================
import array
import struct
from socket import ntohs

_ethtype_to_str = {}
_ipproto_to_str = {}

# Map ethernet type to string
_ethtype_to_str[0x0800] = 'IP'
_ethtype_to_str[0x0806] = 'ARP'
_ethtype_to_str[0x8035] = 'RARP'
_ethtype_to_str[0x8100] = 'VLAN'
_ethtype_to_str[0x88cc] = 'LLDP'

# IP protocol to string
_ipproto_to_str[0]  = 'IP'
_ipproto_to_str[1]  = 'ICMP'
_ipproto_to_str[2]  = 'IGMP'
_ipproto_to_str[4]  = 'IPIP'
_ipproto_to_str[6]  = 'TCP'
_ipproto_to_str[9]  = 'IGRP'
_ipproto_to_str[17] = 'UDP'
_ipproto_to_str[47] = 'GRE'
_ipproto_to_str[89] = 'OSPF'

def checksum (data, start = 0, skip_word = None):

    if len(data) % 2 != 0:
        arr = array.array('H', data[:-1])
    else:
        arr = array.array('H', data)

    if skip_word is not None:
        for i in range(0, len(arr)):
            if i == skip_word:
                continue
            start +=  arr[i]
    else:
        for i in range(0, len(arr)):
            start +=  arr[i]

    if len(data) % 2 != 0:
        start += struct.unpack('H', data[-1]+'\0')[0]

    start  = (start >> 16) + (start & 0xffff)
    start += (start >> 16)

    return ntohs(~start & 0xffff)

def ethtype_to_str(t):
    if t < 0x0600:
        return "llc/%04x" % (t,)
    if _ethtype_to_str.has_key(t):
        return _ethtype_to_str[t]
    else:
        return "%x" % t

def ipproto_to_str(t):
    if _ipproto_to_str.has_key(t):
        return _ipproto_to_str[t]
    else:
        return "%x" % t
