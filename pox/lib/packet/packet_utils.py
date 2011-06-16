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
# Utility functions to support construction and printing of Ethernet/IP
# packets
#======================================================================
import array
import struct
from socket import ntohs

_ethtype_to_str = {}
_ipproto_to_str = {}

# Map ethernet oui to name
_ethoui2name = {}

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

def checksum(data, start, skip_word = 0):

    if len(data) % 2 != 0:
        arr = array.array('H', data[:-1])
    else:
        arr = array.array('H', data)

    if skip_word:
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
    start += (start >> 16);

    return ntohs(~start & 0xffff)


def ip_to_str(a):
    return "%d.%d.%d.%d" % ((a >> 24) & 0xff, (a >> 16) & 0xff, \
                            (a >> 8) & 0xff, a & 0xff)


def ipstr_to_int(a):                            
    octets = a.split('.')
    return int(octets[0]) << 24 |\
           int(octets[1]) << 16 |\
           int(octets[2]) <<  8 |\
           int(octets[3]);

def array_to_ipstr(a):
    return "%d.%d.%d.%d" % (a[0], a[1], a[2], a[3])

def octstr_to_array(ocstr):
    a = array.array('B')
    for item in ocstr.split(':'):
        a.append(int(item, 16))
    return a    
                          
def array_to_octstr(arr):
    bstr = ''
    for byte in arr:
        if bstr != '':
            bstr += ':%02x' % (byte,)
        else:    
            bstr += '%02x' %(byte,)
    return bstr        

def longlong_to_octstr(ll):
    return array_to_octstr(array.array('B',struct.pack('!Q',ll)))

def mac_to_oui(a):
    if type(a) == type(1L):
        a = struct.pack('!Q', a)[2:]
    if type(a) == type(''):
        a = array.array('B',a)

    oui = int(a[0]) << 16 | int(a[1]) << 8 | int(a[2])

    if _ethoui2name.has_key(oui):
        return _ethoui2name[oui]
    else:
        return ""

def mac_to_str(a, resolve_name = False):
    if type(a) == type(1L):
        a = struct.pack('!Q', a)[2:]
    if type(a) == type(''):
        a = array.array('B', a)

    oui = int(a[0]) << 16 | int(a[1]) << 8 | int(a[2])

    # check if globally unique
    if resolve_name and not (a[0] & 0x2):
        if _ethoui2name.has_key(oui):
            return "(%s):%02x:%02x:%02x" %( _ethoui2name[oui], a[3],a[4],a[5])
    return array_to_octstr(a) 

def mac_to_int(mac):
    value = 0
    for byte in struct.unpack('6B', mac):
        value = (value << 8) | byte
    return long(value)

def ethtype_to_str(t):
    if t < 0x0600:
        return "llc"
    if _ethtype_to_str.has_key(t):
        return _ethtype_to_str[t]
    else:    
        return "%x" % t

def ipproto_to_str(t):
    if _ipproto_to_str.has_key(t):
        return _ipproto_to_str[t]
    else:    
        return "%x" % t

def load_oui_names():
    import os
    filename = 'nox/lib/packet/oui.txt'
    if not os.access(filename, os.R_OK):
        return None
    for line in open(filename).readlines():
        if len(line) < 1:
            continue
        if line[0].isspace():
            continue
        split = line.split(' ')
        if not '-' in split[0]:
            continue
        # grab 3-byte OUI
        oui_str  = split[0].replace('-','')
        # strip off (hex) identifer and keep rest of name 
        end = ' '.join(split[1:]).strip()
        end = end.split('\t')
        end.remove('(hex)')
        oui_name = ' '.join(end)  
        # convert oui to int
        oui = int(oui_str, 16)
        _ethoui2name[oui] = oui_name.strip()

load_oui_names()
