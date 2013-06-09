# Copyright 2011,2012 James McCauley
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

"""
Various functionality and data for the packet library
"""

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
_ethtype_to_str[0x888e] = 'PAE'
_ethtype_to_str[0x8847] = 'MPLS'
_ethtype_to_str[0x8848] = 'MPLS_MC' # Multicast
_ethtype_to_str[0x86dd] = 'IPV6'
_ethtype_to_str[0x880b] = 'PPP'
_ethtype_to_str[0x88bb] = 'LWAPP'
_ethtype_to_str[0x880c] = 'GSMP'
_ethtype_to_str[0x8137] = 'IPX'
_ethtype_to_str[0x0842] = 'WOL' # Wake On LAN
_ethtype_to_str[0x22f3] = 'TRILL'
_ethtype_to_str[0x8870] = 'JUMBO'
_ethtype_to_str[0x889a] = 'SCSI' # SCSI Over Ethernet
_ethtype_to_str[0x88a2] = 'ATA' # ATA Over Ethernet
_ethtype_to_str[0x9100] = 'QINQ'
_ethtype_to_str[0xffff] = 'BAD'


# IP protocol to string
#TODO: This should probably be integrated with the decorator used in
#      the ipv6 module.
_ipproto_to_str[0]  = 'HOP_OPTS'
_ipproto_to_str[1]  = 'ICMP'
_ipproto_to_str[2]  = 'IGMP'
_ipproto_to_str[4]  = 'IPIP'
_ipproto_to_str[6]  = 'TCP'
_ipproto_to_str[9]  = 'IGRP'
_ipproto_to_str[17] = 'UDP'
_ipproto_to_str[43] = 'IPV6_ROUTING'
_ipproto_to_str[44] = 'IPV6_FRAG'
_ipproto_to_str[47] = 'GRE'
_ipproto_to_str[58] = 'ICMP6'
_ipproto_to_str[59] = 'IPV6_NO_NEXT'
_ipproto_to_str[60] = 'DEST_OPTS'
_ipproto_to_str[89] = 'OSPF'


class MalformedException (RuntimeError):
  pass


class TruncatedException (RuntimeError):
  pass


def checksum (data, start = 0, skip_word = None):
  """
  Calculate standard internet checksum over data starting at start'th byte

  skip_word: If specified, it's the word offset of a word in data to "skip"
             (as if it were zero).  The purpose is when data is received
             data which contains a computed checksum that you are trying to
             verify -- you want to skip that word since it was zero when
             the checksum was initially calculated.
  """
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
    start += struct.unpack('H', data[-1]+'\0')[0] # Specify order?

  start  = (start >> 16) + (start & 0xffff)
  start += (start >> 16)
  #while start >> 16:
  #  start = (start >> 16) + (start & 0xffff)

  return ntohs(~start & 0xffff)


def ethtype_to_str (t):
  """
  Given numeric ethernet type or length, return human-readable representation
  """
  if t <= 0x05dc:
    return "802.3/%04x" % (t,)
  return _ethtype_to_str.get(t, "%04x" % (t,))


def ipproto_to_str (t):
  """
  Given a numeric IP protocol number (or IPv6 next_header), give human name
  """
  if t in _ipproto_to_str:
    return _ipproto_to_str[t]
  else:
    return "%02x" % (t,)
