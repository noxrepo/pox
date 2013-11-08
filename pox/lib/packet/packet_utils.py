# Copyright 2011,2012 James McCauley
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

"""
Various functionality and data for the packet library
"""

import array
import struct
from socket import ntohs

import protocols as p

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
_ethtype_to_str[0x8848] = 'MPLSM' # Multicast
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
_ipproto_to_str  = p.protocols().get()

class MalformedException (RuntimeError):
  pass


class TruncatedException (RuntimeError):
  pass


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
  if t <= 0x05dc:
    return "802.3/%04x" % (t,)
  return _ethtype_to_str.get(t, "%04x" % (t,))


def ipproto_to_str(t):
  if t in _ipproto_to_str:
    return _ipproto_to_str[t]
  else:
    return "%02x" % (t,)
