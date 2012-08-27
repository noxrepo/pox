# Copyright 2011 Andreas Wundsam
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

import struct

from pox.lib.util import initHelper

# Nicira Vendor extensions. Welcome to embrace-and-extend-town
VENDOR_ID = 0x00002320
# sub_types
ROLE_REQUEST = 10
ROLE_REPLY = 11
# role request / reply patterns
ROLE_OTHER = 0
ROLE_MASTER = 1
ROLE_SLAVE = 2

class nx_data(object):
  """ base class for the data field of Nicira vendor extension
      commands. Picked from the floodlight source code.
  """
  def __init__ (self, **kw):
    self.subtype = 0
    self.length = 4

    initHelper(self, kw)

  def _assert (self):
    return (True, None)

  def pack (self, assertstruct=True):
    if(assertstruct):
      if(not self._assert()[0]):
        return None
    packed = ""
    packed += struct.pack("!L", self.subtype)
    return packed

  def unpack (self, binaryString):
    if (len(binaryString) < 4):
      return binaryString
    (self.subtype,) = struct.unpack_from("!L", binaryString, 0)
    return binaryString[4:]

  def __len__ (self):
    return 4

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.subtype !=  other.subtype: return False
    return True

  def __ne__ (self, other): return not self.__eq__(other)

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += prefix + 'subtype: ' + str(self.subtype) + '\n'
    return outstr

class role_data(nx_data):
  """ base class for the data field of nx role requests."""
  def __init__ (self, subtype, **kw):
    nx_data.__init__(self)
    self.subtype = subtype
    self.role = ROLE_OTHER
    self.length = 8

    initHelper(self, kw)

  def _assert (self):
    return (True, None)

  def pack (self, assertstruct=True):
    if(assertstruct):
      if(not self._assert()[0]):
        return None
    packed = ""
    packed += nx_data.pack(self)
    packed += struct.pack("!L", self.role)
    return packed

  def unpack (self, binaryString):
    if (len(binaryString) < 8):
      return binaryString
    nx_data.unpack(self, binaryString[0:])
    (self.role,) = struct.unpack_from("!L", binaryString, 4)
    return binaryString[8:]

  def __len__ (self):
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not nx_data.__eq__(self, other): return False
    if self.role !=  other.role: return False
    return True

  def __ne__ (self, other): return not self.__eq__(other)

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += nx_data.show(self, prefix + '  ')
    outstr += prefix + 'role: ' + str(self.role) + '\n'
    return outstr

class role_request_data(role_data):
  """ Role request. C->S """
  def __init__ (self, **kw):
    role_data.__init__(self, ROLE_REQUEST, **kw)

class role_reply_data(role_data):
  """ Role reply S->C """
  def __init__ (self, **kw):
    role_data.__init__(self, ROLE_REPLY, **kw)

_nx_subtype_to_type = {
    ROLE_REQUEST: role_request_data,
    ROLE_REPLY: role_reply_data
}

def unpack_vendor_data_nx(data):
    if len(data) < 4: raise RuntimeError("NX vendor data<4 bytes")
    nx = nx_data()
    nx.unpack(data)
    if nx.subtype in _nx_subtype_to_type:
      res = _nx_subtype_to_type[nx.subtype]()
      res.unpack(data)
      return res
    else:
      raise NotImplementedError("subtype not implemented: %d" % nx.subtype)
