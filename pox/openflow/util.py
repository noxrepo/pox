# Copyright 2011,2012 James McCauley
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

import pox.openflow.libopenflow_01 as of
import struct


def make_type_to_class_table ():
  """
  DEPRECATED
  """
  classes = {}
  max = -1
  d = of.__dict__
  for k in d.keys():
    if k.startswith('OFPT_'):
      c = 'ofp' + k[4:].lower()
      cls = (d[c])
      num = d[k]
      classes[num] = cls
      if num > max: max = num

  if len(classes) != max + 1:
    raise "Bad protocol to class mapping"

  return [classes[i] for i in range(0, max)]


def make_type_to_unpacker_table ():
  """
  Returns a list of unpack methods.

  The resulting list maps OpenFlow types to functions which unpack
  data for those types into message objects.
  """

  top = max(of._message_type_to_class)

  r = [of._message_type_to_class[i].unpack_new for i in range(0, top)]

  return r
