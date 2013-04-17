# Copyright 2012 James McCauley
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

"""
A parser for pcap data files.

It's not great, but does the job for now.
"""

#TODO:
# Swap names for _sec and _time?
# Add usec to the datetime one?

from datetime import datetime
from struct import unpack_from

class PCapParser (object):
  def __init__ (self, callback = None):
    self._buf = b''
    self._proc = self._proc_global_header
    self._prefix = ''
    self.version = None
    self.snaplen = None
    self.lltype = None

    self.callback = callback

  def _packet (self, data):
    if self.callback:
      self.callback(data, self)

  def _unpack (self, format, data, offset = 0):
    return unpack_from(self._prefix + format, data, offset)

  def _proc_global_header (self):
    header_len = 4 + 2 + 2 + 4 + 4 + 4 + 4
    if len(self._buf) < header_len: return

    magic = self._buf[0:4]
    header = self._buf[4:header_len]

    if magic == "\xd4\xc3\xb2\xa1":
      self._prefix = "<"
    elif magic == "\xa1\xb2\xc3\xd4":
      self._prefix = ">"
    else:
      raise RuntimeError("Wrong magic number")

    major,minor = self._unpack("HH", header[:4])
    self.version = float("%s.%s" % (major,minor))

    if self.version != 2.4:
      raise RuntimeError("Unknown PCap version: %s" % (self.version,))

    tz,accuracy,self.snaplen,self.lltype = self._unpack("LLLL", header[4:])

    self._buf = self._buf[header_len:]
    self._proc = self._proc_header

  def _proc_header (self):
    if len(self._buf) < 16: return
    self._sec_raw,self._usec,self._cap_size, self._wire_size \
        = self._unpack("LLLL", self._buf[:16])
    self._buf = self._buf[16:]
    self._proc = self._proc_packet

  @property
  def _sec (self):
    return datetime.fromtimestamp(self._sec_raw)

  @property
  def _time (self):
    s = self._sec_raw
    s += self._usec / 1000000.0
    return s

  def _proc_packet (self):
    if len(self._buf) < self._cap_size: return
    data = self._buf[:self._cap_size]
    self._buf = self._buf[self._cap_size:]
    self._proc = self._proc_header
    self._packet(data)

  def feed (self, data):
    self._buf += data

    s = len(self._buf)
    while s > 0:
      self._proc()
      new_s = len(self._buf)
      if new_s == s: break
      s = new_s
