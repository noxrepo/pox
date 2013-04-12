# Copyright 2013 James McCauley
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
Utilities for writing/synthesizing pcap files
"""

import time as pytime
import datetime
from struct import pack

#TODO: Incorporate the one from lib.socketcapture

class PCapRawWriter (object):
  def __init__ (self, outstream, flush = False):
    """
    outstream is the stream to write the PCAP trace to.
    """
    self._out = outstream
    self._flush = flush

    outstream.write(pack("IHHiIII",
      0xa1b2c3d4,      # Magic
      2,4,             # Version
      pytime.timezone, # TZ offset
      0,               # Accuracy of timestamps (apparently 0 is OK)
      0x7fffFFff,      # Snaplen
      1                # Ethernet
      ))

  def write (self, buf, time = None, wire_size = None):
    if len(buf) == 0: return
    if wire_size is None:
      wire_size = len(buf)

    assert wire_size >= len(buf), "cap size > wire size!"

    if time is None:
      t = pytime.time()
    elif isinstance(time, (datetime.datetime, datetime.time)):
      #TODO: TZ?
      t = pytime.mktime(time.timetuple()) + (time.microsecond / 1000000.0)
    else:
      t = time
    ut = t - int(t)
    t = int(t)
    ut = int(ut * 1000000)
    self._out.write(pack("IIII",
      t,ut,          # Timestamp
      len(buf),      # Saved size
      wire_size,     # Original size
      ))

    self._out.write(buf)
    if self._flush: self._out.flush()

