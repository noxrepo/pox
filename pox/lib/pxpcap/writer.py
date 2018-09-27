# Copyright 2013 James McCauley
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

"""
Utilities for writing/synthesizing pcap files
"""

import time as pytime
import datetime
from struct import pack

#TODO: Incorporate the one from lib.socketcapture

class PCapRawWriter (object):
  def __init__ (self, outstream, flush = False, ip = False):
    """
    outstream is the stream to write the PCAP trace to.
    if ip, write IP packets instead of Ethernet
    """
    self._out = outstream
    self._flush = flush

    outstream.write(pack("IHHiIII",
      0xa1b2c3d4,      # Magic
      2,4,             # Version
      pytime.timezone, # TZ offset
      0,               # Accuracy of timestamps (apparently 0 is OK)
      0x7fffFFff,      # Snaplen
      101 if ip else 1 # IP or Ethernet
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
