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
A simple component that dumps packet_in info to the log.

Use --verbose for really verbose dumps.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpidToStr

log = core.getLogger()

_verbose = None
_max_length = None


def _handle_PacketIn (event):
  packet = event.parsed

  msg = dpidToStr(event.dpid) + ": "
  msg = ""
  if _verbose:
    msg += str(packet)
  else:
    p = packet
    while p:
      if isinstance(p, basestring):
        msg += "[%s bytes]" % (len(p),)
        break
      msg += "[%s]" % (p.__class__.__name__,)
      p = p.next

  if _max_length:
    if len(msg) > _max_length:
      msg = msg[:_max_length-3]
      msg += "..."
  core.getLogger("dump:" + dpidToStr(event.dpid)).debug(msg)


def launch (verbose = False, max_length = 110, full_packets = True):
  global _verbose, _max_length
  _verbose = verbose
  _max_length = max_length

  if full_packets:
    # Send full packets to controller
    core.openflow.miss_send_len = 0xffff

  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Packet dumper running")
