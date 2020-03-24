# Copyright 2012 James McCauley
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
A simple component that dumps packet_in info to the log.

Use --verbose for really verbose dumps.
Use --show to show all packets.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpidToStr

log = core.getLogger()

_verbose = None
_max_length = None
_types = None
_show_by_default = None

def _handle_PacketIn (event):
  packet = event.parsed

  show = _show_by_default
  p = packet
  while p:
    if p.__class__.__name__.lower() in _types:
      if _show_by_default:
        # This packet is hidden
        return
      else:
        # This packet should be shown
        show = True
        break
      return
    if not hasattr(p, 'next'): break
    p = p.next

  if not show: return

  msg = dpidToStr(event.dpid) + ": "
  msg = ""
  if _verbose:
    msg += packet.dump()
  else:
    p = packet
    while p:
      if isinstance(p, bytes):
        msg += "[%s bytes]" % (len(p),)
        break
      elif isinstance(p, str):
        msg += "[%s chars]" % (len(p),)
        break
      msg += "[%s]" % (p.__class__.__name__,)
      p = p.next

  if _max_length:
    if len(msg) > _max_length:
      msg = msg[:_max_length-3]
      msg += "..."
  core.getLogger("dump:" + dpidToStr(event.dpid)).debug(msg)


def launch (verbose = False, max_length = 110, full_packets = True,
            hide = False, show = False):
  global _verbose, _max_length, _types, _show_by_default
  _verbose = verbose
  _max_length = max_length
  force_show = (show is True) or (hide is False and show is False)
  if isinstance(hide, str):
    hide = hide.replace(',', ' ').replace('|', ' ')
    hide = set([p.lower() for p in hide.split()])
  else:
    hide = set()
  if isinstance(show, str):
    show = show.replace(',', ' ').replace('|', ' ')
    show = set([p.lower() for p in show.split()])
  else:
    show = set()

  if hide and show:
    raise RuntimeError("Can't both show and hide packet types")

  if show:
    _types = show
  else:
    _types = hide
  _show_by_default = not not hide
  if force_show:
    _show_by_default = force_show

  if full_packets:
    # Send full packets to controller
    core.openflow.miss_send_len = 0xffff

  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Packet dumper running")
