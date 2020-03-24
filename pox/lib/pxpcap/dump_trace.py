# Copyright 2012,2013 James McCauley
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
A simple hack of info.packet_dump that dumps pcap files to the console.

Use --infile=<filename> to specify the pcap file.
Use --verbose for really verbose dumps.
Use --show to show all packets.
Use --show=<types> to show specific types.
Use --hide=<types> to hide specific types.
Use --max-length=<chars> to limit line lengths.
"""

#TODO: Refactor with packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpidToStr
import pox.lib.pxpcap.parser as pxparse
import pox.lib.pxpcap.writer as pxwriter

log = core.getLogger()

_verbose = None
_max_length = None
_types = None
_show_by_default = None


def cb (data, parser):
  packet = pkt.ethernet(data)

  #print "%04x %4s %s" % (d.effective_ethertype,len(d),d.dump())

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
  #core.getLogger("dump").info(msg)
  print(msg)


def launch (infile, verbose = False, max_length = 110,
            hide = False, show = False):
  global _verbose, _max_length, _types, _show_by_default
  _verbose = verbose
  if max_length is True or max_length == '0':
    _max_length = None
  else:
    _max_length = int(max_length)
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

  data = open(infile, "r").read()
  p = pxparse.PCapParser(callback=cb)
  p.feed(data)

  core.quit()
