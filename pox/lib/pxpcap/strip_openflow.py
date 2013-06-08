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
A hacky tool to grab packet in/out data from OpenFlow traffic.

Assumes packets are 1:1 with OF messages (as if captured using the
openflow.debug component).

 --infile=<filename>   Input file
 --outfile=<filename>  Output file
 --out-only            Don't include packet_ins
 --in-only             Don't include packet_outs
 --openflow-port=<num> Specify OpenFlow TCP port
"""

#TODO: Clean this up, follow multiple control traffic streams, decode
#      TCP, etc.

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpidToStr
import pox.lib.pxpcap.parser as pxparse
import pox.lib.pxpcap.writer as pxwriter

log = core.getLogger()

from pox.lib.pxpcap.writer import PCapRawWriter

_writer = None
_of_port = 6633
_in_only = False
_out_only = False

_pis = 0
_pos = 0

def pi_cb (data, parser):
  global _pis, _pos
  packet = pkt.ethernet(data)
  if packet.find('tcp'):
    if packet.find('tcp').dstport == _of_port or \
       packet.find('tcp').srcport == _of_port:
      p = packet.find('tcp').payload
      assert p[0] == '\x01'
      t = ord(p[1])
      packet_length = ord(p[2]) << 8 | ord(p[3])
      if packet_length != len(p):
        log.error("%s != %s" % (packet_length, len(p)))
      if t == of.OFPT_PACKET_IN:
        if _out_only: return
        l,p = of.ofp_packet_in.unpack_new(p)
        _pis += 1
      elif t == of.OFPT_PACKET_OUT:
        if _in_only: return
        l,p = of.ofp_packet_out.unpack_new(p)
        _pos += 1
      else:
        return
      assert l == len(p)

      _writer.write(p.data, time=parser._time, wire_size=parser._wire_size)


def launch (infile, outfile, in_only=False, out_only = False):
  """
  For stripping PI/PO data

  """
  global _writer, _of_port, _in_only, _out_only
  _in_only = in_only
  _out_only = out_only

  data = open(infile, "r").read()
  p = pxparse.PCapParser(callback=pi_cb)
  _writer = pxwriter.PCapRawWriter(open(outfile, "w"))
  p.feed(data)

  log.info("%i packet_ins, %i packet_outs", _pis, _pos)

  core.quit()
