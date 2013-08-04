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
Dumps info about switches when they first connect
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

# Formatted switch descriptions we've logged
# (We rememeber them so that we only print them once)
_switches = set()

# .. unless always is True in which case we always print them
_always = False

def _format_entry (desc):
  def fmt (v):
    if not v: return "<Empty>"
    return str(v)
  dpid = dpid_to_str(desc.connection.dpid)
  ofp = desc.ofp.body
  s = []
  ports = [(p.port_no,p.name) for p in desc.connection.ports.values()]
  ports.sort()
  ports = " ".join(p[1] for p in ports)
  #if len(ports) > len(dpid)+12:
  #  ports = "%s ports" % (len(desc.connection.ports),)

  s.append("New Switch: " + dpid)
  s.append("Hardware:  " + fmt(ofp.hw_desc))
  s.append("Software:  " + fmt(ofp.sw_desc))
  s.append("SerialNum: " + fmt(ofp.serial_num))
  s.append("Desc:      " + fmt(ofp.dp_desc))
  s.append("Ports:     " + fmt(ports))

  # Let's get fancy
  width = max(len(line) for line in s)
  s.insert(0, "=" * width)
  s.insert(2, "-" * width)
  s.append(   "=" * width)

  return "\n".join(s)

def _handle_ConnectionUp (event):
  msg = of.ofp_stats_request(body=of.ofp_desc_stats_request())
  msg.type = 0 # For betta bug, can be removed
  event.connection.send(msg)

def _handle_SwitchDescReceived (event):
  s = _format_entry(event)
  if not _always and s in _switches:
    # We've already logged it.
    return
  _switches.add(s)
  ss = s.split("\n")

  logger = core.getLogger("info." + dpid_to_str(event.connection.dpid))
  for s in ss:
    logger.info(s)


def launch (always = False):
  global _always
  _always = always

  core.openflow.addListenerByName("ConnectionUp",
      _handle_ConnectionUp)
  core.openflow.addListenerByName("SwitchDescReceived",
      _handle_SwitchDescReceived)
