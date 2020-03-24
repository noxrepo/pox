# Copyright 2017 James McCauley
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
A simple hub datapath.

Launch it with a number of interface names, and it will pass packets
between them.  Requires pxpcap to be built -- see "Building pxpcap"
in the POX manual.

Example:
  ./pox.py datapaths.hub --ports=eth0,eth1,eth2
"""

from pox.core import core
from queue import Queue
import pox.lib.packet as pkt
from pox.lib.interfaceio import PCapInterface


class Hub (object):
  """
  A simple hub
  """
  def __init__ (self, ports=[]):
    self._ports = set()
    self.rx_bytes = 0
    for p in ports:
      self.add_port(p)

  def add_port (self, port):
    p = PCapInterface(port)
    p.addListeners(self)
    self._ports.add(p)

  def _handle_RXData (self, event):
    self.rx_bytes += len(event.data)
    for port in self._ports:
      if port is event.interface: continue
      port.send(event.data)


def launch (ports):
  ports = ports.replace(","," ").split()
  l = Hub()
  core.register("hub", l)
  for p in ports:
    l.add_port(p)
