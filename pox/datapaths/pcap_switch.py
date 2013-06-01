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
Software switch with PCap ports

Example:
./pox.py --no-openflow datapaths:softwareswitch --addr=localhost
"""

from pox.core import core
from pox.datapaths import do_launch
from pox.datapaths.switch import SoftwareSwitchBase, OFConnection
import pox.lib.pxpcap as pxpcap
from Queue import Queue
from threading import Thread
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet

log = core.getLogger()


if not pxpcap.enabled:
  raise RuntimeError("You need PXPCap")

def launch (addr, port = 6633, max_retry_delay = 16, dpid = None, ports = '',
    __INSTANCE__ = None):
  """
  Launches a switch
  """

  _ports = ports
  def up (event):
    devs = pxpcap.PCap.get_devices()
    ports = _ports.split(",")
    phys = []
    portnum = 1
    if len(ports) == 1 and ports[0] == '': ports = []
    for p in list(ports):
      if p not in devs:
        log.error("Device %s not available -- ignoring", p)
        continue
      dev = devs[p]
      if dev.get('addrs',{}).get('ethernet',{}).get('addr') is None:
        log.error("Device %s has no ethernet address -- ignoring", p)
        continue
      if dev.get('addrs',{}).get('AF_INET') != None:
        log.error("Device %s has an IP address -- ignoring", p)
        continue
      phy = of.ofp_phy_port()
      phy.port_no = portnum
      portnum += 1
      phy.hw_addr = dev['addrs']['ethernet']['addr']
      phy.name = p
      # Fill in features sort of arbitrarily
      phy.curr = of.OFPPF_10MB_HD
      phy.advertised = of.OFPPF_10MB_HD
      phy.supported = of.OFPPF_10MB_HD
      phy.peer = of.OFPPF_10MB_HD
      phys.append(phy)

    do_launch(PCapSwitch, addr, port, max_retry_delay, dpid, ports=phys)

  core.addListenerByName("UpEvent", up)


class PCapSwitch (SoftwareSwitchBase):
  def __init__ (self, *args, **kw):
    self.q = Queue()
    self.t = Thread(target=self._consumer_threadproc)
    self.t.daemon = True

    super(PCapSwitch,self).__init__(*args,**kw)
    self.px = {}
    for p in self.ports.values():
      px = pxpcap.PCap(p.name, callback = self._pcap_rx)
      px.port_no = p.port_no
      self.px[p.port_no] = px

    import logging
    self.log.setLevel(logging.INFO)

    self.t.start()

  def _consumer_threadproc (self):
    timeout = 3
    while core.running:
      try:
        data = self.q.get(timeout=timeout)
      except:
        continue
      batch = []
      while True:
        self.q.task_done()
        port_no,data = data
        data = ethernet(data)
        batch.append((data,port_no))
        try:
          data = self.q.get(block=False)
        except:
          break
      core.callLater(self.rx_batch, batch)

  def rx_batch (self, batch):
    for data,port_no in batch:
      self.rx_packet(data, port_no)

  def _pcap_rx (self, px, data, sec, usec, length):
    self.q.put((px.port_no, data))

  def _output_packet_physical (self, packet, port_no):
    """
    send a packet out a single physical port

    This is called by the more general _output_packet().
    """
    self.px[port_no].inject(packet)
