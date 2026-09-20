# Copyright 2026 James McCauley
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
Standalone DHCP Server

Implements a standalone DHCP server that runs on normal interfaces.
"""

from pox.core import core
from pox.lib.pxpcap import PCap
from pox.lib.addresses import IPAddr, EthAddr, IP_BROADCAST, IP_ANY
import pox.lib.packet as pkt
from pox.proto.dhcpd import DHCPDBase, DHCPPacketContextBase
from pox.proto.dhcpd import SimpleAddressPool

log = core.getLogger()


class PlainDHCPPacketContext (DHCPPacketContextBase):
  def __init__ (self, pcap_obj, raw_data, server_eth, server_ip):
    self.pcap = pcap_obj
    self.parsed = pkt.ethernet(raw_data)
    self.client_eth = self.parsed.src
    self.server_eth = server_eth
    self.ip_addr = server_ip

  def __str__ (self):
    return "<PlainDHCP Request on %s>" % (self.pcap.device,)

  def send (self, ipp):
    ethp = pkt.ethernet(src=self.server_eth, dst=self.parsed.src)
    ethp.type = pkt.ethernet.IP_TYPE

    if ipp.dstip == IP_BROADCAST:
      ethp.dst = pkt.ETHERNET.ETHER_BROADCAST

    ethp.payload = ipp
    self.pcap.inject(ethp.pack())


class PlainDHCPD (DHCPDBase):
  def __init__ (self, ports, ip_address = None,
                router_address = (), dns_address = (), pool = None,
                subnet = None):

    self.ip_addr = None # Probably gets overridden

    self.pcaps = {} # pcap -> eth,ip

    if isinstance(ports, str):
      ports = [p.strip() for p in ports.split(",") if p.strip()]

    for port in ports:
      try:
        p = PCap(device=port, callback=self._handle_pcap_rx,
                 filter="udp port 67")

        server_ip = p.addresses.get('AF_INET')
        if server_ip: server_ip = server_ip['addr']
        if ip_address is None:
          ip_address = server_ip

        # Get interface's ethernet address
        link_info = (p.addresses.get('ethernet') or
                     p.addresses.get('AF_LINK') or
                     p.addresses.get('AF_PACKET'))

        if link_info and link_info.get('addr'):
          server_eth = link_info['addr']
        else:
          server_eth = EthAddr("02:00:00:11:22:33")

        if server_ip is None:
          log.warning(f"Interface {port} ({server_eth}) has no IP address")

        self.pcaps[p] = server_eth,server_ip
        log.info("Listening for DHCP on %s (%s)",
                 port, server_eth)
      except Exception as e:
        log.error("Failed to bind PCap to interface %s: %s", port, e)

    if router_address == ():
      router_address = ip_address
    if dns_address == ():
      dns_address = ip_address

    if not ip_address:
      for p in self.pcaps:
        try:
          p.close()
        except Exception:
          pass
      raise RuntimeError("DHCP server aborted because it has no IP address")

    super(PlainDHCPD, self).__init__(ip_address, router_address,
                                     dns_address, pool, subnet)

    for _,my_ip in self.pcaps.values():
      if my_ip in self.pool:
        log.debug("Removing my own IP (%s) from address pool", my_ip)
        self.pool.remove(my_ip)

  def _handle_pcap_rx (self, pcap, data, sec, usec, length):
    server_eth,server_ip = self.pcaps[pcap]
    if server_ip is None: server_ip = self.ip_addr
    if server_ip is None: return
    ctxt = PlainDHCPPacketContext(pcap, data, server_eth, server_ip)
    self._process_message(ctxt)

  def _is_my_addr (self, ip):
    if ip in (IP_ANY,IP_BROADCAST,self.ip_addr):
      return True
    for _,my_ip in self.pcaps.values():
      if ip == my_ip:
        return True
    return False



def launch (ports = "eth0",
            network = "192.168.0.0/24",
            first = 100, last = None, count = None,
            ip = None,
            router = (),
            dns = (),
            __INSTANCE__ = None):
  """
  Launch stand-alone DHCP server on local host interfaces

  ports    Comma-separated interfaces to listen on (e.g. --ports=eth0,eth1)
  network  Subnet to allocate addresses from
  first    First host offset in subnet
  last     Last host offset in subnet
  count    Alternate count for total lease pool size
  router   Router IP to give clients (defaults to 'ip')
  dns      DNS IP to give clients (defaults to 'router')
  """
  # A bunch of this logic is pretty much the same as in dhcpd, and we could
  # (should) merge them.
  def fixint (i):
    if i is None: return None
    i = str(i)
    if i.lower() in ("none", "true", "false"): return None
    return int(i)

  def fix (i):
    if i is None: return None
    i = str(i)
    if i.lower() in ("none", "true", "false"): return None
    if i == '()': return ()
    return i

  first,last,count = map(fixint,(first,last,count))
  router,dns = map(fix,(router,dns))


  pool = SimpleAddressPool(network = network, first = first, last = last,
                           count = count)

  try:
    inst = PlainDHCPD(ports=ports, pool=pool, ip_address=ip,
                      router_address=router, dns_address=dns)

    if __INSTANCE__[0] == 0:
      # First or only instance
      core.register(inst)

    log.info("DHCP server on ports %s serving a%s", ports, str(pool)[2:-1])
  except Exception as e:
    log.error(e)
