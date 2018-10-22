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
Reusable ARP table
"""

import time
from pox.lib.recoco import Timer
from pox.core import core
import pox.lib.packet as pkt

log = core.getLogger()



class ARPEntry (object):
  REFRESH_TIME = 60 # Refresh this often
  MIN_BACKOFF = 1
  MAX_BACKOFF = 32

  def __init__ (self, ip, mac):
    self.ts = time.time()
    self.ip = ip
    self.mac = mac
    if mac is not None:
      self.confirm()
    else:
      self.next_refresh = time.time()
      self.refresh_backoff = self.MIN_BACKOFF

  @property
  def age (self):
    return time.time() - self.ts

  def confirm (self, mac=None):
    self.next_refresh = time.time() + self.REFRESH_TIME
    self.refresh_backoff = self.MIN_BACKOFF
    if mac is not None:
      self.mac = mac

  def maybe_refresh (self):
    """
    if returns True, you should send a refresh
    """
    if self.next_refresh > time.time():
      return False
    self.next_refresh = time.time() + self.refresh_backoff
    self.refresh_backoff *= 2
    if self.refresh_backoff > self.MAX_BACKOFF:
      self.refresh_backoff = self.MAX_BACKOFF
    return True


class ARPTable (object):
  MAX_ENTRIES = 1024
  MAX_PENDING = 5

  MAX_PENDING_TIME = 2

  def __init__ (self):
    self.by_ip = {} # ip -> entry
    self.pending = [] # Packets waiting to be sent (ip,(send_args))
    self.timer = Timer(self.MAX_PENDING_TIME, self._timer_proc)

  def __str__ (self):
    sending = set(x for x,y in self.pending)
    r = []
    for ip,e in sorted(self.by_ip.items()):
      m = "%-15s %16s" % (ip, e.mac)
      if ip in sending: m += " p"
      r.append(m)
    return "\n".join(r)

  def add_entry (self, ip, mac=None):
    """
    Add an entry

    The entry can't already exist.
    It will definitely exist after returning.
    """
    assert ip not in self.by_ip
    if len(self.by_ip) >= self.MAX_ENTRIES:
      # Sloppy, but simple.
      # Get ones with lowest age
      entries = sorted(self.by_ip.values(), key = lambda entry: entry.age)
      del entries[self.MAX_ENTRIES:]
      self.by_ip = {e.mac:e for e in entries}
    new_entry = ARPEntry(ip=ip, mac=mac)
    self.by_ip[ip] = new_entry
    return new_entry

  def send (self, eth_packet, router_ip=None, src_eth=None, src_ip=None,
            send_function=None):
    """
    Try to send a packet

    eth_packet is an ethernet object.
    src_eth is the source for any ARPs sent.
    src_ip is the source for any ARPs sent.
    If the above two are not specified, they are taken from eth_packet.
    send_function is a function which takes raw bytes to send.
    If send_function is unset, it is taken from a send_function attribute.
    """
    if send_function is None: send_function = self.send_function
    ipp = eth_packet.find("ipv4")

    if not ipp and eth_packet.type == eth_packet.IP_TYPE:
      if isinstance(eth_packet.payload, bytes):
        # Hm!  Try harder...
        ipp = pkt.ipv4(raw=eth_packet.payload)

    if not ipp or eth_packet.dst.is_multicast:
      send_function(eth_packet.pack())
      return
    if ipp.dstip == pkt.IPV4.IP_BROADCAST:
      #ipp.dstip = router_ip # Not sure what this was about
      eth_packet.dst = pkt.ETHERNET.ETHER_BROADCAST
      send_function(eth_packet.pack())
      return
    if ipp.dstip.is_multicast:
      eth_packet.dst = ipp.dstip.multicast_ethernet_address
      send_function(eth_packet.pack())
      return

    if src_ip is None: src_ip = ipp.srcip
    if src_eth is None: src_eth = eth_packet.src

    if router_ip is not None: dstip = router_ip
    else:                     dstip = ipp.dstip

    if dstip not in self.by_ip: self.add_entry(dstip)

    e = self.by_ip[dstip]
    if e.maybe_refresh():
      # Send ARP
      self._send_arp(dstip, src_eth, src_ip,
                     send_function)

    if e.mac is not None:
      eth_packet.dst = e.mac
      send_function(eth_packet.pack())
    else:
      if len(self.pending) < self.MAX_PENDING:
        self.pending.append((dstip, (eth_packet, router_ip, src_eth, src_ip,
                                     send_function)))

  def _timer_proc (self):
    # We just blow away all the entries every interval, so on average, they
    # live for half the interval.
    del self.pending[:]

  def __del__ (self):
    if self.timer:
      self.timer.cancel()
      self.timer = None

  def _send_arp (self, dstip, src_eth, src_ip, send_function):
    r = pkt.arp()
    r.opcode = r.REQUEST
    r.hwdst = pkt.ETHERNET.ETHER_BROADCAST
    r.protodst = dstip
    r.hwsrc = src_eth
    r.protosrc = src_ip
    e = pkt.ethernet(type=pkt.ethernet.ARP_TYPE,
                     src=r.hwsrc,
                     dst=r.hwdst)
    e.payload = r
    log.debug("Sending ARP for %s", dstip)
    send_function(e.pack())

  def rx_arp_reply (self, arp):
    assert arp.opcode == arp.REPLY
    self.rx_arp(arp)

  def rx_arp (self, arp):
    if arp.protosrc not in self.by_ip:
      self.add_entry(mac=arp.hwsrc, ip=arp.protosrc)
    else:
      self.by_ip[arp.protosrc].confirm(arp.hwsrc)

    # Send any pending packets
    for index,(ip,args) in reversed(list(enumerate(self.pending))):
      if ip == arp.protosrc:
        del self.pending[index]
        log.debug("ARP reply allows sending pending packet")
        self.send(*args)
