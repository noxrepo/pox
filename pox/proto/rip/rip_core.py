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
Library for RIP v2 routing

This is a library that implements the core of RIP v2.  It can be used to
actually implement a RIP router.

We're not quite RFC 2453 compliant; patches to address this are welcome!
"""

from pox.core import core
from pox.lib.addresses import IPAddr, parse_cidr
import pox.lib.packet as pkt
RIP = pkt.RIP
from pox.lib.recoco import Timer
import socket
import time
import weakref


log = core.getLogger()

INFINITY = 16



def new_timer (t, f):
  return Timer(t, f)

def cancel_timer (t):
  if t: t.cancel()
  return None



class Entry (object):
  TIMEOUT = 25 #180
  GARBAGE_TIMEOUT = 70 #120

  #FIXME: This class is pretty bad and could use a significant rewrite (which
  #       also probably means fixing everywhere it's used).
  def __init__ (self, owner, data=None, origin=None, dev=None, static=False,
                local=False):
    self.changed = True
    self.t = None       # Timer
    self.ts = None      # Timestamp
    self.owner = owner  # Owning RIPRouter

    self.next_hop = origin
    self.origin = origin
    # Since we don't pay attention to a route's advertised next_hop, the
    # above are always the same

    self.local = local  # Don't set this in our routing table
    self.static = static or local

    if data is not None:
      self.dev = None
      self.ip = data.ip
      self.size = data.network_bits
      self.metric = min(data.metric + 1, 16)
      #assert self.size is None, self.size
      assert local is False
      assert dev is None
    elif dev: # Direct
      self.dev = dev
      self.ip = origin
      self.size = 32
      self.metric = 1
    elif local:
      self.dev = None
    elif static:
      self.dev = None
      self.ip = None
      self.size = None
      self.metric = None
    else:
      raise RuntimeError()

    self.refresh()

  def __del__ (self):
    self.t = cancel_timer(self.t)

  def __eq__ (self, other):
    for an in "local static origin ip size dev metric next_hop".split():
      if getattr(self, an) != getattr(other, an, None):
        return False
    return True

  @property
  def key (self):
    return "%s/%s" % (self.ip, self.size)

  def _handle_garbage (self):
    if self.owner.table.get(self.key) is self:
      self.owner.log.debug("%s was garbage", self.key)
      del self.owner.table[self.key]

  def _handle_timeout (self):
    assert not self.static
    assert not self.local
    self.metric = INFINITY
    #if self.owner.table.get(self.key) is not self:
    #  self.owner.log.warn("Not me!")
    self.owner.log.warn("%s timed out", self.key)
    self.changed = True
    s = weakref.ref(self)
    self.t = new_timer(self.GARBAGE_TIMEOUT, lambda: s()._handle_garbage())
    self.owner.trigger_update()

  @property
  def is_stale (self):
    if self.static: return False
    if self.ts is None: return False
    return (time.time() - self.ts) > self.TIMEOUT / 2

  def refresh (self):
    if self.static: return
    if self.metric >= INFINITY:
      # Only set timer if there isn't one yet.
      if self.t is None:
        self.changed = True
        s = weakref.ref(self)
        self.t = new_timer(self.GARBAGE_TIMEOUT, lambda: s()._handle_garbage())
    else:
      self.t = cancel_timer(self.t)
      s = weakref.ref(self)
      self.t = new_timer(self.TIMEOUT, lambda: s()._handle_timeout())
      self.ts = time.time()

  def fmt (self):
    s = ''
    if self.static: s += 'S'
    if self.local: s += 'L'
    if self.dev: s += 'D'
    if s: s = ' ' + s
    fmt = "[%14s/%-2s via:%-14s hops:%-2s%4s]"
    return fmt % (self.ip, self.size, self.next_hop, self.metric, s)

  def __str__ (self):
    s = ''
    if self.static: s += 'S'
    if self.local: s += 'L'
    if self.dev: s += 'D'
    if s: s = ' ' + s
    fmt = "[%s/%s via:%s hops:%s%s]"
    return fmt % (self.ip, self.size, self.next_hop, self.metric, s)



class RIPRouter (object):
  ENTRY_TYPE = Entry

  SEND_TIMER = 8#30
  TRIGGERED_TIMER = 2

  DEFAULT_MTU = 1400

  def __init__ (self):
    if not hasattr(self, "log"):
      self.log = log
    super(RIPRouter,self).__init__()
    self.table = {}
    self.triggered_pending = False

  def _new_entry (self, *args, **kw):
    return self.ENTRY_TYPE(self, *args, **kw)

  def sync_table (self):
    """
    Puts our table into the datapath

    OVERRIDE
    """
    raise NotImplementedError()

  def send_updates (self, force):
    """
    Send responses to neighbors

    OVERRIDE

    An implementation should generally look something like this:
    direct_neighbors = _get_port_ip_map()
    for each port
      for each response in get_responses(direct_neighbors, force=force)
        send response to neighbor
    _mark_all_clean()
    """
    raise NotImplementedError()

  def get_responses (self, dests, force, static_only=False, mtu=DEFAULT_MTU):
    # 3.10.2
    outgoing = []
    for e in self.table.values():
      if not (e.changed or force): continue
      if static_only and not e.static: continue
      re = RIP.RIPEntry()
      re.address_family = socket.AF_INET
      re.ip = e.ip
      re.network_bits = e.size
      # We never set next_hop; always use us
      if dests is not None and e.origin in dests:
        if len(dests) == 1:
          re.metric = INFINITY # Poisoned reverse
        else:
          continue # Split horizon
      else:
        re.metric = e.metric
      outgoing.append(re)

    return self.package_responses(outgoing, mtu=mtu)

  def package_responses (self, outgoing, mtu):
    """
    Split a bunch of RIP entries into RIP packets.
    """
    packets = []
    entries = []

    entry_len = 2+2+4+4+4+4
    header_len = RIP.rip.MIN_LEN + pkt.ipv4.MIN_LEN + pkt.udp.MIN_LEN
    # Maybe there will be IP options or something.  Make sure there's some
    # extra space....
    header_len += 12

    def add (e=None, force=False):
      cur = len(entries) * entry_len + header_len
      if e is not None: cur += entry_len
      if (force and len(entries) > 0) or (cur >= mtu):
        ripp = RIP.rip()
        ripp.version = 2
        ripp.command = RIP.RIP_RESPONSE
        ripp.entries.extend(entries)
        packets.append(ripp)
        del entries[:]
      if e is not None: entries.append(e)

    for e in outgoing:
      add(e)

    add(force=True)

    return packets

  def _on_triggered_update (self):
    self.sync_table() # Hacky, but something may have changed.
    self.triggered_pending = False
    self.log.debug("Triggered update")
    self.send_updates(force=False)

  def trigger_update (self):
    if self.triggered_pending: return
    self.triggered_pending = True
    t = Timer(self.TRIGGERED_TIMER, self._on_triggered_update)

  def process_request (self, iface, addr, ripp):
    if len(ripp.entries) == 1 and ripp.entries[0].address_family == 0:
      # Request for full table
      self.log.info("%s requested full table", addr)

  def process_response (self, iface, addr, ripp):
    # 3.9.2
    for e in ripp.entries:
      if e.address_family != socket.AF_INET: continue
      if e.route_tag != 0:
        self.log.warn("Dropping route with nonzero tag (unsupported)")
        continue # Currently unsupported
      if e.ip == addr and e.network_bits == 32 and iface:
        # We're about to add this as a direct neighbor route
        continue
      n = self._new_entry(origin=addr, data=e) # new
      self.process_entry(n)

    # Automatically add static route to neighbors
    if iface is not None:
      e = self._new_entry(origin=addr, dev=iface)
      self.process_entry(e)

  def process_entry (self, n):
    if n.key not in self.table:
      # Not in there at all!
      if n.metric < INFINITY:
        self.table[n.key] = n
        n.changed = True
        self.trigger_update()
      else:
        # Do nothing
        pass
    else:
      o = self.table[n.key] # old
      if o == n:
        # No change at all
        o.refresh()
      elif n.metric < o.metric:
        # Better than current
        self.table[n.key] = n
        self.trigger_update()
      elif n.next_hop == o.next_hop:
        # Always replace from same neighbor
        if n.metric >= INFINITY and o.metric < INFINITY:
          # We just lost the route
          # This should start the deletion process
          self.table[n.key] = n
          self.trigger_update()
        elif n.metric >= INFINITY:
          # We were already at infinity
          pass
        else:
          # Something has changed...
          self.table[n.key] = n
          self.trigger_update()
      elif n.metric < INFINITY and n.metric == o.metric:
        # Same metric from different source
        if o.is_stale:
          self.table[n.key] = n
          self.trigger_update()

  def _mark_all_clean (self):
    """
    Mark all entries as having been sent
    """
    # Mark nothing changed
    for e in self.table.values():
      e.changed = False

  def _get_port_ip_map (self):
    """
    Gets a map from device -> {ips}

    This should return a map where a given port/device maps to a set of IPs
    that we think are directly reachable through this port.

    The default implementaton does this by looking through the routing table
    for "dev" entries.
    """
    direct = {} # iface -> set(ip)
    for e in self.table.values():
      if e.dev and not e.local:
        if e.size != 32: continue
        if e.dev not in direct:
          direct[e.dev] = set()
        direct[e.dev].add(e.ip)

    return direct
