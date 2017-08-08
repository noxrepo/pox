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
A RIP v2 routing daemon for Linux

This component speaks RIP v2 with neighboring routers, and configures the
local Linux routing tables accordingly.

We're not quite RFC 2453 compliant; patches to address this are welcome!
"""

#TODO:
# * Factor the RIP stuff back out into a separate class, so it can be
#   used for a new OpenFlow RIP implementation.
# * Use interfaceio for dealing with interfaces?


from pox.core import core
from pox.lib.addresses import IPAddr, IP_ANY, parse_cidr
import pox.lib.packet.RIP as RIP
from pox.lib.recoco import Timer, Task, RecvFrom, Recv, Select
import socket
import subprocess
import time
import weakref


log = core.getLogger()

DEFAULT_TABLENO = 1

INFINITY = 16

TIMEOUT = 25 #180
GARBAGE_TIMEOUT = 70 #120

SEND_TIMER = 8#30
TRIGGERED_TIMER = 2


SO_BINDTODEVICE = 25


def runfail (*args):
  assert subprocess.call(args) == 0

def runout (*args):
  return subprocess.check_output(args)



def new_timer (t, f):
  return Timer(t, f)

def cancel_timer (t):
  if t: t.cancel()
  return None



class Entry (object):
  def __init__ (self, owner, data=None, origin=None, dev=None, static=False,
                local=False):
    self.changed = True
    self.t = None
    self.ts = None
    self.owner = owner

    self.next_hop = origin
    self.origin = origin
    # Since we don't pay attention to a route's advertised next_hop, the
    # above are always the same

    self.local = local # Don't set this in our routing table
    self.static = static or local

    if data is not None:
      self.dev = None
      self.ip = data.ip
      self.size = data.network_bits
      self.metric = min(data.metric + 1, 16)
    elif dev: # Direct
      self.dev = dev
      self.ip = origin
      self.size = 32
      self.metric = 1
    elif local:
      self.dev = None
    else:
      raise RuntimeError()

    self.refresh()

  def __del__ (self):
    self.t = cancel_timer(self.t)

  @property
  def cmd (self):
    if self.local: return "LOCAL ROUTE"
    ips = str(self.ip)
    if self.size != 32: ips += "/" + str(self.size)

    if self.dev:
      return "%s dev %s metric %s" % (
          ips, self.dev, self.metric)
    else:
      return "%s via %s metric %s" % (
          ips, self.next_hop, self.metric)

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
    self.t = new_timer(GARBAGE_TIMEOUT, lambda: s()._handle_garbage())
    self.owner.trigger_update()

  @property
  def is_stale (self):
    if self.static: return False
    if self.ts is None: return False
    return (time.time() - self.ts) > TIMEOUT / 2

  def refresh (self):
    if self.static: return
    if self.metric >= INFINITY:
      # Only set timer if there isn't one yet.
      if self.t is None:
        self.changed = True
        s = weakref.ref(self)
        self.t = new_timer(GARBAGE_TIMEOUT, lambda: s()._handle_garbage())
    else:
      self.t = cancel_timer(self.t)
      s = weakref.ref(self)
      self.t = new_timer(TIMEOUT, lambda: s()._handle_timeout())
      self.ts = time.time()



class LinuxRIPRouter (Task):
  def __init__ (self, tableno = DEFAULT_TABLENO):
    self.log = log
    super(LinuxRIPRouter,self).__init__()
    self.table = {}
    self.triggered_pending = False
    self.tableno = tableno

    self.init_table()
    self.init_socks()

    self.add_iface_routes()
    self.add_local_routes()

    core.listen_to_dependencies(self)

  def sync_table (self):
    # This is pretty awful!
    rt = runout(*("ip route list table " + str(self.tableno)).split())
    rt = rt.strip().split("\n")

    def get_field (e, f, t=None, d=None):
      if f not in e: return d
      v = e[e.index(f)+1]
      if t is not None: v = t(v)
      return v
    def get_int (e, f):
      return get_field(e, f, t=int)

    add = []
    cur = {}
    remove = set()
    for re in [x.split() for x in rt if x]:
      dst,size = parse_cidr(re[0])
      k = "%s/%s" % (dst,size)
      assert k not in cur
      cur[k] = re
      if k not in self.table:
        remove.add(k)

    for e in self.table.values():
      if e.local: continue
      if e.key not in cur:
        add.append(e)
        continue
      c = cur[e.key]
      if get_int(c, "metric") != e.metric:
        remove.add(e.key)
        add.append(e)
        continue
      if e.dev:
        if e.dev != get_field(c, "dev"):
          remove.add(e.key)
          add.append(e)
          continue
      elif e.next_hop != get_field(c, "via"):
        remove.add(e.key)
        add.append(e)
        continue

    #if add or remove:
    #  self.log.info("Removing %s routes and adding %s", len(remove), len(add))
    modify = set(remove).intersection([e.key for e in add])
    for e in remove:
      cmd = "ip route del " + e + " table " + str(self.tableno)
      self.log.debug("%s route for %s",
                     "Modifying" if e in modify else "Removing", e)
      runfail(*cmd.split())
    for e in add:
      cmd = "ip route add " + e.cmd + " table " + str(self.tableno)
      self.log.debug("%s route for %s",
                     "Modifying" if e.key in modify else "Adding", e.key)
      runfail(*cmd.split())

  def _handle_core_UpEvent (self, e):
    self.send_timer = Timer(SEND_TIMER, self._on_send, recurring=True)
    self.start()

  def _handle_core_DownEvent (self, e):
    self.log.debug("Removing table")
    runfail(*("ip route flush table " + str(self.tableno)).split())
    runfail(*("ip rule del lookup " + str(self.tableno)).split())

  def _on_send (self):
    self.log.debug("Sending timed update")
    self.send_updates(force=True)

  def send_updates (self, force):
    # Try to see who we think we're talking to
    direct = {} # iface -> set(ip)
    for e in self.table.values():
      if e.dev and not e.local:
        if e.dev not in direct:
          direct[e.dev] = set()
        direct[e.dev].add(e.ip)

    for sock,iface in self.sock_to_iface.items():
      dests = direct.get(iface)
      responses = self.get_responses(dests, force=force)
      #self.log.debug("Sending %s RIP packets via %s", len(responses), iface)
      for r in responses:
        sock.sendto(r.pack(), (str(RIP.RIP2_ADDRESS), RIP.RIP_PORT))

    # Mark nothing changed
    for e in self.table.values():
      e.changed = False

  def add_iface_routes (self):
    for iface,ip in get_interfaces():
      n = Entry(self, local=True, origin=ip, dev=iface)
      self.table[n.key] = n

  def add_local_routes (self, table=None):
    cmd = "ip route list".split()
    if table is not None: cmd += ["table", str(table)]
    d = runout(*cmd).strip().split("\n")
    for e in d:
      e = e.split()
      if "src" not in e: continue
      dst = parse_cidr(e[0], allow_host=False)
      src = IPAddr(e[e.index("src")+1])
      n = Entry(self, local=True, origin=src)
      n.ip = dst[0]
      n.size = dst[1]
      n.metric = 1
      self.table[n.key] = n

  def get_responses (self, dests, force):
    # 3.10.2
    outgoing = []
    for e in self.table.values():
      if not (e.changed or force): continue
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

    packets = []
    while outgoing:
      chunk = outgoing[:25]
      del outgoing[:25]

      ripp = RIP.rip()
      ripp.version = 2
      ripp.command = RIP.RIP_RESPONSE
      ripp.entries = chunk
      packets.append(ripp)

    return packets

  def _on_triggered_update (self):
    self.triggered_pending = False
    self.log.debug("Triggered update")
    self.send_updates(force=False)

  def trigger_update (self):
    self.sync_table() # Hacky, but something may have changed.
    if self.triggered_pending: return
    self.triggered_pending = True
    t = Timer(TRIGGERED_TIMER, self._on_triggered_update)

  def init_socks (self):
    def create_sock (iface, addr):
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface + "\0")
      sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
      sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, addr.raw)
      sock.bind(('', RIP.RIP_PORT))
      sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                      RIP.RIP2_ADDRESS.raw + addr.raw)
      return sock

    # We want to be able to distinguish which interface a packet came in on
    # (so that we can add routes for neighbors automatically).  We could do
    # this with recvmsg() except that Python 2 doesn't support it and doing
    # it via ctypes seemed hard.  Instead, we create a separate socket for
    # each interface.
    self.sock_to_iface = {}
    for iface,ip in sorted(get_interfaces()):
      self.sock_to_iface[create_sock(iface,ip)] = iface

    self.log.info("Listening for RIP on %s interfaces", len(self.sock_to_iface))

  def run (self):
    while True:
      rr,ww,oo = yield Select(self.sock_to_iface.keys(), [], [])
      for r in rr:
        #data,addr = yield RecvFrom(sock, 65535)
        data,addr = r.recvfrom(65535)
        if addr[1] != RIP.RIP_PORT: continue
        #TODO: Check that source is on directly connected network
        addr = IPAddr(addr[0])
        data = RIP.rip(raw=data)
        if data.version != 2: continue
        iface = self.sock_to_iface[r]
        #print "<<<",iface, addr, data
        if data.command == RIP.RIP_REQUEST:
          self.process_request(iface, addr, data)
        elif data.command == RIP.RIP_RESPONSE:
          self.process_response(iface, addr, data)
          self.sync_table()

  def process_request (self, iface, addr, ripp):
    if len(ripp.entries) == 1 and ripp.entries[0].address_family == 0:
      # Request for full table
      self.log.info("%s requested full table", addr)

  def process_response (self, iface, addr, ripp):
    # 3.9.2
    changed = False
    for e in ripp.entries:
      if e.address_family != socket.AF_INET: continue
      if e.route_tag != 0:
        self.log.warn("Dropping route with nonzero tag (unsupported)")
        continue # Currently unsupported
      n = Entry(self, origin=addr, data=e) # new
      self.process_entry(n)

    # Automatically add static route to neighbors
    e = Entry(self, origin=addr, dev=iface)
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
      if o.cmd == n.cmd:
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

  def init_table (self):
    """
    Check if a given table exists
    """
    t = self.tableno
    o = runout(*"ip rule show".split()).split("\n")
    o = [x for x in o if x.endswith(" lookup " + str(t))]
    if not o:
      runfail(*("ip rule add table " + str(t)).split())
    runfail(*("ip route flush table " + str(t)).split())



def get_interfaces ():
  """
  Returns a list of (iface,IPAddr)
  """
  # Could use POX's pcap stuff here, but let's just use all commandline stuff
  o = []
  ifaces = runout(*"ip addr show".split()).split("\n")
  cur = None
  for line in ifaces:
    if not line: continue
    if line.startswith(" "):
      if cur is None: continue
      line = line.strip()
      if not line.startswith("inet "): continue
      ip = IPAddr(line.split()[1].split("/")[0])
      o.append((cur, ip))
      cur = None
    else:
      iface = line.split(":")[1].strip().split("@")[0]
      if iface == "lo": continue
      cur = iface
  return o



def launch ():
  core.registerNew(LinuxRIPRouter)
