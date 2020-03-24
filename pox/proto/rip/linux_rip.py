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
# * Use interfaceio for dealing with interfaces?


from pox.core import core
from pox.lib.addresses import IPAddr, parse_cidr
import pox.lib.packet
RIP = pox.lib.packet.RIP
from pox.lib.recoco import Timer, Task, RecvFrom, Recv, Select
import socket
import subprocess
from .rip_core import *


DEFAULT_TABLENO = 1

SO_BINDTODEVICE = 25


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

def runfail (*args):
  assert subprocess.call(args) == 0

def runout (*args):
  return subprocess.check_output(args)



def _cmd (e):
  """
  Convert an Entry to an "ip" command
  """
  if e.local: return "LOCAL ROUTE"
  ips = str(e.ip)
  if e.size != 32: ips += "/" + str(e.size)

  if e.dev:
    return "%s dev %s metric %s" % (
        ips, e.dev, e.metric)
  else:
    return "%s via %s metric %s" % (
        ips, e.next_hop, e.metric)



class LinuxRIPRouter (RIPRouter, Task):
  def __init__ (self, tableno = DEFAULT_TABLENO):
    super(LinuxRIPRouter,self).__init__()
    self.tableno = tableno

    self.init_table()
    self.init_socks()

    self.add_iface_routes()
    self.add_local_routes()

    core.listen_to_dependencies(self)

  def _handle_core_DownEvent (self, e):
    self.log.debug("Removing table")
    runfail(*("ip route flush table " + str(self.tableno)).split())
    runfail(*("ip rule del lookup " + str(self.tableno)).split())

  def _handle_core_UpEvent (self, e):
    self.send_timer = Timer(self.SEND_TIMER, self._on_send, recurring=True)
    self.start()

  def _on_send (self):
    self.log.debug("Sending timed update")
    self.send_updates(force=True)

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

  def add_iface_routes (self):
    for iface,ip in get_interfaces():
      n = self._new_entry(local=True, origin=ip, dev=iface)
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
      n = self._new_entry(local=True, origin=src)
      n.ip = dst[0]
      n.size = dst[1]
      n.metric = 1
      if "metric" in e: n.metric = int(e[e.index("metric")+1])
      self.table[n.key] = n

  def init_table (self):
    """
    Add and/or clear our table
    """
    t = self.tableno
    o = runout(*"ip rule show".split()).split("\n")
    o = [x for x in o if x.endswith(" lookup " + str(t))]
    if not o:
      runfail(*("ip rule add table " + str(t)).split())
    runfail(*("ip route flush table " + str(t)).split())

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
      if e not in modify:
        # Yes, the modify code below isn't used anymore.
        self.log.info("%s route for %s",
                      "Modifying" if e in modify else "Removing", e)
      runfail(*cmd.split())
    for e in add:
      cmd = "ip route add " + _cmd(e) + " table " + str(self.tableno)
      self.log.info("%s route for %s",
                    "Modifying" if e.key in modify else "Adding", e.key)
      runfail(*cmd.split())

  def send_updates (self, force):
    direct = self._get_port_ip_map()

    for sock,iface in self.sock_to_iface.items():
      dests = direct.get(iface)
      responses = self.get_responses(dests, force=force)
      self.log.debug("Sending %s RIP packets via %s", len(responses), iface)
      for r in responses:
        sock.sendto(r.pack(), (str(RIP.RIP2_ADDRESS), RIP.RIP_PORT))

    self._mark_all_clean()



def launch ():
  core.registerNew(LinuxRIPRouter)
