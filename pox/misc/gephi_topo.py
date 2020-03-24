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
Detects topology and streams it to Gephi

Gephi is a pretty awesome graph visualization/manipulation package.  It has
a plugin for streaming graphs back and forth between it and something else.
We use that (by opening a listening socket -- port 8282 by default) and
sending detected switches, links, and (optionally) hosts.

Based on POXDesk's tinytopo module.
Requires discovery.  host_tracker is optional.

pox.py openflow.discovery misc.gephi_topo host_tracker forwarding.l2_learning
"""

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.ioworker.workers import *
from pox.lib.ioworker import *

import json

log = core.getLogger()

clients = set()


class GephiHTTPWorker (RecocoIOWorker):
  # HTTP worker input states.  It'd be nice to reuse the web component, but
  # it seemed a bit awkward with Gephi's (sort of unusual) streaming.
  class HEADER: pass
  class BODY: pass
  class DEAD: pass

  def __init__ (self, *args, **kw):
    super(GephiHTTPWorker, self).__init__(*args, **kw)
    self._connecting = True
    self.data = b''
    self._state = self.HEADER

  def _handle_close (self):
    log.info("Client disconnect")
    super(GephiHTTPWorker, self)._handle_close()
    clients.discard(self)

  def _handle_connect (self):
    log.info("Client connect")
    super(GephiHTTPWorker, self)._handle_connect()
    clients.add(self)

  def _handle_rx (self):
    self.data += self.read().replace("\r", "")
    while True:
      datalen = len(self.data)

      if self._state is self.HEADER:
        if '\n\n' in self.data:
          header,self.data = self.data.split('\n\n', 1)
          self._process_header(header)
      elif self._state is self.BODY:
        pass

      if datalen == len(self.data): break

  def _process_header (self, request):
    request = request.strip().split("\n")
    if not request: return
    req = request[0]
    #kv = {}
    #for r in request[1:]:
    #  k,v = r.split(':', 1)
    #  kv[k] = v

    if 'POST' in req:
      self._state = self.BODY
      self.shutdown()
      return

    # Assume it's a GET /
    self.send_full()

  def send_full (self):
    out = core.GephiTopo.get_full()
    self.send_json(out)

  def send_json (self, m):
    # Build the body...
    b = '\r\n'.join(json.dumps(part) for part in m)
    b += '\r\n'

    # Build the header...
    h = []
    h.append('HTTP/1.1 200 OK')
    h.append('Content-Type: test/plain') # This is what Gephi claims
    #h.append('Content-Length: ' + str(len(d)))
    h.append('Server: POX/%s.%s.%s' % core.version)
    h.append('Connection: close')
    h = '\r\n'.join(h)

    self.send(h + '\r\n\r\n' + b)

  def send_msg (self, m):
    self.send_json([m])


def an (n, **kw):
  kw['label'] = str(n)
  return {'an':{str(n):kw}}

def ae (a, b):
  a = str(a)
  b = str(b)
  if a > b:
    a,b=b,a
  return {'ae':{a+"_"+b:{'source':a,'target':b,'directed':False}}}

def de (a, b):
  a = str(a)
  b = str(b)
  if a > b:
    a,b=b,a
  return {'de':{a+"_"+b:{}}}

def dn (n):
  return {'dn':{str(n):{}}}

def clear ():
  return {'dn':{'filter':'ALL'}}


class GephiTopo (object):
  def __init__ (self):
    core.listen_to_dependencies(self)
    self.switches = set()
    self.links = set()
    self.hosts = {} # mac -> dpid

  def _handle_core_ComponentRegistered (self, event):
    if event.name == "host_tracker":
      event.component.addListenerByName("HostEvent",
          self.__handle_host_tracker_HostEvent)

  def send (self, data):
    for c in clients:
      c.send_msg(data)

  def get_full (self):
    out = []

    out.append(clear())

    for s in self.switches:
      out.append(an(s, kind='switch'))
    for e in self.links:
      out.append(ae(e[0],e[1]))
    for h,s in self.hosts.items():
      out.append(an(h, kind='host'))
      if s in self.switches:
        out.append(ae(h,s))

    return out

  def __handle_host_tracker_HostEvent (self, event):
    # Name is intentionally mangled to keep listen_to_dependencies away
    h = str(event.entry.macaddr)
    s = dpid_to_str(event.entry.dpid)

    if event.leave:
      if h in self.hosts:
        if s in self.switches:
          self.send(de(h,s))
        self.send(dn(h))
        del self.hosts[h]
    else:
      if h not in self.hosts:
        self.hosts[h] = s
        self.send(an(h, kind='host'))
        if s in self.switches:
          self.send(ae(h, s))
        else:
          log.warn("Missing switch")

  def _handle_openflow_ConnectionUp (self, event):
    s = dpid_to_str(event.dpid)
    if s not in self.switches:
      self.send(an(s))
      self.switches.add(s)

  def _handle_openflow_ConnectionDown (self, event):
    s = dpid_to_str(event.dpid)
    if s in self.switches:
      self.send(dn(s))
      self.switches.remove(s)

  def _handle_openflow_discovery_LinkEvent (self, event):
    s1 = event.link.dpid1
    s2 = event.link.dpid2
    s1 = dpid_to_str(s1)
    s2 = dpid_to_str(s2)
    if s1 > s2: s1,s2 = s2,s1

    assert s1 in self.switches
    assert s2 in self.switches

    if event.added and (s1,s2) not in self.links:
      self.links.add((s1,s2))
      self.send(ae(s1,s2))

      # Do we have abandoned hosts?
      for h,s in self.hosts.items():
        if s == s1: self.send(ae(h,s1))
        elif s == s2: self.send(ae(h,s2))

    elif event.removed and (s1,s2) in self.links:
      self.links.remove((s1,s2))
      self.send(de(s1,s2))


loop = None

def launch (port = 8282, __INSTANCE__ = None):
  if not core.hasComponent("GephiTopo"):
    core.registerNew(GephiTopo)

  global loop
  if not loop:
    loop = RecocoIOLoop()
    #loop.more_debugging = True
    loop.start()

  worker_type = GephiHTTPWorker
  w = RecocoServerWorker(child_worker_type=worker_type, port = int(port))
  loop.register_worker(w)
