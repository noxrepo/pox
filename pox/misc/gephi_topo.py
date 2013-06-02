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

class ServerWorker (TCPServerWorker, RecocoIOWorker):
  pass

clients = set()

class GephiWorker (RecocoIOWorker):
  def __init__ (self, *args, **kw):
    super(GephiWorker, self).__init__(*args, **kw)
    self._connecting = True
    self.data = b''

  def _handle_close (self):
    log.info("Client disconnect")
    super(GephiWorker, self)._handle_close()
    clients.discard(self)

  def _handle_connect (self):
    log.info("Client connect")
    super(GephiWorker, self)._handle_connect()
    core.GephiTopo.send_full(self)
    clients.add(self)

  def _handle_rx (self):
    self.data += self.read()
    while '\n' in self.data:
      # We don't currently do anything with this
      msg,self.data = self.data.split('\n',1)

      # This SHOULD be an HTTP request.

      #print msg
      pass


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
      c.send(json.dumps(data) + '\r\n')

  def send_full (self, client):
    out = []

    out.append(clear())

    for s in self.switches:
      out.append(an(s, kind='switch'))
    for e in self.links:
      out.append(ae(e[0],e[1]))
    for h,s in self.hosts.iteritems():
      out.append(an(h, kind='host'))
      if s in self.switches:
        out.append(ae(h,s))

    out = '\r\n'.join(json.dumps(o) for o in out)

    client.send(out + '\r\n')

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
      for h,s in self.hosts.iteritems():
        if s == s1: self.send(ae(h,s1))
        elif s == s2: self.send(ae(h,s2))

    elif event.removed and (s1,s2) in self.links:
      self.links.remove((s1,s2))
      self.send(de(s1,s2))


def launch (port = 8282):
  core.registerNew(GephiTopo)

  # In theory, we're supposed to be running a web service, but instead
  # we just spew Gephi graph streaming junk at everyone who connects. :)
  global loop
  loop = RecocoIOLoop()
  #loop.more_debugging = True
  loop.start()

  w = ServerWorker(child_worker_type=GephiWorker, port = int(port))
  loop.register_worker(w)
