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
Creates a spanning tree (or possibly more than one)

This component uses the discovery component to build a view of the network
topology, constructs a spanning tree, and then disables flooding on switch
ports that aren't on the tree by setting their NO_FLOOD bit.  The result
is that topologies with loops no longer turn your network into useless
hot packet soup.

Note that this does not have much of a relationship to Spanning Tree
Protocol.  They have similar purposes, but this is a rather different way
of going about it.

This component is intended to replace the spanning_tree component, but
it currently has no support for dynamic topologies (that is, where
something that used to be connected to one thing now connects to
another thing) and has fairly different behavior in general, so we
still have the spanning_tree module too (for now).
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
import time

log = core.getLogger()

def _now ():
  return time.time()



class Port (object):
  def __init__ (self, no, up):
    assert no < of.OFPP_MAX
    self.no = no
    self.up = up
    self.reset_wait()
    self.never_block = False

  def reset_wait (self):
    self.ts = _now()

  @property
  def waiting (self):
    # We'd like to wait for a while here, but it seems like NO_FWD
    # now affects sending packet_outs, which I don't think it used
    # to.  So waiting actually kills discovery.  So we only wait
    # a little while, hoping that it'll be enough to stop any
    # worst case behavior.
    return self.age < core.openflow_discovery.send_cycle_time / 4

  @property
  def age (self):
    return _now() - self.ts



def is_down (p):
  if (p.config & of.OFPPC_PORT_DOWN): return True
  if (p.state & of.OFPPS_LINK_DOWN): return True
  return False

def is_up (p):
  return not is_down(p)



class Switch (object):
  def __init__ (self, master, dpid):
    self.dpid = dpid
    self.log = log.getChild(dpid_to_str(dpid))
    self.ports = {}
    self._port_out_cache = None
    self._port_out = None
    self.master = master

  def get_port (self, p):
    assert p < of.OFPP_MAX
    if p not in self.ports:
      self.ports[p] = Port(p, False)
    return self.ports[p]

  def _handle_ConnectionUp (self, e):
    # Not a real event handler -- we call it ourselves
    self._port_cache = None
    self._sync_port_data()

  def _handle_ConnectionDown (self, e):
    for p in self.ports.values():
      p.up = False

  def _handle_PortStatus (self, e):
    if e.port >= of.OFPP_MAX: return
    if e.port not in self.ports:
      if e.deleted:
        self.ports[e.port] = Port(e.port, False)
      else:
        self.ports[e.port] = Port(e.port, is_up(e.ofp.desc))
    else:
      if e.deleted:
        self.ports[e.port].up = False
      else:
        self.ports[e.port].reset_wait()

  def _handle_timer (self):
    self._sync_port_data()
    self._compute()

  def _sync_port_data (self):
    # Make sure we've got the latest port info
    con = core.openflow.getConnection(self.dpid)
    old_ports = self.ports
    self.ports = {}
    if not con: return
    for p in con.ports.values():
      if p.port_no >= of.OFPP_MAX: continue
      if p.port_no in old_ports:
        self.ports[p.port_no] = old_ports[p.port_no]
        self.ports[p.port_no].up = is_up(p)
      else:
        self.ports[p.port_no] = Port(p.port_no, is_up(p))

  def _compute (self):
    con = core.openflow.getConnection(self.dpid)
    if not con: return
    self._sync_port_data()
    out = {} # portno->Allow?

    # Get port->link
    links = {l.port(self.dpid):l for l in self.master.topo.iterlinks(self.dpid)}

    for p in con.ports.values():
      if p.port_no >= of.OFPP_MAX: continue
      p = self.ports[p.port_no]
      fld = False
      rcv = False
      if p.never_block:
        fld = True
        rcv = True
      elif p.waiting:
        pass
      else:
        rcv = True
        l = links.get(p.no)
        if l:
          if l.on_tree:
            fld = True
        else:
          # Doesn't look like a switch-switch link (not a workin one anyway)
          fld = True

      out[p.no] = 0
      # I think we'd like to use OFPPC_NO_RECV, but that only
      # lets us receive STP -- what we really want are our
      # special discovery packets.  So use NO_FWD instead.
      if not fld: out[p.no] |= of.OFPPC_NO_FLOOD
      if not rcv: out[p.no] |= of.OFPPC_NO_FWD

    self._port_out = out
    #self.log.debug(out)

    self._realize()

  def _realize (self):
    if self._port_out == self._port_out_cache: return

    # We really shouldn't need to get the connection here...
    con = core.openflow.connections.get(self.dpid)
    if con is None: return

    data = []
    for port_no,cfg in self._port_out.items():
      if port_no not in self.ports: continue
      if port_no not in con.ports: continue
      p = con.ports[port_no]
      pm = of.ofp_port_mod(port_no=p.port_no,
                           hw_addr=p.hw_addr,
                           config = cfg,
                           mask = of.OFPPC_NO_FLOOD|of.OFPPC_NO_FWD)
      data.append(pm.pack())

    # We could probably handle the features stuff better
    data.append(of.ofp_features_request().pack())

    if self.send(b''.join(data)):
      self._port_out_cache = self._port_out
      self.log.info("Configured %s ports", len(data) - 1)

  def send (self, data):
    con = core.openflow.connections.get(self.dpid)
    if not con:
      self.log.info("Not connected -- didn't send %s bytes" % (len(data),))
      return False
    con.send(data)
    return True



class LinkData (object):
  def __init__ (self, link):
    self.link = link.uni
    self.uv_ts = 0.0 # Long time ago!
    self.vu_ts = 0.0 # Long time ago!
    assert self.link.end[0][0] != self.link.end[1][0] # Unsupported
    self.on_tree = False

  @property
  def up (self):
    return self.liveness == 1

  @property
  def forward_up (self):
    return self.uv_ts > 0

  @property
  def reverse_up (self):
    return self.vu_ts > 0

  @property
  def liveness (self):
    # 0 -> down, 1 -> up, 0.5 -> half up
    uv = self.uv_ts > 0 #(t-self.uv_ts) < self.TIMEOUT
    vu = self.vu_ts > 0 #(t-self.vu_ts) < self.TIMEOUT
    if uv and vu: return 1
    if uv or vu: return 0.5
    return 0

  def mark_alive (self, link):
    if link == self.link:
      self.uv_ts = _now()
    elif link.uni == self.link:
      self.vu_ts = _now()
    else:
      raise RuntimeError()

  def mark_dead (self, link = None):
    if link is None:
      self.uv_ts = 0.0
      self.vu_ts = 0.0
      return

    if link == self.link:
      self.uv_ts = 0.0
    elif link.uni == self.link:
      self.vu_ts = 0.0
    else:
      raise RuntimeError()

  def port (self, sw):
    if self.link.end[0][0] == sw:
      return self.link.end[0][1]
    elif self.link.end[1][0] == sw:
      return self.link.end[1][1]
    else:
      raise RuntimeError()

  def otherport (self, sw):
    return self.other(sw)[1]

  def pair (self, sw):
    return (sw, self.port(sw))

  def otherpair (self, sw):
    if self.link.end[0][0] == sw:
      return self.link.end[1]
    elif self.link.end[1][0] == sw:
      return self.link.end[0]
    else:
      raise RuntimeError()

  def __hash__ (self):
    return hash(self.link)

  def __cmp__ (self, other):
    if isinstance(other, LinkData):
      return cmp(self.link, other.link)
    raise RuntimeError("Bad comparison") # Don't do this



class Topo (object):
  def __init__ (self):
    self.links = {} # UniLink -> LinkData
    self.ports = {} # (dpid,port) -> LinkData
    self.switches = {} # dpid -> port -> LinkData
    self.tree_links = set()

  def clear_tree (self):
    for l in self.tree_links:
      l.on_tree = False
    self.tree_links.clear()

  def add_to_tree (self, l):
    l.on_tree = True
    self.tree_links.add(l)

  def get_link (self, link):
    if link.uni not in self.links:

      #TODO: Handle such cases?
      emsg = "Dynamic/hubbed/multi-access topology not supported"
      if link.end[0] in self.ports:
        if self.ports[link.end[0]].link != link.uni:
          raise RuntimeError(emsg)
      if link.end[1] in self.ports:
        if self.ports[link.end[1]].link != link.uni:
          raise RuntimeError(emsg)

      l = LinkData(link)
      self.links[link.uni] = l
      self.ports[link.end[0]] = l
      self.ports[link.end[1]] = l
      self._add_port(*link.end[0], link=l)
      self._add_port(*link.end[1], link=l)

    return self.links[link.uni]

  def _add_port (self, sw, port, link):
    if sw not in self.switches: self.switches[sw] = {}
    assert port not in self.switches[sw]
    # Above should always be true since dynamic topo not supported yet
    self.switches[sw][port] = link

  def get_port (self, port): # port is (dpid, port)
    return self.ports.get(port)

  def iterlinks (self, sw=None):
    """
    Iterate links, optionally only those on a given switch
    """
    if sw is None:
      return iter(self.links.values())
    if sw not in self.switches:
      return ()
    return iter(self.switches[sw].values())



class SpanningForest (object):
  def __init__ (self, mode=None):
    if mode is None: mode = 'stable'
    self._mode_function = getattr(type(self), '_compute_' + mode)
    self.log = log
    self.topo = Topo()
    self.switches = {} # dpid -> Switch
    self.t = None
    core.listen_to_dependencies(self)

  def _all_dependencies_met (self):
    self._handle_timer()

  def _handle_timer (self):
    self.t = Timer(1, self._handle_timer)
    for sw in self.switches.values():
      sw._handle_timer()

  def _handle_openflow_PortStatus (self, e):
    # Should have the switch...
    self.switches[e.dpid]._handle_PortStatus(e)

    l = self.topo.get_port((e.dpid, e.port))
    if l is not None:
      prev_liveness = l.liveness
      if is_down(e.ofp.desc):
        l.mark_dead()
      if l.liveness != prev_liveness:
        self._compute()

  def _handle_openflow_discovery_LinkEvent (self, e):
    link = self.topo.get_link(e.link)
    prev_liveness = link.liveness
    if e.added:
      link.mark_alive(e.link)
    else:
      link.mark_dead(e.link)
    if link.liveness != prev_liveness:
      self._compute()

  def _handle_openflow_ConnectionUp (self, event):
    if event.dpid not in self.switches:
      self.switches[event.dpid] = Switch(self, event.dpid)

    self.switches[event.dpid]._handle_ConnectionUp(event)
    self._compute()

  def _handle_openflow_ConnectionDown (self, event):
    if event.dpid in self.switches:
      self.switches[event.dpid]._handle_ConnectionDown(event)
      self._compute()

  def _compute (self):
    self._mode_function(self)

  def _compute_nx (self):
    """
    Computes a spanning tree using NetworkX
    """
    # Build graph of just up bidirectional links
    import networkx as NX
    g = NX.Graph()
    for l in self.topo.iterlinks():
      if l.up:
        u,v = l.link.end[0][0],l.link.end[1][0]
        if g.has_edge(u,v): continue
        g.add_edge(u, v, data=l)

    tree = NX.minimum_spanning_tree(g)
    self.log.debug("Computed spanning forest: %s of %s links",
                   tree.size(), len(self.topo.links))
    self.topo.clear_tree()
    for u,v,d in tree.edges(data=True):
      self.topo.add_to_tree(d['data'])

    for sw in self.switches.values():
      sw._compute()

  def _compute_stable (self):
    self._compute_simple(stable=True)

  def _compute_unstable (self):
    self._compute_simple(stable=False)

  def _compute_randomized (self):
    self._compute_simple(stable=False, randomize=True)

  def _compute_simple (self, stable=True, randomize=False):
    """
    Computes a spanning tree aiming for stability

    If stable=True, we prioritize reusing the same links we used the last
    time we ran so that a minimal number of changes should be made.

    It's not particularly efficient, but should be fine for reasonably
    sized graphs.
    """
    links = {l.link:l for l in self.topo.iterlinks() if l.up}

    reachable = {} # n -> set{n,n,...}

    used = []

    def add_links (links):
      for bl in links:
        l = bl.link
        if ( l.dpid2 in reachable.setdefault(l.dpid1, set([l.dpid1])) or
             l.dpid1 in reachable.setdefault(l.dpid2, set([l.dpid2])) ):
          # Already reachable
          continue
        for o in reachable.get(l.dpid2, set([l.dpid2])):
          reachable[l.dpid1].add(o)
          if o in reachable: reachable[o] = reachable[l.dpid1]
        used.append(bl)

    prev = getattr(self, "_prev", [])
    self._prev = used
    if stable:
      for i in range(len(prev)-1, -1, -1):
        l = prev[i]
        if l.link in links:
          del links[l.link]
        else:
          del prev[i]

      self.log.debug("Computing spanning forest.  New links:%s Reused:%s",
                     len(links), len(prev))
      add_links(prev)
    else:
      self.log.debug("Computing spanning forest.      Links:%s", len(links))

    links = list(links.values())
    links.sort(key=lambda l:l.link)

    if randomize:
      # If you want a really unstable tree, try this!
      import random
      random.shuffle(links)

    add_links(links)

    # Print out the nodes in each tree
    #m = set()
    #for x in reachable.itervalues():
    #  if id(x) in m: continue #m[id(x)] = len(m) + 1
    #  m.add(id(x))
    #  print sorted([hex(n)[2:] for n in x])

    self.log.debug("Spanning forest computed.  Components:%s  Links:%s",
                   len(set(id(x) for x in reachable.values())),len(used))

    self.topo.clear_tree()
    for l in used:
      self.topo.add_to_tree(l)

    for sw in self.switches.values():
      sw._compute()



def launch (mode=None):
  core.registerNew(SpanningForest, mode=mode)
