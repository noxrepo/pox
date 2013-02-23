# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
Creates a spanning tree.

This component uses the discovery component to build a view of the network
topology, constructs a spanning tree, and then disables flooding on switch
ports that aren't on the tree by setting their NO_FLOOD bit.  The result
is that topologies with loops no longer turn your network into useless
hot packet soup.

This component is inspired by and roughly based on the description of
Glenn Gibb's spanning tree module for NOX:
  http://www.openflow.org/wk/index.php/Basic_Spanning_Tree

Note that this does not have much of a relationship to Spanning Tree
Protocol.  They have similar purposes, but this is a rather different way
of going about it.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer

log = core.getLogger()

# Might be nice if we made this accessible on core...
#_adj = defaultdict(lambda:defaultdict(lambda:[]))

def _calc_spanning_tree ():
  """
  Calculates the actual spanning tree

  Returns it as dictionary where the keys are DPID1, and the
  values are tuples of (DPID2, port-num), where port-num
  is the port on DPID1 connecting to DPID2.
  """
  def flip (link):
    return Discovery.Link(link[2],link[3], link[0],link[1])

  adj = defaultdict(lambda:defaultdict(lambda:[]))
  switches = set()
  # Add all links and switches
  for l in core.openflow_discovery.adjacency:
    adj[l.dpid1][l.dpid2].append(l)
    switches.add(l.dpid1)
    switches.add(l.dpid2)

  # Cull links -- we want a single symmetric link connecting nodes
  for s1 in switches:
    for s2 in switches:
      if s2 not in adj[s1]:
        continue
      if not isinstance(adj[s1][s2], list):
        continue
      assert s1 is not s2
      good = False
      for l in adj[s1][s2]:
        if flip(l) in core.openflow_discovery.adjacency:
          # This is a good one
          adj[s1][s2] = l.port1
          adj[s2][s1] = l.port2
          good = True
          break
      if not good:
        del adj[s1][s2]
        if s1 in adj[s2]:
          # Delete the other way too
          del adj[s2][s1]

  q = []
  more = set(switches)

  done = set()

  tree = defaultdict(set)

  while True:
    q = sorted(list(more)) + q
    more.clear()
    if len(q) == 0: break
    v = q.pop(False)
    if v in done: continue
    done.add(v)
    for w,p in adj[v].iteritems():
      if w in tree: continue
      more.add(w)
      tree[v].add((w,p))
      tree[w].add((v,adj[w][v]))

  if False:
    log.debug("*** SPANNING TREE ***")
    for sw,ports in tree.iteritems():
      #print " ", dpidToStr(sw), ":", sorted(list(ports))
      #print " ", sw, ":", [l[0] for l in sorted(list(ports))]
      log.debug((" %i : " % sw) + " ".join([str(l[0]) for l in
                                           sorted(list(ports))]))
    log.debug("*********************")

  return tree


# Keep a list of previous port states so that we can skip some port mods
_prev = defaultdict(lambda : defaultdict(lambda : None))


def _reset (event):
  # When a switch connects, forget about previous port states
  _prev[event.dpid].clear()


def _handle (event):
  # When links change, update spanning tree

  # Get a spanning tree
  tree = _calc_spanning_tree()
  log.debug("Spanning tree updated")

  # Now modify ports as needed
  try:
    change_count = 0
    for sw, ports in tree.iteritems():
      con = core.openflow.getConnection(sw)
      if con is None: continue # Must have disconnected
      tree_ports = [p[1] for p in ports]
      for p in con.ports.itervalues():
        if p.port_no < of.OFPP_MAX:
          flood = p.port_no in tree_ports
          if not flood:
            if core.openflow_discovery.is_edge_port(sw, p.port_no):
              flood = True
          if _prev[sw][p.port_no] is flood:
            continue # Skip
          change_count += 1
          _prev[sw][p.port_no] = flood
          #print sw,p.port_no,flood
          #TODO: Check results

          pm = of.ofp_port_mod(port_no=p.port_no,
                               hw_addr=p.hw_addr,
                               config = 0 if flood else of.OFPPC_NO_FLOOD,
                               mask = of.OFPPC_NO_FLOOD)
          con.send(pm)

          _invalidate_ports(con.dpid)
    if change_count:
      log.info("%i ports changed", change_count)
  except:
    _prev.clear()
    log.exception("Couldn't push spanning tree")


_dirty_switches = {} # A map dpid_with_dirty_ports->Timer
_coalesce_period = 2 # Seconds to wait between features requests

def _invalidate_ports (dpid):
  """
  Registers the fact that port info for dpid may be out of date

  When the spanning tree adjusts the port flags, the port config bits
  we keep in the Connection become out of date.  We don't want to just
  set them locally because an in-flight port status message could
  overwrite them.  We also might not want to assume they get set the
  way we want them.  SO, we do send a features request, but we wait a
  moment before sending it so that we can potentially coalesce several.

  TLDR: Port information for this switch may be out of date for around
        _coalesce_period seconds.
  """
  if dpid in _dirty_switches:
    # We're already planning to check
    return
  t = Timer(_coalesce_period, _check_ports, args=(dpid,))
  _dirty_switches[dpid] = t

def _check_ports (dpid):
  """
  Sends a features request to the given dpid
  """
  _dirty_switches.pop(dpid,None)
  con = core.openflow.getConnection(dpid)
  if con is None: return
  con.send(of.ofp_barrier_request())
  con.send(of.ofp_features_request())
  log.debug("Requested switch features for %s", str(con))


def launch ():
  def start_spanning_tree ():
    core.openflow.addListenerByName("ConnectionUp", _reset)
    core.openflow_discovery.addListenerByName("LinkEvent", _handle)
    log.debug("Spanning tree component ready")
  core.call_when_ready(start_spanning_tree, "openflow_discovery")

