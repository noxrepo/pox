# Copyright 2013 xeonkung
# This is Toll Way project
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
A modification of l2_pairs to work with FlowVisor on looped topologies.

The spanning_tree component doesn't work with FlowVisor because FlowVisor
does not virtualize the NO_FLOOD bit on switch ports, which is what
the spanning_tree component would need to work properly.

This hack of l2_pairs uses the spanning tree construction from the
spanning_tree component, but instead of using it to modify port bits,
instead of ever actually flooding, it "simulates" flooding by just
adding all of the ports on the spanning tree as individual output
actions.

Requires discovery.
"""

# These next two imports are common POX convention
from pox.core import core
import pox.openflow.libopenflow_01 as of
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()


# This table maps (switch,MAC-addr) pairs to the port on 'switch' at
# which we last saw a packet *from* 'MAC-addr'.
# (In this case, we use a Connection object for the switch.)
table = {}

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# A spanning tree to be used for flooding
tree = {}
tollway_port = {}

# database file path
dbfile = '~/xeonkung/Documents/KMUTNB/Programing/tollway/tollway.db'

def _is_toll_way(event):
  return False

def _xxx_match_parse(match):
  of_match = of.ofp_match()
  conn = sqlite3.connect(dbfile)
  c = conn.cursor()
  # do somthing

  conn.close()
  if match.get("l2") is not None:
    # apply l2 match

    if :
      pass

def _calc_tree ():
  """
  Calculates the actual spanning tree

  Returns it as dictionary where the keys are DPID1, and the
  values are tuples of (DPID2, port-num), where port-num
  is the port on DPID1 connecting to DPID2.
  """
  def flip (link):
    return Discovery.Link(link[2],link[3], link[0],link[1])

  adj = defaultdict(lambda:defaultdict(lambda:[]))
  normal = defaultdict(lambda:defaultdict(lambda:None))
  tollway = defaultdict(lambda:defaultdict(lambda:None))
  switches = set()
  # tollway port
  tp = defaultdict(lambda:defaultdict(lambda:None))

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
      for l in adj[s1][s2]:
        if flip(l) in core.openflow_discovery.adjacency:
          # This is Full Duplex Link
          if normal[s1][s2] is None:
            normal[s1][s2] = l.port1
            normal[s2][s1] = l.port2
          elif tollway[s1][s2] is None:
            tollway[s1][s2] = l.port1
            tollway[s2][s1] = l.port2
            # add toll way port
            tp[s1][normal[s1][s2]] = l.port1
            tp[s2][normal[s2][s1]] = l.port2 


  # cal normal tree
  q = []
  more = set(switches)

  done = set()

  nTree = defaultdict(set)
  
  while True:
    q = sorted(list(more)) + q
    more.clear()
    if len(q) == 0: break
    v = q.pop(False)
    if v in done: continue
    done.add(v)
    for w,p in normal[v].iteritems():
      if w in nTree: continue
      more.add(w)
      nTree[v].add((w,p))
      nTree[w].add((v,normal[w][v]))

  global tree
  tree = nTree

  global tollway_port
  tollway_port = tp

  log.debug("Finish _calc_tree()")

def _handle_links (event):
  """
  Handle discovery link events to update the spanning tree
  """
  _calc_tree()


def _handle_PacketIn (event):
  """
  Handle messages the switch has sent us because it has no
  matching rule.
  """

  def drop ():
    # Kill buffer on switch
    if event.ofp.buffer_id is not None:
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      event.connection.send(msg)

  def send_tollway(normal_port):
    # out when hasn't toll way
    if tollway_port[event.connection.dpid][dst_port] is None:
      return False
    # Check tollway registered Packet
    return False

  packet = event.parsed

  if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
     return drop()

  # Learn the source
  table[(event.connection.dpid, packet.src)] = event.port

  if not packet.dst.is_multicast:
    dst_port = table.get((event.connection.dpid, packet.dst))
    if _is_toll_way(event) and tollway_port[event.connection.dpid][dst_port] is not None:
      dst_port = tollway_port[event.connection.dpid][dst_port]
      log.debug("Go with Tollway port")
      return    
  else:
    # Ideally, we'd install a flow entries that output multicasts
    # to all ports on the spanning tree.
    dst_port = None

  if dst_port is None:
    # We don't know where the destination is yet.  So, we'll just
    # send the packet out all ports in the spanning tree
    # and hope the destination is out there somewhere. :)
    msg = of.ofp_packet_out(data = event.ofp)

    tree_ports = [p[1] for p in tree.get(event.dpid, [])]

    for p in event.connection.ports:
      if p >= of.OFPP_MAX:
        # Not a normal port
        continue

      if not core.openflow_discovery.is_edge_port(event.dpid, p):
        # If the port isn't a switch-to-switch port, it's fine to flood
        # through it.  But if it IS a switch-to-switch port, we only
        # want to use it if it's on the spanning tree.
        if p not in tree_ports:
          continue

      msg.actions.append(of.ofp_action_output(port = p))

    event.connection.send(msg)

  else:
    # Since we know the switch ports for both the source and dest
    # MACs, we can install rules for both directions.
    msg = of.ofp_flow_mod()
    msg.match.dl_dst = packet.src
    msg.match.dl_src = packet.dst
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = event.port))
    event.connection.send(msg)
    
    # This is the packet that just came in -- we want to
    # install the rule and also resend the packet.
    msg = of.ofp_flow_mod()
    msg.data = event.ofp # Forward the incoming packet
    msg.match.dl_src = packet.src
    msg.match.dl_dst = packet.dst
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = dst_port))
    event.connection.send(msg)

    log.debug("Installing %s <-> %s" % (packet.src, packet.dst))


def launch (db=None):
  def start ():
    core.openflow_discovery.addListenerByName("LinkEvent", _handle_links)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("FlowVisor Pair-Learning switch running.")
  global dbfile
  if db is not None:
    dbfile = db
  core.call_when_ready(start, "openflow_discovery")