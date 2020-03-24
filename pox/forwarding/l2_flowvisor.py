# Copyright 2012 James McCauley
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
import pox.openflow.spanning_tree as spanning_tree

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()


# This table maps (switch,MAC-addr) pairs to the port on 'switch' at
# which we last saw a packet *from* 'MAC-addr'.
# (In this case, we use a Connection object for the switch.)
table = {}


# A spanning tree to be used for flooding
tree = {}

def _handle_links (event):
  """
  Handle discovery link events to update the spanning tree
  """
  global tree
  tree = spanning_tree._calc_spanning_tree()


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

  packet = event.parsed

  if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
     return drop()

  # Learn the source
  table[(event.connection,packet.src)] = event.port

  if not packet.dst.is_multicast:
    dst_port = table.get((event.connection,packet.dst))
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
    msg.actions.append(of.ofp_action_output(port = event.port))
    event.connection.send(msg)

    # This is the packet that just came in -- we want to
    # install the rule and also resend the packet.
    msg = of.ofp_flow_mod()
    msg.data = event.ofp # Forward the incoming packet
    msg.match.dl_src = packet.src
    msg.match.dl_dst = packet.dst
    msg.actions.append(of.ofp_action_output(port = dst_port))
    event.connection.send(msg)

    log.debug("Installing %s <-> %s" % (packet.src, packet.dst))


def launch ():
  def start ():
    core.openflow_discovery.addListenerByName("LinkEvent", _handle_links)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("FlowVisor Pair-Learning switch running.")
  core.call_when_ready(start, "openflow_discovery")
