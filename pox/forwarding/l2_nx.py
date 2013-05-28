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
A quick-and-dirty learning switch for Open vSwitch

This learning switch requires Nicira extensions as found in Open vSwitch.
Furthermore, you must enable packet-in conversion.  Run with something like:
  ./pox.py openflow.nicira --convert-packet-in forwarding.l2_nx

This forwards based on ethernet source and destination addresses.  Where
l2_pairs installs rules for each pair of source and destination address,
this component uses two tables on the switch -- one for source addresses
and one for destination addresses.  Specifically, we use tables 0 and 1
on the switch to implement the following logic:
0. Is this source address known?
   NO: Send to controller (so we can learn it)
1. Is this destination address known?
   YES:  Forward out correct port
   NO: Flood

Note that unlike the other learning switches *we keep no state in the
controller*.  In truth, we could implement this whole thing using OVS's
learn action, but doing it something like is done here will still allow
us to implement access control or something at the controller.
"""

from pox.core import core
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nx
from pox.lib.revent import EventRemove


# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()


def _handle_PacketIn (event):
  packet = event.parsed

  if event.port > of.OFPP_MAX:
    log.debug("Ignoring special port %s", event.port)
    return

  # Add to source table
  msg = nx.nx_flow_mod()
  msg.match.of_eth_src = packet.src
  msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
  event.connection.send(msg)

  # Add to destination table
  msg = nx.nx_flow_mod()
  msg.table_id = 1
  msg.match.of_eth_dst = packet.src
  msg.actions.append(of.ofp_action_output(port = event.port))
  event.connection.send(msg)

  log.info("Learning %s on port %s of %s"
           % (packet.src, event.port, event.connection))


def _handle_ConnectionUp (event):
  # Set up this switch.
  # After setting up, we send a barrier and wait for the response
  # before starting to listen to packet_ins for this switch -- before
  # the switch is set up, the packet_ins may not be what we expect,
  # and our responses may not work!

  # Turn on Nicira packet_ins
  msg = nx.nx_packet_in_format()
  event.connection.send(msg)

  # Turn on ability to specify table in flow_mods
  msg = nx.nx_flow_mod_table_id()
  event.connection.send(msg)

  # Clear second table
  msg = nx.nx_flow_mod(command=of.OFPFC_DELETE, table_id = 1)
  event.connection.send(msg)

  # Fallthrough rule for table 0: flood and send to controller
  msg = nx.nx_flow_mod()
  msg.priority = 1 # Low priority
  msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
  msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
  event.connection.send(msg)

  # Fallthrough rule for table 1: flood
  msg = nx.nx_flow_mod()
  msg.table_id = 1
  msg.priority = 1 # Low priority
  msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
  event.connection.send(msg)

  def ready (event):
    if event.ofp.xid != 0x80000000:
      # Not the right barrier
      return
    log.info("%s ready", event.connection)
    event.connection.addListenerByName("PacketIn", _handle_PacketIn)
    return EventRemove

  event.connection.send(of.ofp_barrier_request(xid=0x80000000))
  event.connection.addListenerByName("BarrierIn", ready)


def launch ():
  def start ():
    if not core.NX.convert_packet_in:
      log.error("PacketIn conversion required")
      return
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("Simple NX switch running.")
  core.call_when_ready(start, ['NX','openflow'])
