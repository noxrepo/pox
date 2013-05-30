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
This makes Nicira-extension capable switches into learning switches

This uses the "learn" action so that switches become learning switches
*with no controller involvement*.

  ./pox.py openflow.nicira forwarding.l2_nx_self_learning
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nx


log = core.getLogger("l2_nx_self_learning")


def _handle_ConnectionUp (event):
  # Set up this switch.

  # Turn on ability to specify table in flow_mods
  msg = nx.nx_flow_mod_table_id()
  event.connection.send(msg)

  # Clear second table
  msg = nx.nx_flow_mod(command=of.OFPFC_DELETE, table_id = 1)
  event.connection.send(msg)

  # Learning rule in table 0
  msg = nx.nx_flow_mod()
  msg.table_id = 0

  learn = nx.nx_action_learn(table_id=1,hard_timeout=10)
  learn.spec.chain(
      field=nx.NXM_OF_VLAN_TCI, n_bits=12).chain(
      field=nx.NXM_OF_ETH_SRC, match=nx.NXM_OF_ETH_DST).chain(
      field=nx.NXM_OF_IN_PORT, output=True)

  msg.actions.append(learn)
  msg.actions.append(nx.nx_action_resubmit.resubmit_table(1))
  event.connection.send(msg)

  # Fallthrough rule for table 1: flood
  msg = nx.nx_flow_mod()
  msg.table_id = 1
  msg.priority = 1 # Low priority
  msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
  event.connection.send(msg)



def launch ():
  def start ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("NX self-learning switch running.")
  core.call_when_ready(start, ['NX','openflow'])
