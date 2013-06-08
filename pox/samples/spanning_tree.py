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
Demonstrates the spanning tree module so that the L2 switch
works decently on topologies with loops.
"""

def launch (forwarding = "l2"):
  import pox.log.color
  pox.log.color.launch()
  import pox.log
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
  from pox.core import core
  import pox.openflow.discovery
  pox.openflow.discovery.launch()

  core.getLogger("openflow.spanning_tree").setLevel("INFO")
  if forwarding.lower() == "l3":
    import pox.forwarding.l3_learning as fw
  elif forwarding.lower() == "l2_multi":
    import pox.forwarding.l2_multi as fw
  else:
    import pox.forwarding.l2_learning as fw
  core.getLogger().debug("Using forwarding: %s", fw.__name__)
  fw.launch()

  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch()
