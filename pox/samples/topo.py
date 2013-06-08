# Copyright 2011 James McCauley
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
Fires up topology, discovery, and a l2 learning switch controller
"""

def launch ():
  import pox.topology
  pox.topology.launch()
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.openflow.topology
  pox.openflow.topology.launch()
  import pox.forwarding.l2_learning
  pox.forwarding.l2_learning.launch()
