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
Demonstrates the spanning tree module so that the L2 switch
works decently on topologies with loops.
"""

def launch (l3 = False):
  import pox.log.color
  pox.log.color.launch()
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch()
  if l3:
    import pox.forwarding.l3_learning
    pox.forwarding.l3_learning.launch()
  else:
    import pox.forwarding.l2_learning
    pox.forwarding.l2_learning.launch()
