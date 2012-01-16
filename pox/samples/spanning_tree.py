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
