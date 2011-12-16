# Copyright 2011 James McCauley
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
Fires up topology, discovery, and host_tracker
"""

def launch ():
  import pox.topology
  pox.topology.launch()
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.openflow.topology
  pox.openflow.topology.launch()
  import pox.host_tracker
  pox.host_tracker.launch()
