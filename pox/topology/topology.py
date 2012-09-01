# Copyright 2011
#
# This file is part of POX.
# Some of the arp/openflow-related code was borrowed from dumb_l3_switch.
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
The Topology module is the root of an object model composed of entities
like switches, hosts, links, etc.  This object model is populated by other
modules.  For example, openflow.topology populates the topology object
with OpenFlow switches.

Note that this means that you often want to invoke something like:
   $ ./pox.py topology openflow.discovery openflow.topology
"""

from pox.lib.revent import *
from pox.core import core
from pox.lib.addresses import *
from pox.lib.graph.nom import NOM

class Topology (NOM):

  _core_name = "topology" # We want to be core.topology

  def __init__ (self, name="topology"):
    NOM.__init__(self)
    self.log = core.getLogger(name)

  def __len__(self):
    return len(self.getEntitiesOfType())

  def __str__(self):
    # TODO: display me graphically
    strings = []
    strings.append("topology (%d total entities)" % len(self))
    for entity in self.getEntitiesOfType():
      strings.append(str(entity))

    return '\n'.join(strings)
