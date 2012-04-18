
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