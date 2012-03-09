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
This package contains a nom-based L2 learning switch.
"""
from pox.core import core
log = core.getLogger("nom_l2_switch_controller.init")

def launch (distributed=False):
  # TODO: need a more transparent mechanism for specifying the debug flag...
  """
  Starts a NOM-based L2 learning switch, along with the discovery and topology modules
  """
  if type(distributed) == bool and distributed:
    distributed = 1
  elif type(distributed) == str:
    distributed = int(distributed)

  import pox.openflow.connection_arbiter
  pox.openflow.connection_arbiter.launch()

  import pox.openflow.topology
  pox.openflow.topology.launch()

  import pox.topology
  pox.topology.launch()

  import pox.openflow.discovery
  pox.openflow.discovery.launch()

  from pox.core import core
  if distributed:
    import pox.controllers.nom_server as nom_server
    # creates listening tcp socket via messenger
    # sends serialized master topology to connecting client controllers
    nom_server.launch()

    import distributed_nom_l2_switch_controller
    for id in range(0, distributed):
      # TODO: no sure if I should be registering these with core
      # (name conflict, and not suitable for emulation with true distrbuted controller)
      # for now this is just to keep the controllers from being garbage collected
      name = "controller#%d" % id
      # each controller sends a get request to the nom_server on inititalization
      core.register(name, distributed_nom_l2_switch_controller.nom_l2_switch_controller(name))

  else:
    # not distributed
    import nom_l2_switch_controller
    core.registerNew(nom_l2_switch_controller.nom_l2_switch_controller)

  log.info("l2_switch_controller launch completed")
