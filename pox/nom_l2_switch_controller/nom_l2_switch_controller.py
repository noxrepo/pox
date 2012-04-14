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
This is a prototype control application written on top of the (substrate) NOM.

It converts NOM switch entities into LearningSwitches.
"""

from pox.core import core
from pox.controllers.controller import Controller
from learning_switch import LearningSwitch

name = "l2_controller"
log = core.getLogger(name)

# In addition to declaring the user-defined NOM entity, the application must tell the platform
# how and when to instantiate these NOM entities. We do this with the following controller:
class nom_l2_switch_controller (Controller):
  """ Controller that treats the network as a set of learning switches """

  _core_name = name

  def __init__ (self):
    """ Initializes the l2 switch controller component """
    Controller.__init__(self)
    log.debug("nom_l2_switch_controller booting...")

  def _handle_topology_SwitchJoin(self, switchjoin_event):
    """ Convert switches into Learning Switches """
    log.debug("Switch Join! %s " % switchjoin_event)
    switch = switchjoin_event.switch
    name = "learning_" + switch.name
    core.topology.addEntity(LearningSwitch(name, switch))
