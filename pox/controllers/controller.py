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

from pox.core import core
import pox.topology.topology as topology
from pox.lib.revent import *

name = "controller"
log = core.getLogger(name)

class Controller (EventMixin, topology.Controller):
  """
  Generic Controller Application Superclass. Loads up topology and
  registers subclasse's handlers with topology et al.
  """

  _core_name = name

  # The set of components we depend on. These must be loaded before we can begin.
  _wantComponents = set(['topology'])

  def __init__(self):
    EventMixin.__init__(self)
    topology.Controller.__init__(self, "controller", handshake_complete=True)

    if not core.listenToDependencies(self, self._wantComponents):
      # If dependencies aren't fully loaded, register event handlers for ComponentRegistered
      self.listenTo(core)
    else:
      core.topology.addEntity(self)

  def _handle_ComponentRegistered (self, event):
    """ Checks whether the newly registered component is one of our dependencies """
    if core.listenToDependencies(self, self._wantComponents):
      core.topology.addEntity(self)
      return EventRemove
