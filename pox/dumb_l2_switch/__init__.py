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
This package contains two L2 learning switches for OpenFlow.

The default, dumb_l2_switch, is written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.

The other, ofcommand_l2_switch, is derived originally from NOX's pyswitch
example.  It is now a demonstration of the ofcommand library for constructing
OpenFlow messages.
"""

def launch ():
  """
  Starts an L2 learning switch.
  """
  import dumb_l2_switch
  from pox.core import core
  core.registerNew(dumb_l2_switch.dumb_l2_switch)
