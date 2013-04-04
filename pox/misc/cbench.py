# Copyright 2013 YAMAMOTO Takashi
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
a dummy module for oflops cbench benchmark

this is intended to be comparable with ryu cbench app.
	https://github.com/osrg/ryu/blob/master/ryu/app/cbench.py
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of


class CBench (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def _handle_PacketIn (self, event):
    msg = of.ofp_flow_mod()
    self.connection.send(msg)

class cbench (object):
  def __init__ (self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp (self, event):
    CBench(event.connection)


def launch ():
  core.registerNew(cbench)
