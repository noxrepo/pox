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
This simple component makes it so that switches send full packet
payloads on table misses.
"""

from pox.core import core
from pox.lib.revent import EventRemove

def launch ():
  def set_miss_length (event = None):
    if not core.hasComponent('openflow'):
      return
    core.openflow.miss_send_len = 0x7fff
    core.getLogger().info("Requesting full packet payloads")
    return EventRemove
    
  if set_miss_length() is None:
    core.addListenerByName("ComponentRegistered", set_miss_length)
