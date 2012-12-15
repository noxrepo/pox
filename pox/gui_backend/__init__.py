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
Fires up messenger, guimessenger, and monitoring
"""

def launch ():
  import pox.messenger.messenger
  pox.messenger.messenger.launch()
  import pox.messenger.mux
  pox.messenger.mux.launch()
  import pox.gui_backend.guimessenger
  pox.gui_backend.guimessenger.launch()
  import pox.messenger.log_service
  pox.messenger.log_service.launch()
  import pox.gui_backend.monitoring
  pox.gui_backend.monitoring.launch()
