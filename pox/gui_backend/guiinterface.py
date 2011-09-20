# Copyright 2011 James McCauley
# Copyright 2011 Kyriakos Zarifis
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
This is the communication interface between POX and the GUI.
The gui backend component acts as a proxy between other components and the GUI.

GUI --> POX component:
If we want to trigger component functionality through the GUI, the component
must exposes that functionality through its API. The "backend" should just call
that API when ith gets input from the GUI (for example, think monitoring).

POX component --> GUI
If the component wants to send something to the GUI, it just raises events.
The backend listens to those events and packs them up and sends them to the GUI.

Note: log messages are treated separately, and use their own communication
channel
"""

from pox.lib.revent.revent import *
from pox.lib.recoco.recoco import *
import pox.core
from pox.core import core as core
import json

log = pox.core.getLogger()
