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

# This file is based on the discovery component in NOX, though it has
# been substantially rewritten.

"""
This module sends periodic echo requests to switches.

At the moment, it only works on the primary OF nexus.

It supports the following commandline options:
 --interval=X  Send an echo request every X seconds (default 20)
 --timeout=X   Expect response from switch within X seconds (default 3)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.recoco import Timer
import time

log = core.getLogger()

def _handle_timer (ofnexus):
  er = of.ofp_echo_request().pack()
  count = len(ofnexus.connections)
  t = time.time()
  dead = []

  for dpid,con in ofnexus.connections.iteritems():
    if t - con.idle_time > (_interval+_switch_timeout):
      dead.append(con)
      continue
    con.send(er)

  for con in dead:
    con.disconnect("timed out")


_running = False
_switch_timeout = None # This amount beyond interval
_interval = None

def launch (interval = 20, timeout = 3):
  global _interval, _switch_timeout
  _interval = float(interval)
  _switch_timeout = float(timeout)
  def start ():
    global _running
    if _running:
      log.error("Keepalive already running")
      return
    _running = True
    Timer(_interval, _handle_timer, recurring=True, args=(core.openflow,))
  core.call_when_ready(start, "openflow", __name__)
