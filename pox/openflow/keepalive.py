# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

  for dpid,con in ofnexus.connections.items():
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
