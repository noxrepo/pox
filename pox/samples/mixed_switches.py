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

"""
A quick example of treating different datapaths differently.

Although it's not currently particularly well supported, there's
nothing to stop one from using different components with particular
switches.  There are multiple ways to do this, but this component
demonstrates a pretty straightforward one.

When components are loaded from the commandline, their launch()
function is run.  In many cases, this launch() function sets up
a listener for openflow.ConnectionUp events.  When one is raised,
the component handles it by setting up more event listeners on
that connection.

If we want to have some switches behave one way and others
behave another way, we simply don't let them set up their own
ConnectionUp handlers and take care of initializing the rest
of the component ourself.

Here we demonstrate that by making switches with odd-numbered
DPIDs be l2_pairs switches and even-numbered DPIDs be l2_learning
switches.
"""

from pox.core import core
import pox.forwarding.l2_pairs as l2p
import pox.forwarding.l2_learning as l2l

log = core.getLogger()

def _handle_ConnectionUp (event):
  if event.dpid & 1 == 1:
    log.info("Treating %s as l2_pairs", event.connection)
    event.connection.addListenerByName("PacketIn", l2p._handle_PacketIn)
  else:
    log.info("Treating %s as l2_learning", event.connection)
    l2l.LearningSwitch(event.connection, False)

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  log.info("Mixed switches demo running.")
