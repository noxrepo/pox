# Copyright 2013 YAMAMOTO Takashi
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
