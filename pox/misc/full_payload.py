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
