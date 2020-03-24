# Copyright 2011 Dorgival Guedes
# Copyright 2013 James McCauley
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
Tracks host location and configuration

See host_tracker.host_tracker for more info.
"""

from pox.core import core
from . import host_tracker
log = core.getLogger()
import logging
log.setLevel(logging.INFO)
from pox.lib.addresses import EthAddr

def launch (src_mac = None, no_flow = False, **kw):
  for k, v in kw.items():
    if k in host_tracker.timeoutSec:
      host_tracker.timeoutSec[k] = int(v)
      log.debug("Changing timer parameter: %s = %s",k,v)
    elif k == 'pingLim':
      host_tracker.PingCtrl.pingLim = int(v)
      log.debug("Changing ping limit to %s",v)
    else:
      log.error("Unknown option: %s(=%s)",k,v)
  core.registerNew(host_tracker.host_tracker, ping_src_mac = src_mac,
      install_flow = not no_flow)
