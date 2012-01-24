# Copyright 2011 Dorgival Guedes
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

from pox.core import core
import pox
import host_tracker
log = core.getLogger()
import logging
log.setLevel(logging.INFO)

def launch (**kw):
  core.registerNew(host_tracker.host_tracker)
  for k, v in kw.iteritems():
    if k in host_tracker.timeoutSec:
      host_tracker.timeoutSec[k] = int(v)
      log.warn("Changing timer parameter: %s = %s",k,v)
    elif k == 'pingLim':
      host_tracker.PingCtrl.pingLim = int(v)
      log.warn("Changing ping limit to %s",v)
    else:
      log.warn("Unknown option: %s(=%s)",k,v)
      
     

