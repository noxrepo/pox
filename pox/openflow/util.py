# Copyright 2011-2013 James McCauley
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

import pox.openflow.libopenflow_01 as of
import struct
from pox.lib.revent import EventMixin
import pox.openflow

def make_type_to_unpacker_table ():
  """
  Returns a list of unpack methods.

  The resulting list maps OpenFlow types to functions which unpack
  data for those types into message objects.
  """

  top = max(of._message_type_to_class)

  r = [of._message_type_to_class[i].unpack_new for i in range(0, top+1)]

  return r


class DPIDWatcher (EventMixin):
  """
  Strains OpenFlow messages by DPID
  """

  #TODO: Reference count handling

  _eventMixin_events = pox.openflow.OpenFlowNexus._eventMixin_events

  def __init__ (self, dpid, nexus = None, invert = False):

    if nexus is None:
      from pox.core import core
      nexus = core.openflow

    self.invert = invert

    self._dpids = set()
    if isinstance(dpid, str):
      dpid = dpid.replace(',',' ')
      dpid = dpid.split()
    if isinstance(dpid, (list,tuple)):
      for d in dpid:
        self._add_dpid(d)
    else:
      self._add_dpid(dpid)

    #core.listen_to_dependencies(self)

    for ev in self._eventMixin_events:
      nexus.addListener(ev, self._handler)

  def _handler (self, event, *args, **kw):
    dpid = getattr(event, 'dpid', None)
    if dpid is None:
      return

    if self.invert:
      if event.dpid in self._dpids: return
    else:
      if event.dpid not in self._dpids: return

    if len(args) or len(kw):
      log.warn("Custom invoke for %s", event)
      # This is a warning because while I think this will always or almost
      # always work, I didn't feel like checking.

    self.raiseEventNoErrors(event)

  def _add_dpid (self, dpid):
    if dpid is True:
      # Special case -- everything!
      self._dpids = True
      return
    elif self._dpids is True:
      self._dpids = set()
    try:
      dpid = int(dpid)
    except:
      dpid = str_to_dpid(dpid)
    self._dpids.add(dpid)
