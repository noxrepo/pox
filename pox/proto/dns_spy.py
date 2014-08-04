# Copyright 2011-2012 James McCauley
# Copyright 2013 Felician Nemeth
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
This component spies on DNS replies, stores the results, and raises events
when things are looked up or when its stored mappings are updated.

Similar to NOX's DNSSpy component, but with more features.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.packet.dns as pkt_dns

from pox.lib.addresses import IPAddr
from pox.lib.revent import *

log = core.getLogger()


class DNSUpdate (Event):
  def __init__ (self, item):
    Event.__init__()
    self.item = item

class DNSLookup (Event):
  def __init__ (self, rr):
    Event.__init__()

    self.name = rr.name
    self.qtype = rr.qtype

    self.rr = rr
    for t in pkt_dns.rrtype_to_str.values():
      setattr(self, t, False)
    t = pkt_dns.rrtype_to_str.get(rr.qtype)
    if t is not None:
      setattr(self, t, True)
      setattr(self, "OTHER", False)
    else:
      setattr(self, "OTHER", True)


class DNSSpy (EventMixin):
  _eventMixin_events = set([ DNSUpdate, DNSLookup ])

  def __init__ (self)
    self.ip_to_name = {}
    self.name_to_ip = {}
    self.cname = {}

    core.listen_to_dependencies(self)

    # Add handy function to console
    core.Interactive.variables['lookup'] = self.lookup

  def lookup (self, something):
    if something in self.name_to_ip:
      return self.name_to_ip[something]
    if something in self.cname:
      return self.lookup(self.cname[something])
    try:
      return self.ip_to_name.get(IPAddr(something))
    except:
      return None

  def _record (self, ip, name):
    # Handle reverse lookups correctly?
    modified = False
    val = self.ip_to_name.setdefault(ip, [])
    if name not in val:
      val.insert(0, name)
      modified = True

    val = self.name_to_ip.setdefault(name, [])
    if ip not in val:
      val.insert(0, ip)
      modified = True

    return modified

  def _record_cname (self, name, cname):
    modified = False
    val = self.cname.setdefault(name, [])
    if name not in val:
      val.insert(0, cname)
      modified = True

    return modified

  def _handle_DNSHelper_DNSLookup (self, event):
    if rrclass_to_str.get(entry.qclass, '') != "IN":
      return # Internet only

    self.raiseEvent(DNSLookup, event.rr)

  def _handle_DNSHelper_DNSAnswer (self, event):
    entry = event.item
    if entry.qtype == pkt.dns.rr.CNAME_TYPE:
      if self._record_cname(entry.name, entry.rddata):
        self.raiseEvent(DNSUpdate, entry.name)
        log.info("add cname entry: %s %s" % (entry.rddata, entry.name))
    elif entry.qtype == pkt.dns.rr.A_TYPE:
      if self._record(entry.rddata, entry.name):
        self.raiseEvent(DNSUpdate, entry.name)
        log.info("add dns entry: %s %s" % (entry.rddata, entry.name))


def launch ():
  core.registerNew(DNSSpy)
