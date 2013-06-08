# Copyright 2011-2012 James McCauley
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

  def __init__ (self, install_flow = True):
    self._install_flow = install_flow

    self.ip_to_name = {}
    self.name_to_ip = {}
    self.cname = {}

    core.openflow.addListeners(self)

    # Add handy function to console
    core.Interactive.variables['lookup'] = self.lookup

  def _handle_ConnectionUp (self, event):
    if self._install_flow:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
      msg.match.tp_src = 53
      msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
      event.connection.send(msg)

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

  def _handle_PacketIn (self, event):
    p = event.parsed.find('dns')

    if p is not None and p.parsed:
      log.debug(p)

      for q in p.questions:
        if q.qclass != 1: continue # Internet only
        self.raiseEvent(DNSLookup, q)

      def process_q (entry):
        if entry.qclass != 1:
          # Not internet
          return

        if entry.qtype == pkt.dns.rr.CNAME_TYPE:
          if self._record_cname(entry.name, entry.rddata):
            self.raiseEvent(DNSUpdate, entry.name)
            log.info("add cname entry: %s %s" % (entry.rddata, entry.name))
        elif entry.qtype == pkt.dns.rr.A_TYPE:
          if self._record(entry.rddata, entry.name):
            self.raiseEvent(DNSUpdate, entry.name)
            log.info("add dns entry: %s %s" % (entry.rddata, entry.name))

      for answer in p.answers:
        process_q(answer)
      for addition in p.additional:
        process_q(addition)


def launch (no_flow = False):
  core.registerNew(DNSSpy, not no_flow)
