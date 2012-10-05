# Copyright 2011-2012 James McCauley
# Copyright 2008 (C) Nicira, Inc.
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

"""
This component spies on DNS replies.

Similar to NOX's DNSSpy component.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr

log = core.getLogger()

class DNSSpy (object):
  def __init__ (self, install_flow = True):
    self._install_flow = install_flow

    self.ip_to_name = {}
    self.name_to_ip = {}

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
    try:
      return self.ip_to_name.get(IPAddr(something))
    except:
      return None

  def _record (self, ip, name):
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

  def _handle_PacketIn (self, event):
    p = event.parsed.find('dns')

    if p is not None and p.parsed:
      log.debug(p)

      for answer in p.answers:
        if answer.qtype == pkt.dns.rr.A_TYPE:
          if self._record(answer.rddata, answer.name):
            log.info("add dns entry: %s %s" % (answer.rddata, answer.name))

      for addition in p.additional:
        if addition.qtype == pkt.dns.rr.A_TYPE: 
          if self._record(addition.rddata, addition.name):
            log.info("additional dns entry: %s %s" % (addition.rddata,
                                                      addition.name))


def launch (no_flow = False):
  core.registerNew(DNSSpy, not no_flow)
