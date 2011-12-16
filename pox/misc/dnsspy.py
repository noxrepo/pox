# Copyright 2011 James McCauley
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
This is a port of NOX's DNSSpy component.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.packet import *

log = core.getLogger()

class DNSSpy (EventMixin):
  def __init__ (self):
    self.ip_records = {}

    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_proto = ipv4.UDP_PROTOCOL
    msg.match.tp_src = 53
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    event.connection.send(msg)

  def _handle_PacketIn (self, event):
    p = event.parse().find('dns')
    if p is not None:
      log.debug(p)

      for answer in p.answers:
        if answer.qtype == dns.dns.rr.A_TYPE:
          val = self.ip_records[answer.rddata]
          if answer.name not in val:
            val.insert(0, answer.name)

            log.info("add dns entry: %s %s" % (answer.rddata, answer.name))

      for addition in p.additional:
        if addition.qtype == dns.dns.rr.A_TYPE: 
          val = self.ip_records[addition.rddata]
          if addition.name not in val:
            val.insert(0, addition.name)
            log.info("additional dns entry: %s %s" % (addition.rddata, addition.name))


def launch ():
  core.registerNew(DNSSpy)
