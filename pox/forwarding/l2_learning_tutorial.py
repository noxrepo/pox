# Copyright 2012 James McCauley
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
This is the world's simplest OpenFlow learning switch.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


def _handle_PacketIn (event):
  packet = event.parsed

  # If we get a packet FROM some src address on some input port, we
  # know that if we want to send TO that address, we should send it
  # out that port.  Install a rule for this.
  msg = of.ofp_flow_mod()
  msg.match.dl_dst = packet.src
  msg.actions.append(of.ofp_action_output(port = event.port))
  event.connection.send(msg)

  # Now since we got a packet at the controller, that must mean
  # that we hadn't installed a rule for the destination address
  # yet -- we don't know where it is.  So, we'll just send the
  # packet out all ports (except the one it came in on!) and
  # hope the destination is out there somewhere. :)
  msg = of.ofp_packet_out()
  msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
  msg.buffer_id = event.ofp.buffer_id # Resend the incoming packet
  msg.in_port = event.port # Don't flood out the incoming port
  event.connection.send(msg)


def launch ():
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Learning switch running.")
