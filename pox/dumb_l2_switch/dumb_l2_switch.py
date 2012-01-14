# Copyright 2011 James McCauley
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
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5

class LearningSwitch (EventMixin):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each new flow:
  1) Use source address and port to update address/port table
  2) Is ethertype LLDP?
     Yes:
        2a) Drop packet -- LLDP is never forwarded
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
     No:
        3b) Port for destination address in our address/port table?
           No:
             3ba) Flood the packet
          Yes:
             3bb1) Install flow table entry in the switch so that this
                   flow goes out the appopriate port
             3bb2) Send buffered packet out appopriate port
  """
  def __init__ (self, connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()

    def flood ():
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time > FLOOD_DELAY:
        # Only flood if we've been connected for a little while...
        #log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpidToStr(event.dpid))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      """ Drops the packet """
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if packet.type == packet.LLDP_TYPE:
      drop()
      return

    if packet.dst.isMulticast():
      flood() # 3a
    else:
      if packet.dst not in self.macToPort:
        log.debug("port for %s unknown -- flooding" % (packet.dst,))
        flood() # 3ba
      else:
        # 3bb
        port = self.macToPort[packet.dst]
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)


class dumb_l2_switch (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)

