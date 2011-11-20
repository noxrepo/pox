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

"""
This is a prototype control application written on top of the (substrate) NOM. 

It demonstrates that there are a lot of design decisions to be made.. In particular,
it seems there is a tension between the constraints of order-independence (the
application should keep no state of its own, therefore all state should be
stored in the NOM) and the need to hide the details of the lower layers of the
NOM functionality (e.g. pox.openflow.topology) from the application developer.

So,
- Should the application developer define custom NOM entities within their own
  modules, or at a lower layer? 
- If in their own module, how do we get the lower layers
  (i.e. pox.openflow.topology) to instantiate the custom  NOM entity rather
  than the default (i.e. OpenFlowSwitch)
- Should we provide a generic mechanism for users to define custom NOM entities 
  from their own module? For example, we could allow them to add handlers via
  python reflection foo to the default NOM entities.

More thoughts inline.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.openflow import PacketIn 
from pox.lib.revent.revent import *

log = core.getLogger()

class nom_l2_switch_controller (EventMixin):
  def __init__ (self):
    """
    Precondition: pox.topology is loaded 

    TODO: How do applications specify whether they want to use the NOM or not? 
    Does inheritance seems like the cleanest way..?
    
    On a related note, should we have a well-defined interface (`nom_update()`)
    that all applications wishing to use the NOM implement? Or, do we just
    interpose on their Topology.EntityJoin event handlers?
    """
    log.debug("nom_l2_switch_controller booting...")
    
    # For now, just add listeners for Topology.EntityJoin events
    topo = core.components['topology']
    assert(topo is not None, "pox.topology not loaded yet!")
    self.listenTo(topo)

  def _handle_SwitchJoin(self, join_event):
    switch = join_event.switch
    log.debug("SwitchJoin! %s" % (str(switch)))
    # Turn that sucker into a Learning switch!
    # Note that we can externally add attributes to NOM entities easily like so:
    switch.macToPort = {}

    # Adding event handlers to NOM entities is a little trickier:
    # Hopefully there's a better way? Another option would be to add a method
    # `_handle_PacketIn` with python reflection foo. 
    def PacketIn_handler (packet_in_event):
      log.debug("PacketIn_handler! packet_in_event: %s" % (str(packet_in_event)))
      """
      The learning switch "brain". 
  
      When we see a packet, we'd like to output it on a port which will join_eventually
      lead to the destination.  To accomplish this, we build a table that maps
      addresses to ports.
  
      We populate the table by observing traffic.  When we see a packet from some
      source coming from some port, we know that source is out that port.
  
      When we want to forward traffic, we look up the destination in our table.  If
      we don't know the port, we simply send the message out all ports except the
      one it came in on.  (In the presence of loops, this is bad!).
  
      In short, our algorithm looks like this:
  
      For each new flow:
      1) Use source address and port to update address/port table
      2) Is destination multicast?
         Yes:
            2a) Flood the packet
         No:
            2b) Port for destination address in our address/port table?
               No:
                 2ba) Flood the packet
              Yes:
                 2bb1) Install flow table entry in the switch so that this flow
                       goes out the appopriate port
                 2bb2) Send buffered packet out appopriate port
  
      Handles PacketIn messages from the switch to implement above algorithm.
      """
      def flood ():
        """ Floods the packet """
        # Should there be a layer below this to build this packet?
        # I guess I would have expected something like:
        # msg = of.ofp_packet_out(actions = [foo],  buffer_id = join_event.ofp.buffer_id, in_port = join_event.port)
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.buffer_id = packet_in_event.ofp.buffer_id
        msg.in_port = packet_in_event.port
        # Switch is a proxy to its underlying connection. Maybe should change?
        # alternative is: switch.connection.send(msg)
        # One downside of the alternative is that it enables the user to
        # store a reference to the connection object, which shouldn't happen!
        # (we want reconnects to be transparent)
        switch.send(msg)

      packet = packet_in_event.parse()
      switch.macToPort[packet.src] = packet_in_event.port # 1
      if packet.dst.isMulticast():
        flood() # 2a
      else:
        if packet.dst not in switch.macToPort:
          log.debug("port for %s unknown -- flooding" % (packet.dst,))
          flood() # 2ba
        else:
          # 2bb
          port = switch.macToPort[packet.dst]
          log.debug("installing flow for %s.%i -> %s.%i" %
                    (packet.src, packet_in_event.port, packet.dst, port))
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet)
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          msg.actions.append(of.ofp_action_output(port = port))
          msg.buffer_id = packet_in_event.ofp.buffer_id
          switch.send(msg)

    # Register the handler on the switch object
    # Note that this only works because the OpenFlowSwitch type inherits from join_eventMixin. 
    # If it were some other Switch subclass, this invocation might barf.
    switch.addListener(PacketIn, PacketIn_handler)
