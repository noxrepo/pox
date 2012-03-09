
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow import PacketIn
from pox.topology.topology import Switch, Entity
from pox.lib.revent import EventMixin

import pickle

# Note that control applications are /stateless/; they are simply a function:
#    f(view) -> configuration
#
# The view is encapsulated in the NOM, and the configuration results from manipulating
# NOM entities.
#
# To ensure statelesness (order-independence), the application must never instantiate its own
# objects. Instead, it must "fold in" any needed state into the NOM. The platform itself is in
# charge of managing the NOM.
#
# To "fold in" state, the application must declare a user-defined NOM entity. The entities
# encapsulate:
#   i.    State (e.g., self.mac2port = {})
#   ii.   Behavior (i.e. event handlers, such as def _handle_PacketIn() below)
#
# This is an example of a user-defined NOM entity.
class LearningSwitch (EventMixin, Entity):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will eventually
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
                   goes out the appropriate port
             2bb2) Send buffered packet out appropriate port
  """
  def __init__ (self, name, switch=None, macToPort={}):
    """
    Initialize the NOM Wrapper for Switch Entities

    switch - the NOM switch entity to wrap
    """
    # TODO: don't force user to inherit from Entity. We need this for Entity.ID.
    # The long-term solution would be to create a second NOM layer for user-defined
    # entities.
    Entity.__init__(self)
    self.name = name
    self.switch = switch
    self.log = core.getLogger(name)

    # We define our own state
    self.macToPort = macToPort

    if isinstance(switch, Entity):
      # We also define our behavior by registering an event handler (_handle_PacketIn)
      self.listenTo(switch)

  def _handle_PacketIn (self, packet_in_event):
    """ Event handler for PacketIn events: run the learning switch algorithm """
    self.log.debug("PacketIn_handler! packet_in_event: %s" % (str(packet_in_event)))

    def flood ():
      """ Floods the packet """
      # TODO: there should really be a static method in pox.openflow that constructs this
      # this packet for us.
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = packet_in_event.ofp.buffer_id
      msg.in_port = packet_in_event.port
      self.switch.send(msg)

    packet = packet_in_event.parse()
    self.macToPort[packet.src] = packet_in_event.port # 1
    if packet.dst.isMulticast():
      flood() # 2a
    else:
      if packet.dst not in self.macToPort:
        self.log.debug("port for %s unknown -- flooding" % (packet.dst,))
        flood() # 2ba
      else:
        # 2bb
        port = self.macToPort[packet.dst]
        self.log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, packet_in_event.port, packet.dst, port))
        # TODO: there should really be a static method in pox.openflow that constructs this
        # this packet for us.
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.buffer_id = packet_in_event.ofp.buffer_id
        self.switch.send(msg)

  def serialize(self):
    # TODO: this is a hack... need a better way of differntiating IDs (remote case) from raw objects (local case)
    if isinstance(self.switch, Entity):
      switch_id = self.switch.id
    else:
      switch_id = self.switch

    serializable = LearningSwitch(self.name, switch_id)
    serializable.log = None
    return pickle.dumps(serializable, protocol = 0)
