from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent.revent import *

log = core.getLogger()

class LearningSwitch (EventMixin):
  def __init__ (self, connection):
    self.connection = connection
    self.macToPort = {}

    self.listenTo(connection)

  def _handle_PacketIn (self, event):
    def flood ():
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    packet = event.parse()
    self.macToPort[packet.src] = event.port
    if packet.dst.isMulticast():
      flood()
    else:
      if packet.dst not in self.macToPort:
        log.debug("port for %s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        port = self.macToPort[packet.dst]
        log.debug("installing flow for %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)


class dumb_l2_switch (EventMixin):
  def __init__ (self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)

