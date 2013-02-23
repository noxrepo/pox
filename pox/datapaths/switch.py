# Copyright 2012,2013 Colin Scott
# Copyright 2012,2013 James McCauley
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
A software OpenFlow switch

Based partially on pylibopenflow:
Copyright(C) 2009, Stanford University
Date November 2009
Created by ykk
"""

from pox.lib.util import assert_type, initHelper, dpid_to_str
from pox.lib.revent import Event, EventMixin
from pox.openflow.libopenflow_01 import *
import pox.openflow.libopenflow_01 as of
from pox.openflow.util import make_type_to_unpacker_table
from pox.openflow.flow_table import SwitchFlowTable
from pox.lib.packet import *

import logging


class DpPacketOut (Event):
  """
  Event raised when a dataplane packet is sent out a port
  """
  def __init__ (self, node, packet, port):
    assert assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.node = node
    self.packet = packet
    self.port = port
    # For backwards compatability:
    self.switch = node


def _generate_ports (num_ports=4, prefix=0):
  return [ofp_phy_port(port_no=i, hw_addr=EthAddr("00:00:00:00:%2x:%2x"
          % (prefix % 255, i))) for i in range(1, num_ports+1)]


class SoftwareSwitch (EventMixin):
  _eventMixin_events = set([DpPacketOut])

  def __init__ (self, dpid, name=None, ports=4, miss_send_len=128,
                max_buffers=100, features=None):
    """
    Initialize switch
     - ports is a list of ofp_phy_ports
    """
    if name is None: name = dpid_to_str(dpid)
    self.name = name

    if isinstance(ports, int):
      ports = _generate_ports(num_ports=ports, prefix=dpid)

    self.dpid = dpid
    self.max_buffers = max_buffers
    self.miss_send_len = miss_send_len

    self.table = SwitchFlowTable()
    self.log = logging.getLogger(self.name)
    self.xid_count = xid_generator()
    self._connection = None

    # buffer for packets during packet_in
    self.packet_buffer = []

    # Map port_no -> openflow.pylibopenflow_01.ofp_phy_ports
    self.ports = {}
    self.port_stats = {}
    for port in ports:
      self.ports[port.port_no] = port
      self.port_stats[port.port_no] = ofp_port_stats(port_no=port.port_no)

    # set of port numbers that are currently down
    self.down_port_nos = set()

    if features is not None:
      self.features = features
    else:
      # Set up default features

      self.features = SwitchFeatures()
      self.features.flow_stats = True
      self.features.table_stats = True
      self.features.port_stats = True
      #self.features.stp = True
      #self.features.ip_reasm = True
      #self.features.queue_stats = True
      #self.features.arp_match_ip = True

      self.features.act_output = True
      #self.features.act_enqueue = True
      #self.features.act_strip_vlan = True
      self.features.act_set_vlan_vid = True
      self.features.act_set_vlan_pcp = True
      self.features.act_set_dl_dst = True
      self.features.act_set_dl_src = True
      self.features.act_set_nw_dst = True
      self.features.act_set_nw_src = True
      #self.features.act_set_nw_tos = True
      self.features.act_set_tp_dst = True
      self.features.act_set_tp_src = True
      #self.features.act_vendor = True

    # Set up handlers for incoming OpenFlow messages
    # That is, self.ofp_handlers[OFPT_FOO] = self._rx_foo
    self.ofp_handlers = {}
    for value,name in ofp_type_map.iteritems():
      name = name.split("OFPT_",1)[-1].lower()
      h = getattr(self, "_rx_" + name, None)
      if not h: continue
      assert of._message_type_to_class[value]._from_controller, name
      self.ofp_handlers[value] = h

  def rx_message (self, connection, msg):
    """
    Handle an incoming message
    """
    ofp_type = msg.header_type
    h = self.ofp_handlers.get(ofp_type)
    if h is None:
      raise RuntimeError("No handler for ofp_type %s(%d)"
                         % (ofp_type_map.get(ofp_type), ofp_type))

    h(msg, connection=connection)

  def set_connection (self, connection):
    """
    Set this switch's connection.
    """
    connection.set_message_handler(self.rx_message)
    self._connection = connection

  def send (self, message):
    """
    Send a message to this switch's communication partner

    If the switch is not connected, the message is silently dropped.
    """

    if self._connection:
      self._connection.send(message)
    else:
      self.log.debug("Asked to send message %s, but not connected", message)

  def _rx_hello (self, ofp, connection):
    self.log.debug("Receive hello %s", self.name)
    self.send_hello()

  def _rx_echo_request (self, ofp, connection):
    """
    Handles echo requests
    """
    self.log.debug("Reply echo of xid: %s %s", str(ofp), self.name)
    msg = ofp_echo_reply(xid=ofp.xid)
    self.send(msg)

  def _rx_features_request (self, ofp, connection):
    """
    Handles feature requests
    """
    self.log.debug("Reply features request of xid %s %s", str(ofp), self.name)
    msg = ofp_features_reply(datapath_id = self.dpid,
                             xid = ofp.xid,
                             n_buffers = self.max_buffers,
                             n_tables = 1,
                             capabilities = self.features.capability_bits,
                             actions = self.features.action_bits,
                             ports = self.ports.values())
    self.send(msg)

  def _rx_flow_mod (self, ofp, connection):
    """
    Handles flow mods
    """
    self.log.debug("Flow mod %s: %s", self.name, ofp.show())
    self.table.process_flow_mod(ofp)
    if(ofp.buffer_id > 0):
      self._process_actions_for_packet_from_buffer(ofp.actions, ofp.buffer_id)

  def _rx_packet_out (self, packet_out, connection):
    """
    Handles packet_outs
    """
    self.log.debug("Packet out: %s", packet_out.show())

    if(packet_out.data):
      self._process_actions_for_packet(packet_out.actions, packet_out.data,
                                       packet_out.in_port)
    elif(packet_out.buffer_id > 0):
      self._process_actions_for_packet_from_buffer(packet_out.actions,
                                                   packet_out.buffer_id)
    else:
      self.log.warn("packet_out: No data and no buffer_id -- "
                    "don't know what to send")

  def _rx_echo_reply (self, ofp, connection):
    self.log.debug("Echo reply: %s %s", str(ofp), self.name)

  def _rx_barrier_request (self, ofp, connection):
    self.log.debug("Barrier request %s %s", self.name, str(ofp))
    msg = ofp_barrier_reply(xid = ofp.xid)
    self.send(msg)

  def _rx_get_config_request (self, ofp, connection):
    self.log.debug("Get config request %s %s ", self.name, str(ofp))
    msg = ofp_get_config_reply(xid = ofp.xid)
    self.send(msg)

  def _rx_stats_request (self, ofp, connection):
    self.log.debug("Get stats request %s %s ", self.name, str(ofp))

    def desc_stats (ofp):
      return ofp_desc_stats(mfr_desc="POX",
                            hw_desc=core._get_platform_info(),
                            sw_desc=core.version_string,
                            serial_num=str(self.dpid),
                            dp_desc=type(self).__name__)

    def flow_stats (ofp):
      req = ofp_flow_stats_request().unpack(ofp.body)
      assert self.table_id == TABLE_ALL
      return self.table.flow_stats(req.match, req.out_port)

    def aggregate_stats (ofp):
      req = ofp_aggregate_stats_request().unpack(ofp.body)
      assert self.table_id == TABLE_ALL
      return self.table.aggregate_stats(req.match, out_port)

    def table_stats (ofp):
      return self.table.table_stats()

    def port_stats (ofp):
      req = ofp_port_stats_request().unpack(ofp.body)
      if req.port_no == OFPP_NONE:
        res = ofp_port_stats(port_no=OFPP_NONE)
        for stats in self.port_stats.values():
          res += stats
        return res
      else:
        return self.port_stats[req.port_no]

    def queue_stats (ofp):
      raise AttributeError("not implemented")

    stats_handlers = {
        OFPST_DESC: desc_stats,
        OFPST_FLOW: flow_stats,
        OFPST_AGGREGATE: aggregate_stats,
        OFPST_TABLE: table_stats,
        OFPST_PORT: port_stats,
        OFPST_QUEUE: queue_stats
    }

    if ofp.type in stats_handlers:
      handler = stats_handlers[ofp.type]
    else:
      raise AttributeError("Unsupported stats request type %d" % ofp.type)

    reply = ofp_stats_reply(xid=ofp.xid, body=handler(ofp))
    self.log.debug("Sending stats reply %s %s", self.name, str(reply))
    self.send(reply)

  def _rx_set_config (self, config, connection):
    self.log.debug("Set config %s %s", self.name, str(config))

  def _rx_port_mod (self, port_mod, connection):
    self.log.debug("Get port modification request %s %s", self.name,
                   str(port_mod))
    port_no = port_mod.port_no
    if port_no not in self.ports:
      err = ofp_error(type=OFPET_PORT_MOD_FAILED, code=OFPPMFC_BAD_PORT)
      self.send(err)
      return
    port = self.ports[port_no]
    if port.hw_addr != port_mod.hw_addr:
      err = ofp_error(type=OFPET_PORT_MOD_FAILED, code=OFPPMFC_BAD_HW_ADDR)
      self.send(err)
      return

    mask = port_mod.mask

    if mask & OFPPC_NO_FLOOD:
      mask ^= OFPPC_NO_FLOOD
      if port.set_config(port_mod.config, OFPPC_NO_FLOOD):
        if port.config & OFPPC_NO_FLOOD:
          self.log.debug("Disabling flooding on port %s", port)
        else:
          self.log.debug("Enabling flooding on port %s", port)

    if mask & OFPPC_PORT_DOWN:
      mask ^= OFPPC_PORT_DOWN
      change = port.set_config(port_mod.config, OFPPC_PORT_DOWN)
      # Note (Peter Peresini): Although the spec is not clear about it,
      # we will assume that config.OFPPC_PORT_DOWN implies
      # state.OFPPS_LINK_DOWN.  This is consistent with Open vSwitch.

      #TODO: for now, we assume that there is always physical link present
      #      and that the link state depends only on the configuration.
      old_state = port.state & OFPPS_LINK_DOWN
      port.state = port.state & ~OFPPS_LINK_DOWN
      if port.config & OFPPC_PORT_DOWN:
        port.state = port.state | OFPPS_LINK_DOWN
      new_state = port.state & OFPPS_LINK_DOWN
      if old_state != new_state:
        self.send_port_status(port, OFPPR_MODIFY)

    if mask != 0:
      self.log.warn("Unsupported PORT_MOD flags: %08x", mask)

  def _rx_vendor (self, vendor, connection):
    self.log.debug("Vendor %s %s", self.name, str(vendor))
    # We don't support vendor extensions, so send an OFP_ERROR, per
    # page 42 of spec
    err = ofp_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_VENDOR)
    self.send(err)

  def send_hello (self):
    """
    Send hello
    """
    self.log.debug("Send hello %s ", self.name)
    msg = ofp_hello()
    self.send(msg)

  def send_packet_in (self, in_port, buffer_id=None, packet=b'', xid=None,
                      reason=None, data_length=None):
    """
    Send PacketIn
    """
    if hasattr(packet, 'pack'):
      packet = packet.pack()
    assert assert_type("packet", packet, bytes)
    self.log.debug("Send PacketIn %s ", self.name)
    if reason is None:
      reason = OFPR_NO_MATCH
    if data_length is not None and len(packet) > data_length:
      if buffer_id is not None:
        packet = packet[:data_length]

    if xid == None:
      xid = self.xid_count()
    msg = ofp_packet_in(xid=xid, in_port = in_port, buffer_id = buffer_id,
                        reason = reason, data = packet)

    self.send(msg)

  def send_echo (self, xid=0):
    """
    Send echo request
    """
    self.log.debug("Send echo %s", self.name)
    msg = ofp_echo_request()
    self.send(msg)

  def send_port_status (self, port, reason):
    """
    Send port status

    port is an ofp_phy_port
    reason is one of OFPPR_xxx
    """
    assert assert_type("port", port, ofp_phy_port, none_ok=False)
    assert reason in ofp_port_reason_rev_map.values()
    msg = ofp_port_status(desc=port, reason=reason)
    self.send(msg)

  # ==================================== #
  #   Dataplane processing               #
  # ==================================== #

  def process_packet (self, packet, in_port):
    """
    process a dataplane packet

    packet: an instance of ethernet
    in_port: the integer port number
    """
    assert assert_type("packet", packet, ethernet, none_ok=False)
    assert assert_type("in_port", in_port, int, none_ok=False)

    entry = self.table.entry_for_packet(packet, in_port)
    if(entry != None):
      entry.touch_packet(len(packet))
      self._process_actions_for_packet(entry.actions, packet, in_port)
    else:
      # no matching entry
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count(),
                          reason=OFPR_NO_MATCH, data_length=self.miss_send_len)

  def take_port_down (self, port):
    """
    Take the given port down

    Sends a port_status message to the controller
    """
    port_no = port.port_no
    if port_no not in self.ports:
      raise RuntimeError("port_no %d not in %s's ports" % (port_no, str(self)))
    self.down_port_nos.add(port_no)
    self.send_port_status(port, OFPPR_DELETE)

  def bring_port_up (self, port):
    """
    Bring the given port up

    Sends a port_status message to the controller
    """
    port_no = port.port_no
    self.down_port_nos.discard(port_no)
    self.ports[port_no] = port
    self.send_port_status(port, OFPPR_ADD)

  # ==================================== #
  #    Helper Methods                    #
  # ==================================== #

  def _output_packet (self, packet, out_port, in_port, max_len=None):
    """
    send a packet out some port.

    packet: instance of ethernet
    out_port, in_port: the integer port number
    max_len: maximum packet payload length to send to controller
    """
    assert assert_type("packet", packet, ethernet, none_ok=False)

    def real_send (port_no, allow_in_port=False):
      if type(port_no) == ofp_phy_port:
        port_no = port_no.port_no
      # The OF spec states that packets should not be forwarded out their
      # in_port unless OFPP_IN_PORT is explicitly used.
      if port_no == in_port and not allow_in_port:
        self.log.warn("out_port %d == in_port. Dropping", out_port)
        return
      if port_no not in self.ports:
        raise RuntimeError("Invalid physical output port: %x" % port_no)
      if port_no in self.down_port_nos:
        #raise RuntimeError("output port %x currently down!" % port_no)
        self.log.warn("Port %d is currently down. Dropping packet", port_no)
      if self.ports[port_no].state & OFPPS_LINK_DOWN:
        self.log.debug("Sending packet on a port which is down!")
      else:
        self.raiseEvent(DpPacketOut(self, packet, self.ports[port_no]))

    if out_port < OFPP_MAX:
      real_send(out_port)
    elif out_port == OFPP_IN_PORT:
      real_send(in_port, allow_in_port=True)
    elif out_port == OFPP_FLOOD:
      for no,port in self.ports.iteritems():
        if no == in_port: continue
        if port.config & OFPPC_NO_FLOOD: continue
        real_send(port)
    elif out_port == OFPP_ALL:
      for no,port in self.ports.iteritems():
        if no == in_port: continue
        real_send(port)
    elif out_port == OFPP_CONTROLLER:
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count(),
                          reason=OFPR_ACTION, data_length=max_len)
    elif out_port == OFPP_TABLE:
      # There better be a table entry there, else we get infinite recurision
      # between switch<->controller
      # Note that this isn't infinite recursion, since the table entry's
      # out_port will not be OFPP_TABLE
      self.process_packet(packet, in_port)
    else:
      raise("Unsupported virtual output port: %x" % out_port)

  def _buffer_packet (self, packet, in_port=None):
    """
    Buffer packet and return buffer ID

    If no buffer is available, return None.
    """
    # Do we have an empty slot?
    for (i, value) in enumerate(self.packet_buffer):
      if value is None:
        # Yes -- use it
        self.packet_buffer[i] = (packet, in_port)
        return i + 1
    # No -- create a new slow
    if len(self.packet_buffer) >= self.max_buffers:
      # No buffers available!
      return None
    self.packet_buffer.append( (packet, in_port) )
    return len(self.packet_buffer)

  def _process_actions_for_packet_from_buffer (self, actions, buffer_id):
    """
    output and release a packet from the buffer
    """
    buffer_id = buffer_id - 1
    if(buffer_id >= len(self.packet_buffer)):
      self.log.warn("Invalid output buffer id: %x", buffer_id)
      return
    if(self.packet_buffer[buffer_id] is None):
      self.log.warn("Buffer %x has already been flushed", buffer_id)
      return
    (packet, in_port) = self.packet_buffer[buffer_id]
    self._process_actions_for_packet(actions, packet, in_port)
    self.packet_buffer[buffer_id] = None

  def _process_actions_for_packet (self, actions, packet, in_port):
    """
    process the output actions for a packet
    """
    assert assert_type("packet", packet, [ethernet, str], none_ok=False)
    if not isinstance(packet, ethernet):
      packet = ethernet.unpack(packet)

    def output_packet (action, packet):
      self._output_packet(packet, action.port, in_port, action.max_len)
      return packet
    def set_vlan_id (action, packet):
      if not isinstance(packet.next, vlan):
        packet.next = vlan(prev = packet.next)
        packet.next.eth_type = packet.type
        packet.type = ethernet.VLAN_TYPE
      packet.id = action.vlan_id
      return packet
    def set_vlan_pcp (action, packet):
      if not isinstance(packet.next, vlan):
        packet.next = vlan(prev = packet)
        packet.next.eth_type = packet.type
        packet.type = ethernet.VLAN_TYPE
      packet.pcp = action.vlan_pcp
      return packet
    def strip_vlan (action, packet):
      if isinstance(packet.next, vlan):
        packet.type = packet.next.eth_type
        packet.next = packet.next.next
      return packet
    def set_dl_src (action, packet):
      packet.src = action.dl_addr
      return packet
    def set_dl_dst (action, packet):
      packet.dst = action.dl_addr
      return packet
    def set_nw_src (action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.nw_src = action.nw_addr
      return packet
    def set_nw_dst (action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.nw_dst = action.nw_addr
      return packet
    def set_nw_tos (action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.tos = action.nw_tos
      return packet
    def set_tp_src (action, packet):
      if(isinstance(packet.next, udp) or isinstance(packet.next, tcp)):
        packet.next.srcport = action.tp_port
      return packet
    def set_tp_dst (action, packet):
      if(isinstance(packet.next, udp) or isinstance(packet.next, tcp)):
        packet.next.dstport = action.tp_port
      return packet
    def enqueue (action, packet):
      self.log.warn("Enqueue not supported.  Performing regular output.")
      return output_packet(action.tp_port, packet)
#    def push_mpls_tag (action, packet):
#      bottom_of_stack = isinstance(packet.next, mpls)
#      packet.next = mpls(prev = packet.pack())
#      if bottom_of_stack:
#        packet.next.s = 1
#      packet.type = action.ethertype
#      return packet
#    def pop_mpls_tag (action, packet):
#      if not isinstance(packet.next, mpls):
#        return packet
#      if not isinstance(packet.next.next, str):
#        packet.next.next = packet.next.next.pack()
#      if action.ethertype in ethernet.type_parsers:
#        packet.next = ethernet.type_parsers[action.ethertype](packet.next.next)
#      else:
#        packet.next = packet.next.next
#      packet.ethertype = action.ethertype
#      return packet
#    def set_mpls_label (action, packet):
#      if not isinstance(packet.next, mpls):
#        mock = ofp_action_push_mpls()
#        packet = push_mpls_tag(mock, packet)
#      packet.next.label = action.mpls_label
#      return packet
#    def set_mpls_tc (action, packet):
#      if not isinstance(packet.next, mpls):
#        mock = ofp_action_push_mpls()
#        packet = push_mpls_tag(mock, packet)
#      packet.next.tc = action.mpls_tc
#      return packet
#    def set_mpls_ttl (action, packet):
#      if not isinstance(packet.next, mpls):
#        mock = ofp_action_push_mpls()
#        packet = push_mpls_tag(mock, packet)
#      packet.next.ttl = action.mpls_ttl
#      return packet
#    def dec_mpls_ttl (action, packet):
#      if not isinstance(packet.next, mpls):
#        return packet
#      packet.next.ttl = packet.next.ttl - 1
#      return packet

    handler_map = {
        OFPAT_OUTPUT: output_packet,
        OFPAT_SET_VLAN_VID: set_vlan_id,
        OFPAT_SET_VLAN_PCP: set_vlan_pcp,
        OFPAT_STRIP_VLAN: strip_vlan,
        OFPAT_SET_DL_SRC: set_dl_src,
        OFPAT_SET_DL_DST: set_dl_dst,
        OFPAT_SET_NW_SRC: set_nw_src,
        OFPAT_SET_NW_DST: set_nw_dst,
        OFPAT_SET_NW_TOS: set_nw_tos,
        OFPAT_SET_TP_SRC: set_tp_src,
        OFPAT_SET_TP_DST: set_tp_dst,
        OFPAT_ENQUEUE: enqueue,
#        OFPAT_PUSH_MPLS: push_mpls_tag,
#        OFPAT_POP_MPLS: pop_mpls_tag,
#        OFPAT_SET_MPLS_LABEL: set_mpls_label,
#        OFPAT_SET_MPLS_TC: set_mpls_tc,
#        OFPAT_SET_MPLS_TTL: set_mpls_ttl,
#        OFPAT_DEC_MPLS_TTL: dec_mpls_ttl,
    }
    for action in actions:
#      if action.type is ofp_action_resubmit:
#        self.process_packet(packet, in_port)
#        return
      if(action.type not in handler_map):
        raise NotImplementedError("Unknown action type: %x " % type)
      packet = handler_map[action.type](action, packet)

  def __repr__ (self):
    return "%s(dpid=%s, num_ports=%d)" % (type(self).__name__,
                                          dpid_to_str(self.dpid),
                                          len(self.ports))


class OFConnection (object):
  """
  A codec for OpenFlow messages.

  Decodes and encodes OpenFlow messages (ofp_message) into byte arrays.

  Wraps an io_worker that does the actual io work, and calls a
  receiver_callback function when a new message as arrived.
  """

  # Unlike of_01.Connection, this is persistent (at least until we implement
  # a proper recoco Connection Listener loop)
  # Globally unique identifier for the Connection instance
  ID = 0

  # These methods are called externally by IOWorker
  def msg (self, m):
    self.log.debug("%s %s", str(self), str(m))
  def err (self, m):
    self.log.error("%s %s", str(self), str(m))
  def info (self, m):
    self.log.info("%s %s", str(self), str(m))

  def __init__ (self, io_worker):
    self.io_worker = io_worker
    self.io_worker.rx_handler = self.read
    self.controller_id = io_worker.socket.getpeername()
    self.error_handler = None
    OFConnection.ID += 1
    self.ID = OFConnection.ID
    self.log = logging.getLogger("ControllerConnection(id=%d)" % (self.ID,))
    self.unpackers = make_type_to_unpacker_table()

    self.on_message_received = None

  def set_message_handler (self, handler):
    self.on_message_received = handler

  def send (self, data):
    """
    Send raw data to the controller.

    Generally, data is a bytes object. If not, we check if it has a pack()
    method and call it (hoping the result will be a bytes object).  This
    way, you can just pass one of the OpenFlow objects from the OpenFlow
    library to it and get the expected result, for example.
    """
    if type(data) is not bytes:
      if hasattr(data, 'pack'):
        data = data.pack()
    self.io_worker.send(data)

  def read (self, io_worker):
    while True:
      message = io_worker.peek()
      if len(message) < 4:
        break

      if ord(message[0]) != OFP_VERSION:
        e = ValueError("Bad OpenFlow version (%s) on connection %s",
                       ord(message[0]), str(self))
        if self.error_handler:
          return self.error_handler(e)
        else:
          raise e

      # OpenFlow parsing occurs here:
      ofp_type = ord(message[1])
      packet_length = ord(message[2]) << 8 | ord(message[3])
      if packet_length > len(message):
        break

      # msg.unpack implicitly only examines its own bytes, and not trailing
      # bytes
      new_offset, msg_obj = self.unpackers[ofp_type](message, 0)
      assert new_offset == packet_length

      io_worker.consume_receive_buf(packet_length)

      # note: on_message_received is just a function, not a method
      if self.on_message_received is None:
        raise RuntimeError("on_message_receieved hasn't been set yet!")

      try:
        self.on_message_received(self, msg_obj)
      except Exception as e:
        if self.error_handler:
          return self.error_handler(e)
        else:
          raise e

    return True

  def close (self):
    self.io_worker.close()

  def get_controller_id (self):
    """
    Return a tuple of the controller's (address, port) we are connected to
    """
    return self.controller_id

  def __str__ (self):
    return "[Con " + str(self.ID) + "]"


class SwitchFeatures (object):
  """
  Stores switch features

  Keeps settings for switch capabilities and supported actions.
  Automatically has attributes of the form ".act_foo" for all OFPAT_FOO,
  and ".cap_foo" for all OFPC_FOO (as gathered from libopenflow).
  """
  def __init__ (self, **kw):
    self._cap_info = {}
    for val,name in ofp_capabilities_map.iteritems():
      name = name[5:].lower() # strip OFPC_
      name = "cap_" + name
      setattr(self, name, False)
      self._cap_info[name] = val

    self._act_info = {}
    for val,name in ofp_action_type_map.iteritems():
      name = name[6:].lower() # strip OFPAT_
      name = "act_" + name
      setattr(self, name, False)
      self._act_info[name] = val

    initHelper(self, kw)

  @property
  def capability_bits (self):
    """
    Value used in features reply
    """
    return sum( (v if getattr(self, k) else 0)
                for k,v in self._cap_info.iteritems() )

  @property
  def action_bits (self):
    """
    Value used in features reply
    """
    return sum( (v if getattr(self, k) else 0)
                for k,v in self._act_info.iteritems() )

  def __str__ (self):
    l = list(k for k in self._cap_info if getattr(self, k))
    l += list(k for k in self._act_info if getattr(self, k))
    return ",".join(l)
