# Copyright 2012 Colin Scott
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
Software OpenFlow Switch

Based heavily on pylibopenflow:

Copyright(C) 2009, Stanford University
Date November 2009
Created by ykk
"""
# TODO: Don't have SoftwareSwitch take a socket object... Should really have a
# OF_01 like task that listens for socket connections, creates a new socket,
# wraps it in a OFConnection object, and calls SoftwareSwitch._handle_ConnectionUp

from pox.lib.util import assert_type
from pox.lib.revent import Event, EventMixin
from pox.openflow.libopenflow_01 import *
from pox.openflow.util import make_type_to_unpacker_table
from pox.openflow.flow_table import SwitchFlowTable
from pox.lib.packet import *

from errno import EAGAIN
from collections import namedtuple
import inspect
import itertools
import logging


class DpPacketOut (Event):
  """ Event raised when a dataplane packet is sent out a port """
  def __init__ (self, node, packet, port):
    assert_type("packet", packet, ethernet, none_ok=False)
    Event.__init__(self)
    self.node = node
    self.packet = packet
    self.port = port
    # For backwards compatability:
    self.switch = node


def _default_port_list(num_ports=4, prefix=0):
  return [ofp_phy_port(port_no=i, hw_addr=EthAddr("00:00:00:00:%2x:%2x" % (prefix % 255, i))) for i in range(1, num_ports+1)]


class SoftwareSwitch(EventMixin):
  _eventMixin_events = set([DpPacketOut])

  def __init__(self, dpid, name=None, ports=4,
               miss_send_len=128, n_buffers=100, n_tables=1, capabilities=None):
    '''
    Initialize switch
     - ports is a list of ofp_phy_ports
    '''
    ##Datapath id of switch
    self.dpid = dpid
    ## Human-readable name of the switch
    self.name = name
    if self.name is None:
      self.name = str(dpid)
    self.log = logging.getLogger(self.name)
    ##Number of buffers
    self.n_buffers = n_buffers
    ##Number of tables
    self.n_tables= n_tables
    # Note that there is one switch table in the OpenFlow 1.0 world
    self.table = SwitchFlowTable()
    # buffer for packets during packet_in
    self.packet_buffer = []
    if(ports == None or isinstance(ports, int)):
      ports=_default_port_list(num_ports=ports, prefix=dpid)

    self.xid_count = xid_generator(1)

    ## Hash of port_no -> openflow.pylibopenflow_01.ofp_phy_ports
    self.ports = {}
    self.port_stats = {}
    for port in ports:
      self.ports[port.port_no] = port
      self.port_stats[port.port_no] = ofp_port_stats(port_no=port.port_no)

    # set of port numbers that are currently down
    self.down_port_nos = set()
    self.no_flood_ports = set()

    ## (OpenFlow Handler map)
    self.ofp_handlers = {
       # Reactive handlers
       ofp_type_rev_map['OFPT_HELLO'] : self._receive_hello,
       ofp_type_rev_map['OFPT_ECHO_REQUEST'] : self._receive_echo,
       ofp_type_rev_map['OFPT_FEATURES_REQUEST'] : self._receive_features_request,
       ofp_type_rev_map['OFPT_FLOW_MOD'] : self._receive_flow_mod,
       ofp_type_rev_map['OFPT_PACKET_OUT'] : self._receive_packet_out,
       ofp_type_rev_map['OFPT_BARRIER_REQUEST'] : self._receive_barrier_request,
       ofp_type_rev_map['OFPT_GET_CONFIG_REQUEST'] : self._receive_get_config_request,
       ofp_type_rev_map['OFPT_SET_CONFIG'] : self._receive_set_config,
       ofp_type_rev_map['OFPT_STATS_REQUEST'] : self._receive_stats_request,
       ofp_type_rev_map['OFPT_VENDOR'] : self._receive_vendor,
       ofp_type_rev_map['OFPT_PORT_MOD'] : self._receive_port_mod,
       # Proactive responses
       ofp_type_rev_map['OFPT_ECHO_REPLY'] : self._receive_echo_reply
       # TODO: many more packet types to process
    }

    self._connection = None

    ##Capabilities
    if (isinstance(capabilities, SwitchCapabilities)):
      self.capabilities = capabilities
    else:
      self.capabilities = SwitchCapabilities(miss_send_len)

  def on_message_received(self, connection, msg):
    ofp_type = msg.header_type
    if ofp_type not in self.ofp_handlers:
      raise RuntimeError("No handler for ofp_type %s(%d)" % (ofp_type_map.get(ofp_type), ofp_type))
    h = self.ofp_handlers[ofp_type]

    # figure out wether the handler supports the 'connection' argument, if so attach it
    # (handlers for NX extended switches sometimes need to know which connection a
    # particular message was received on)
    argspec = inspect.getargspec(h)
    if "connection" in argspec.args or argspec.keywords:
      h(msg, connection=connection)
    else:
      h(msg)

  def set_connection(self, connection):
    '''
    Set this switch's connection.
    '''
    connection.set_message_handler(self.on_message_received)
    self._connection = connection

  def send(self, message):
    """ Send a message to this switches communication partner. If the switch is not connected, the message is silently dropped. """

    if self._connection:
      self._connection.send(message)
    else:
      self.log.debug("Asked to send message %s, but not connected", message)

  # ==================================== #
  #    Reactive OFP processing           #
  # ==================================== #
  def _receive_hello(self, ofp):
    self.log.debug("Receive hello %s", self.name)
    # How does the OpenFlow protocol prevent an infinite loop of Hello messages?
    self.send_hello()

  def _receive_echo(self, ofp):
    """Reply to echo request
    """
    self.log.debug("Reply echo of xid: %s %s", str(ofp), self.name)
    msg = ofp_echo_reply(xid=ofp.xid)
    self.send(msg)

  def _receive_features_request(self, ofp):
    """Reply to feature request
    """
    self.log.debug("Reply features request of xid %s %s", str(ofp), self.name)
    msg = ofp_features_reply(datapath_id = self.dpid, xid = ofp.xid, n_buffers = self.n_buffers,
                             n_tables = self.n_tables,
                             capabilities = self.capabilities.get_capabilities(),
                             actions = self.capabilities.get_actions(),
                             ports = self.ports.values())
    self.send(msg)

  def _receive_flow_mod(self, ofp):
    """Handle flow mod: just print it here
    """
    self.log.debug("Flow mod %s: %s", self.name, ofp.show())
    self.table.process_flow_mod(ofp)
    if(ofp.buffer_id > 0):
      self._process_actions_for_packet_from_buffer(ofp.actions, ofp.buffer_id)

  def _receive_packet_out(self, packet_out):
    """
    Send the packet out the given port
    """
    self.log.debug("Packet out: %s", packet_out.show())

    if(packet_out.data):
      self._process_actions_for_packet(packet_out.actions, packet_out.data, packet_out.in_port)
    elif(packet_out.buffer_id > 0):
      self._process_actions_for_packet_from_buffer(packet_out.actions, packet_out.buffer_id)
    else:
      self.log.warn("packet_out: No data and no buffer_id -- don't know what to send")

  def _receive_echo_reply(self, ofp):
    self.log.debug("Echo reply: %s %s", str(ofp), self.name)

  def _receive_barrier_request(self, ofp):
    self.log.debug("Barrier request %s %s", self.name, str(ofp))
    msg = ofp_barrier_reply(xid = ofp.xid)
    self.send(msg)

  def _receive_get_config_request(self, ofp):
    self.log.debug("Get config request %s %s ", self.name, str(ofp))
    msg = ofp_get_config_reply(xid = ofp.xid)
    self.send(msg)

  def _receive_stats_request(self, ofp):
    self.log.debug("Get stats request %s %s ", self.name, str(ofp))

    def desc_stats(ofp):
      return ofp_desc_stats(mfr_desc="BadAssEmulatedPoxSwitch(TM)",
                            hw_desc="your finest emulated asics",
                            sw_desc="pox. reliable, fast, stable. Choose 0 (or more?)",
                            serial_num=str(self.dpid),
                            dp_desc="high performance emuswitch. Several packets per second have been observed (but not by reliable witnesses)")

    def flow_stats(ofp):
      req = ofp_flow_stats_request().unpack(ofp.body)
      assert(self.table_id == TABLE_ALL)
      return self.table.flow_stats(req.match, req.out_port)

    def aggregate_stats(ofp):
      req = ofp_aggregate_stats_request().unpack(ofp.body)
      assert(self.table_id == TABLE_ALL)
      return self.table.aggregate_stats(req.match, out_port)

    def table_stats(ofp):
      return self.table.table_stats()

    def port_stats(ofp):
      req = ofp_port_stats_request().unpack(ofp.body)
      if req.port_no == OFPP_NONE:
        res = ofp_port_stats(port_no=OFPP_NONE)
        for stats in self.port_stats.values():
          res += stats
        return res
      else:
        return self.port_stats[req.port_no]

    def queue_stats(ofp):
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

  def _receive_set_config(self, config):
    self.log.debug("Set config %s %s", self.name, str(config))

  def _receive_port_mod(self, port_mod):
    self.log.debug("Get port modification request %s %s", self.name, str(port_mod))
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
      port.config = (port.config & ~OFPPC_NO_FLOOD) | (port_mod.config & OFPPC_NO_FLOOD)
      #TODO: Make sure .config syncs with no_flood_ports, or generate that .config
      #      at query time based on no_flood_ports
      if port.config & OFPPC_NO_FLOOD:
        self.log.debug("Disabling flooding on port %s", port)
        self.no_flood_ports.add(port)
      else:
        self.log.debug("Enabling flooding on port %s", port)
        self.no_flood_ports.discard(port)

    if mask & OFPPC_PORT_DOWN:
      mask ^= OFPPC_PORT_DOWN
      port.config = (port.config & ~OFPPC_PORT_DOWN) | (port_mod.config & OFPPC_PORT_DOWN)
      # Note (Peter Peresini): Although the spec is not clear about it,
      # we will assume that config.OFPPC_PORT_DOWN implies state.OFPPS_LINK_DOWN.
      # This is consistent with Open vSwitch.

      # FIXME: for now, we assume that there is always physical link present
      # and that the link state depends only on the configuration.
      old_state = port.state & OFPPS_LINK_DOWN
      port.state = port.state & ~OFPPS_LINK_DOWN
      if port.config & OFPPC_PORT_DOWN:
        port.state = port.state | OFPPS_LINK_DOWN
      new_state = port.state & OFPPS_LINK_DOWN
      if old_state != new_state:
        self.send_port_status(port, OFPPR_MODIFY)

    if mask != 0:
      self.log.warn("Unsupported PORT_MOD flags: %08x", mask)

  def _receive_vendor(self, vendor):
    self.log.debug("Vendor %s %s", self.name, str(vendor))
    # We don't support vendor extensions, so send an OFP_ERROR, per page 42 of spec
    err = ofp_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_VENDOR)
    self.send(err)

  # ==================================== #
  #    Proactive OFP processing          #
  # ==================================== #
  def send_hello(self):
    """Send hello
    """
    self.log.debug("Send hello %s ", self.name)
    msg = ofp_hello()
    self.send(msg)

  def send_packet_in(self, in_port, buffer_id=None, packet="", xid=None, reason=None):
    """Send PacketIn
    Assume no match as reason, buffer_id = 0xFFFFFFFF,
    and empty packet by default
    """
    assert_type("packet", packet, ethernet)
    self.log.debug("Send PacketIn %s ", self.name)
    if (reason == None):
      reason = ofp_packet_in_reason_rev_map['OFPR_NO_MATCH']
    if (buffer_id == None):
      buffer_id = int("0xFFFFFFFF",16)

    if xid == None:
      xid = self.xid_count()
    msg = ofp_packet_in(xid=xid, in_port = in_port, buffer_id = buffer_id, reason = reason,
                        data = packet.pack())

    self.send(msg)

  def send_echo(self, xid=0):
    """Send echo request
    """
    self.log.debug("Send echo %s", self.name)
    msg = ofp_echo_request()
    self.send(msg)

  def send_port_status(self, port, reason):
    '''
    port is an ofp_phy_port
    reason is one of 'OFPPR_ADD', 'OFPPR_DELETE', 'OFPPR_MODIFY'
    '''
    assert_type("port", port, ofp_phy_port, none_ok=False)
    assert(reason in ofp_port_reason_rev_map.values())
    msg = ofp_port_status(desc=port, reason=reason)
    self.send(msg)

  # ==================================== #
  #   Dataplane processing               #
  # ==================================== #

  def process_packet(self, packet, in_port):
    """ process a dataplane packet the way a real OpenFlow switch would.
        packet: an instance of ethernet
        in_port: the integer port number
    """
    assert_type("packet", packet, ethernet, none_ok=False)
    assert_type("in_port", in_port, int, none_ok=False)

    entry = self.table.entry_for_packet(packet, in_port)
    if(entry != None):
      entry.touch_packet(len(packet))
      self._process_actions_for_packet(entry.actions, packet, in_port)
    else:
      # no matching entry
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count(), reason=OFPR_NO_MATCH)

  def take_port_down(self, port):
    ''' Take the given port down, and send a port_status message to the controller '''
    port_no = port.port_no
    if port_no not in self.ports:
      raise RuntimeError("port_no %d not in %s's ports" % (port_no, str(self)))
    self.down_port_nos.add(port_no)
    self.send_port_status(port, OFPPR_DELETE)

  def bring_port_up(self, port):
    ''' Bring the given port up, and send a port_status message to the controller '''
    port_no = port.port_no
    self.down_port_nos.discard(port_no)
    self.ports[port_no] = port
    self.send_port_status(port, OFPPR_ADD)

  # ==================================== #
  #    Helper Methods                    #
  # ==================================== #

  def _output_packet(self, packet, out_port, in_port):
    """ send a packet out some port.
        packet: instance of ethernet
        out_port, in_port: the integer port number """
    assert_type("packet", packet, ethernet, none_ok=False)
    def real_send(port_no, allow_in_port=False):
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
    elif out_port == OFPP_FLOOD or out_port == OFPP_ALL:
      # no support for spanning tree yet -> flood=all
      for (no,port) in self.ports.iteritems():
        if no != in_port and port not in self.no_flood_ports:
          real_send(port)
    elif out_port == OFPP_CONTROLLER:
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count(), reason=OFPR_ACTION)
    elif out_port == OFPP_TABLE:
      # There better be a table entry there, else we get infinite recurision
      # between switch<->controller
      # Note that this isn't infinite recursion, since the table entry's
      # out_port will not be OFPP_TABLE
      self.process_packet(packet, in_port)
    else:
      raise("Unsupported virtual output port: %x" % out_port)

  def _buffer_packet(self, packet, in_port=None):
    """ Find a free buffer slot to buffer the packet in. """
    for (i, value) in enumerate(self.packet_buffer):
      if(value==None):
        self.packet_buffer[i] = (packet, in_port)
        return i + 1
    self.packet_buffer.append( (packet, in_port) )
    return len(self.packet_buffer)

  def _process_actions_for_packet_from_buffer(self, actions, buffer_id):
    """ output and release a packet from the buffer """
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

  def _process_actions_for_packet(self, actions, packet, in_port):
    """ process the output actions for a packet """
    assert_type("packet", packet, [ethernet, str], none_ok=False)
    if not isinstance(packet, ethernet):
      packet = ethernet.unpack(packet)

    def output_packet(action, packet):
      self._output_packet(packet, action.port, in_port)
      return packet
    def set_vlan_id(action, packet):
      if not isinstance(packet.next, vlan):
        packet.next = vlan(prev = packet.next)
        packet.next.eth_type = packet.type
        packet.type = ethernet.VLAN_TYPE
      packet.id = action.vlan_id
      return packet
    def set_vlan_pcp(action, packet):
      if not isinstance(packet.next, vlan):
        packet.next = vlan(prev = packet)
        packet.next.eth_type = packet.type
        packet.type = ethernet.VLAN_TYPE
      packet.pcp = action.vlan_pcp
      return packet
    def strip_vlan(action, packet):
      if isinstance(packet.next, vlan):
        packet.type = packet.next.eth_type
        packet.next = packet.next.next
      return packet
    def set_dl_src(action, packet):
      packet.src = action.dl_addr
      return packet
    def set_dl_dst(action, packet):
      packet.dst = action.dl_addr
      return packet
    def set_nw_src(action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.nw_src = action.nw_addr
      return packet
    def set_nw_dst(action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.nw_dst = action.nw_addr
      return packet
    def set_nw_tos(action, packet):
      if(isinstance(packet.next, ipv4)):
        packet.next.tos = action.nw_tos
      return packet
    def set_tp_src(action, packet):
      if(isinstance(packet.next, udp) or isinstance(packet.next, tcp)):
        packet.next.srcport = action.tp_port
      return packet
    def set_tp_dst(action, packet):
      if(isinstance(packet.next, udp) or isinstance(packet.next, tcp)):
        packet.next.dstport = action.tp_port
      return packet
    def enqueue(action, packet):
      self.log.warn("output_enqueue not supported yet. Performing regular output")
      return output_packet(action.tp_port, packet)
#    def push_mpls_tag(action, packet):
#      bottom_of_stack = isinstance(packet.next, mpls)
#      packet.next = mpls(prev = packet.pack())
#      if bottom_of_stack:
#        packet.next.s = 1
#      packet.type = action.ethertype
#      return packet
#    def pop_mpls_tag(action, packet):
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
#    def set_mpls_label(action, packet):
#      if not isinstance(packet.next, mpls):
#        mock = ofp_action_push_mpls()
#        packet = push_mpls_tag(mock, packet)
#      packet.next.label = action.mpls_label
#      return packet
#    def set_mpls_tc(action, packet):
#      if not isinstance(packet.next, mpls):
#        mock = ofp_action_push_mpls()
#        packet = push_mpls_tag(mock, packet)
#      packet.next.tc = action.mpls_tc
#      return packet
#    def set_mpls_ttl(action, packet):
#      if not isinstance(packet.next, mpls):
#        mock = ofp_action_push_mpls()
#        packet = push_mpls_tag(mock, packet)
#      packet.next.ttl = action.mpls_ttl
#      return packet
#    def dec_mpls_ttl(action, packet):
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

  def __repr__(self):
    return "SoftwareSwitch(dpid=%d, num_ports=%d)" % (self.dpid, len(self.ports))


class OFConnection (object):
  """ A codec for OpenFlow messages. Decodes and encodes OpenFlow messages (ofp_message)
      into byte arrays.

      Wraps an io_worker that does the actual io work, and calls a receiver_callbac
      function when a new message as arrived.
  """

  # Unlike of_01.Connection, this is persistent (at least until we implement a proper
  # recoco Connection Listener loop)
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

  def set_message_handler(self, handler):
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
        e = ValueError("Bad OpenFlow version (%s) on connection %s", ord(message[0]), str(self))
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

  def close(self):
    self.io_worker.close()

  def get_controller_id(self):
    ''' Return a tuple of the controller's (address, port) we are connected to'''
    return self.controller_id

  def __str__ (self):
    return "[Con " + str(self.ID) + "]"


class SwitchCapabilities:
  """
  Class to hold switch capabilities
  """
  def __init__(self, miss_send_len=128):
    """Initialize

    Copyright(C) 2009, Stanford University
    Date October 2009
    Created by ykk
    """
    ##Capabilities support by datapath
    self.flow_stats = False
    self.table_stats = False
    self.port_stats = False
    self.stp = False
    self.multi_phy_tx = False
    self.ip_resam = False
    ##Switch config
    self.send_exp = None
    self.ip_frag = 0
    self.miss_send_len = miss_send_len
    ##Valid actions
    self.act_output = True
    self.act_set_vlan_vid = True
    self.act_set_vlan_pcp = True
    self.act_strip_vlan = True
    self.act_set_dl_src = True
    self.act_set_dl_dst = True
    self.act_set_nw_src = True
    self.act_set_nw_dst = True
    self.act_set_tp_src = True
    self.act_set_tp_dst = True
    self.act_vendor = False

  def get_capabilities(self):
    """Return value for uint32_t capability field
    """
    value = 0
    if (self.flow_stats):
      value += ofp_capabilities_rev_map['OFPC_FLOW_STATS']
    if (self.table_stats):
      value += ofp_capabilities_rev_map['OFPC_TABLE_STATS']
    if (self.port_stats):
      value += ofp_capabilities_rev_map['OFPC_PORT_STATS']
    if (self.stp):
      value += ofp_capabilities_rev_map['OFPC_STP']
    if (self.multi_phy_tx):
      value += ofp_capabilities_rev_map['OFPC_MULTI_PHY_TX']
    if (self.ip_resam):
      value += ofp_capabilities_rev_map['OFPC_IP_REASM']
    return value

  def get_actions(self):
    """Return value for uint32_t action field
    """
    value = 0
    if (self.act_output):
      value += (1 << (ofp_action_type_rev_map['OFPAT_OUTPUT']+1))
    if (self.act_set_vlan_vid):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_VLAN_VID']+1))
    if (self.act_set_vlan_pcp):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_VLAN_PCP']+1))
    if (self.act_strip_vlan):
      value += (1 << (ofp_action_type_rev_map['OFPAT_STRIP_VLAN']+1))
    if (self.act_set_dl_src):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_DL_SRC']+1))
    if (self.act_set_dl_dst):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_DL_DST']+1))
    if (self.act_set_nw_src):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_NW_SRC']+1))
    if (self.act_set_nw_dst):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_NW_DST']+1))
    if (self.act_set_tp_src):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_TP_SRC']+1))
    if (self.act_set_tp_dst):
      value += (1 << (ofp_action_type_rev_map['OFPAT_SET_TP_DST']+1))
    return value
