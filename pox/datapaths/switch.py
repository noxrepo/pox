# Copyright 2012,2013 Colin Scott
# Copyright 2012,2013 James McCauley
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
A software OpenFlow switch
"""

"""
TODO
----
* Don't reply to HELLOs -- just send one on connect
* Pass raw OFP packet to rx handlers as well as parsed
* Once previous is done, use raw OFP for error data when appropriate
* Check self.features to see if various features/actions are enabled,
  and act appropriately if they're not (rather than just doing them).
* Virtual ports currently have no config/state, but probably should.
* Provide a way to rebuild, e.g., the action handler table when the
  features object is adjusted.
"""


from pox.lib.util import assert_type, initHelper, dpid_to_str
from pox.lib.revent import Event, EventMixin
from pox.lib.recoco import Timer
from pox.openflow.libopenflow_01 import *
import pox.openflow.libopenflow_01 as of
from pox.openflow.util import make_type_to_unpacker_table
from pox.openflow.flow_table import FlowTable, TableEntry
from pox.lib.packet import *

import logging
import struct
import time


# Multicast address used for STP 802.1D
_STP_MAC = EthAddr('01:80:c2:00:00:00')


class DpPacketOut (Event):
  """
  Event raised when a dataplane packet is sent out a port
  """
  def __init__ (self, node, packet, port):
    assert assert_type("packet", packet, ethernet, none_ok=False)
    self.node = node
    self.packet = packet
    self.port = port
    self.switch = node # For backwards compatability


class SoftwareSwitchBase (object):
  def __init__ (self, dpid, name=None, ports=4, miss_send_len=128,
                max_buffers=100, max_entries=0x7fFFffFF, features=None):
    """
    Initialize switch
     - ports is a list of ofp_phy_ports or a number of ports
     - miss_send_len is number of bytes to send to controller on table miss
     - max_buffers is number of buffered packets to store
     - max_entries is max flows entries per table
    """
    if name is None: name = dpid_to_str(dpid)
    self.name = name

    self.dpid = dpid

    if isinstance(ports, int):
      ports = [self.generate_port(i) for i in range(1, ports+1)]

    self.max_buffers = max_buffers
    self.max_entries = max_entries
    self.miss_send_len = miss_send_len
    self.config_flags = 0
    self._has_sent_hello = False

    self.table = FlowTable()
    self.table.addListeners(self)

    self._lookup_count = 0
    self._matched_count = 0

    self.log = logging.getLogger(self.name)
    self._connection = None

    # buffer for packets during packet_in
    self._packet_buffer = []

    # Map port_no -> openflow.pylibopenflow_01.ofp_phy_ports
    self.ports = {}
    self.port_stats = {}

    for port in ports:
      self.add_port(port)

    if features is not None:
      self.features = features
    else:
      # Set up default features

      self.features = SwitchFeatures()
      self.features.cap_flow_stats = True
      self.features.cap_table_stats = True
      self.features.cap_port_stats = True
      #self.features.cap_stp = True
      #self.features.cap_ip_reasm = True
      #self.features.cap_queue_stats = True
      #self.features.cap_arp_match_ip = True

      self.features.act_output = True
      self.features.act_enqueue = True
      self.features.act_strip_vlan = True
      self.features.act_set_vlan_vid = True
      self.features.act_set_vlan_pcp = True
      self.features.act_set_dl_dst = True
      self.features.act_set_dl_src = True
      self.features.act_set_nw_dst = True
      self.features.act_set_nw_src = True
      self.features.act_set_nw_tos = True
      self.features.act_set_tp_dst = True
      self.features.act_set_tp_src = True
      #self.features.act_vendor = True

    # Set up handlers for incoming OpenFlow messages
    # That is, self.ofp_handlers[OFPT_FOO] = self._rx_foo
    self.ofp_handlers = {}
    for value,name in ofp_type_map.items():
      name = name.split("OFPT_",1)[-1].lower()
      h = getattr(self, "_rx_" + name, None)
      if not h: continue
      assert of._message_type_to_class[value]._from_controller, name
      self.ofp_handlers[value] = h

    # Set up handlers for actions
    # That is, self.action_handlers[OFPAT_FOO] = self._action_foo
    #TODO: Refactor this with above
    self.action_handlers = {}
    for value,name in ofp_action_type_map.items():
      name = name.split("OFPAT_",1)[-1].lower()
      h = getattr(self, "_action_" + name, None)
      if not h: continue
      if getattr(self.features, "act_" + name) is False: continue
      self.action_handlers[value] = h

    # Set up handlers for stats handlers
    # That is, self.stats_handlers[OFPST_FOO] = self._stats_foo
    #TODO: Refactor this with above
    self.stats_handlers = {}
    for value,name in ofp_stats_type_map.items():
      name = name.split("OFPST_",1)[-1].lower()
      h = getattr(self, "_stats_" + name, None)
      if not h: continue
      self.stats_handlers[value] = h

    # Set up handlers for flow mod handlers
    # That is, self.flow_mod_handlers[OFPFC_FOO] = self._flow_mod_foo
    #TODO: Refactor this with above
    self.flow_mod_handlers = {}
    for name,value in ofp_flow_mod_command_rev_map.items():
      name = name.split("OFPFC_",1)[-1].lower()
      h = getattr(self, "_flow_mod_" + name, None)
      if not h: continue
      self.flow_mod_handlers[value] = h

  def _gen_port_name (self, port_no):
    return "%s.%s"%(dpid_to_str(self.dpid, True).replace('-','')[:12], port_no)

  def _gen_ethaddr (self, port_no):
    # May cause problems if you have large DPIDs...
    return EthAddr("02%06x%04x" % (self.dpid % 0x00FFff, port_no % 0xffFF))

  def generate_port (self, port_no, name = None, ethaddr = None):
    dpid = self.dpid
    p = ofp_phy_port()
    p.port_no = port_no
    if ethaddr is None:
      p.hw_addr = self._gen_ethaddr(p.port_no)
    else:
      p.hw_addr = EthAddr(ethaddr)
    if name is None:
      p.name = self._gen_port_name(p.port_no)
    else:
      p.name = name
    # Fill in features sort of arbitrarily
    p.config = OFPPC_NO_STP
    p.curr = OFPPF_10MB_HD
    p.advertised = OFPPF_10MB_HD
    p.supported = OFPPF_10MB_HD
    p.peer = OFPPF_10MB_HD
    return p

  @property
  def _time (self):
    """
    Get the current time

    This should be used for, e.g., calculating timeouts.  It currently isn't
    used everywhere it should be.

    Override this to change time behavior.
    """
    return time.time()

  def _handle_FlowTableModification (self, event):
    """
    Handle flow table modification events
    """
    # Currently, we only use this for sending flow_removed messages
    if not event.removed: return

    if event.reason in (OFPRR_IDLE_TIMEOUT,OFPRR_HARD_TIMEOUT,OFPRR_DELETE):
      # These reasons may lead to a flow_removed
      count = 0
      for entry in event.removed:
        if entry.flags & OFPFF_SEND_FLOW_REM and not entry.flags & OFPFF_EMERG:
          # Flow wants removal notification -- send it
          fr = entry.to_flow_removed(self._time, reason=event.reason)
          self.send(fr)
          count += 1
      self.log.debug("%d flows removed (%d removal notifications)",
          len(event.removed), count)

  def rx_message (self, connection, msg):
    """
    Handle an incoming OpenFlow message
    """
    ofp_type = msg.header_type
    h = self.ofp_handlers.get(ofp_type)
    if h is None:
      raise RuntimeError("No handler for ofp_type %s(%d)"
                         % (ofp_type_map.get(ofp_type), ofp_type))

    self.log.debug("Got %s with XID %s",ofp_type_map.get(ofp_type),msg.xid)
    h(msg, connection=connection)

  def set_connection (self, connection):
    """
    Set this switch's connection.
    """
    self._has_sent_hello = False
    connection.set_message_handler(self.rx_message)
    self._connection = connection

  def send (self, message, connection = None):
    """
    Send a message to this switch's communication partner
    """
    if connection is None:
      connection = self._connection
    if connection:
      connection.send(message)
    else:
      self.log.debug("Asked to send message %s, but not connected", message)

  def _rx_hello (self, ofp, connection):
    #FIXME: This isn't really how hello is supposed to work -- we're supposed
    #       to send it immediately on connection.  See _send_hello().
    self.send_hello()

  def _rx_echo_request (self, ofp, connection):
    """
    Handles echo requests
    """
    msg = ofp_echo_reply(xid=ofp.xid, body=ofp.body)
    self.send(msg)

  def _rx_features_request (self, ofp, connection):
    """
    Handles feature requests
    """
    self.log.debug("Send features reply")
    msg = ofp_features_reply(datapath_id = self.dpid,
                             xid = ofp.xid,
                             n_buffers = self.max_buffers,
                             n_tables = 1,
                             capabilities = self.features.capability_bits,
                             actions = self.features.action_bits,
                             ports = list(self.ports.values()))
    self.send(msg)

  def _rx_flow_mod (self, ofp, connection):
    """
    Handles flow mods
    """
    self.log.debug("Flow mod details: %s", ofp.show())

    #self.table.process_flow_mod(ofp)
    #self._process_flow_mod(ofp, connection=connection, table=self.table)
    handler = self.flow_mod_handlers.get(ofp.command)
    if handler is None:
      self.log.warn("Command not implemented: %s" % command)
      self.send_error(type=OFPET_FLOW_MOD_FAILED, code=OFPFMFC_BAD_COMMAND,
                      ofp=ofp, connection=connection)
      return
    handler(flow_mod=ofp, connection=connection, table=self.table)

    if ofp.buffer_id is not None:
      self._process_actions_for_packet_from_buffer(ofp.actions, ofp.buffer_id,
                                                   ofp)

  def _rx_packet_out (self, packet_out, connection):
    """
    Handles packet_outs
    """
    self.log.debug("Packet out details: %s", packet_out.show())

    if packet_out.data:
      self._process_actions_for_packet(packet_out.actions, packet_out.data,
                                       packet_out.in_port, packet_out)
    elif packet_out.buffer_id is not None:
      self._process_actions_for_packet_from_buffer(packet_out.actions,
                                                   packet_out.buffer_id,
                                                   packet_out)
    else:
      self.log.warn("packet_out: No data and no buffer_id -- "
                    "don't know what to send")

  def _rx_echo_reply (self, ofp, connection):
    pass

  def _rx_barrier_request (self, ofp, connection):
    msg = ofp_barrier_reply(xid = ofp.xid)
    self.send(msg)

  def _rx_get_config_request (self, ofp, connection):
    msg = ofp_get_config_reply(xid = ofp.xid)
    msg.miss_send_len = self.miss_send_len
    msg.flags = self.config_flags
    self.log.debug("Sending switch config reply %s", msg)
    self.send(msg)

  def _rx_stats_request (self, ofp, connection):
    handler = self.stats_handlers.get(ofp.type)
    if handler is None:
      self.log.warning("Stats type %s not implemented", ofp.type)

      self.send_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_STAT,
                      ofp=ofp, connection=connection)
      return

    body = handler(ofp, connection=connection)
    if body is not None:
      reply = ofp_stats_reply(xid=ofp.xid, type=ofp.type, body=body)
      self.log.debug("Sending stats reply %s", reply)
      self.send(reply)

  def _rx_set_config (self, config, connection):
    self.miss_send_len = config.miss_send_len
    self.config_flags = config.flags

  def _rx_port_mod (self, port_mod, connection):
    port_no = port_mod.port_no
    if port_no not in self.ports:
      self.send_error(type=OFPET_PORT_MOD_FAILED, code=OFPPMFC_BAD_PORT,
                      ofp=port_mod, connection=connection)
      return
    port = self.ports[port_no]
    if port.hw_addr != port_mod.hw_addr:
      self.send_error(type=OFPET_PORT_MOD_FAILED, code=OFPPMFC_BAD_HW_ADDR,
                      ofp=port_mod, connection=connection)
      return

    mask = port_mod.mask

    for bit in range(32):
      bit = 1 << bit
      if mask & bit:
        handled,r = self._set_port_config_bit(port, bit, port_mod.config & bit)
        if not handled:
          self.log.warn("Unsupported port config flag: %08x", bit)
          continue
        if r is not None:
          msg = "Port %s: " % (port.port_no,)
          if isinstance(r, str):
            msg += r
          else:
            msg += ofp_port_config_map.get(bit, "config bit %x" % (bit,))
            msg += " set to "
            msg += "true" if r else "false"
          self.log.debug(msg)

  def _rx_vendor (self, vendor, connection):
    # We don't support vendor extensions, so send an OFP_ERROR, per
    # page 42 of spec
    self.send_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_VENDOR,
                    ofp=vendor, connection=connection)

  def _rx_queue_get_config_request (self, ofp, connection):
    """
    Handles an OFPT_QUEUE_GET_CONFIG_REQUEST message.
    """
    reply = ofp_queue_get_config_reply(xid=ofp.xid, port=ofp.port, queues=[])
    self.log.debug("Sending queue get config reply %s", reply)
    self.send(reply)

  def send_hello (self, force = False):
    """
    Send hello (once)
    """
    #FIXME: This is wrong -- we should just send when connecting.
    if self._has_sent_hello and not force: return
    self._has_sent_hello = True
    self.log.debug("Sent hello")
    msg = ofp_hello(xid=0)
    self.send(msg)

  def send_packet_in (self, in_port, buffer_id=None, packet=b'', reason=None,
                      data_length=None):
    """
    Send PacketIn
    """
    if hasattr(packet, 'pack'):
      packet = packet.pack()
    assert assert_type("packet", packet, bytes)
    self.log.debug("Send PacketIn")
    if reason is None:
      reason = OFPR_NO_MATCH
    if data_length is not None and len(packet) > data_length:
      if buffer_id is not None:
        packet = packet[:data_length]

    msg = ofp_packet_in(xid = 0, in_port = in_port, buffer_id = buffer_id,
                        reason = reason, data = packet)

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

  def send_error (self, type, code, ofp=None, data=None, connection=None):
    """
    Send an error

    If you pass ofp, it will be used as the source of the error's XID and
    data.
    You can override the data by also specifying data.
    """
    err = ofp_error(type=type, code=code)
    if ofp:
      err.xid = ofp.xid
      err.data = ofp.pack()
    else:
      err.xid = 0
    if data is not None:
      err.data = data
    self.send(err, connection = connection)

  def rx_packet (self, packet, in_port, packet_data = None):
    """
    process a dataplane packet

    packet: an instance of ethernet
    in_port: the integer port number
    packet_data: packed version of packet if available
    """
    assert assert_type("packet", packet, ethernet, none_ok=False)
    assert assert_type("in_port", in_port, int, none_ok=False)
    port = self.ports.get(in_port)
    if port is None:
      self.log.warn("Got packet on missing port %i", in_port)
      return

    is_stp = packet.dst == _STP_MAC

    if (port.config & OFPPC_NO_RECV) and not is_stp:
      # Drop all except STP
      return
    if (port.config & OFPPC_NO_RECV_STP) and is_stp:
      # Drop STP
      return

    if self.config_flags & OFPC_FRAG_MASK:
      ipp = packet.find(ipv4)
      if ipp:
        if (ipp.flags & ipv4.MF_FLAG) or ipp.frag != 0:
          frag_mode = self.config_flags & OFPC_FRAG_MASK
          if frag_mode == OFPC_FRAG_DROP:
            # Drop fragment
            return
          elif frag_mode == OFPC_FRAG_REASM:
            if self.features.cap_ip_reasm:
              #TODO: Implement fragment reassembly
              self.log.info("Can't reassemble fragment: not implemented")
          else:
            self.log.warn("Illegal fragment processing mode: %i", frag_mode)

    self.port_stats[in_port].rx_packets += 1
    if packet_data is not None:
      self.port_stats[in_port].rx_bytes += len(packet_data)
    else:
      self.port_stats[in_port].rx_bytes += len(packet.pack()) # Expensive

    self._lookup_count += 1
    entry = self.table.entry_for_packet(packet, in_port)
    if entry is not None:
      self._matched_count += 1
      entry.touch_packet(len(packet))
      self._process_actions_for_packet(entry.actions, packet, in_port)
    else:
      # no matching entry
      if port.config & OFPPC_NO_PACKET_IN:
        return
      buffer_id = self._buffer_packet(packet, in_port)
      if packet_data is None:
        packet_data = packet.pack()
      self.send_packet_in(in_port, buffer_id, packet_data,
                          reason=OFPR_NO_MATCH, data_length=self.miss_send_len)

  def delete_port (self, port):
    """
    Removes a port

    Sends a port_status message to the controller

    Returns the removed phy_port
    """
    try:
      port_no = port.port_no
      assert self.ports[port_no] is port
    except:
      port_no = port
      port = self.ports[port_no]
    if port_no not in self.ports:
      raise RuntimeError("Can't remove nonexistent port " + str(port_no))
    self.send_port_status(port, OFPPR_DELETE)
    del self.ports[port_no]
    return port

  def add_port (self, port):
    """
    Adds a port

    Sends a port_status message to the controller
    """
    try:
      port_no = port.port_no
    except:
      port_no = port
      port = self.generate_port(port_no, self.dpid)
    if port_no in self.ports:
      raise RuntimeError("Port %s already exists" % (port_no,))
    self.ports[port_no] = port
    self.port_stats[port.port_no] = ofp_port_stats(port_no=port.port_no)
    self.send_port_status(port, OFPPR_ADD)

  def _set_port_config_bit (self, port, bit, value):
    """
    Set a port config bit

    This is called in response to port_mods.  It is passed the ofp_phy_port,
    the bit/mask, and the value of the bit (i.e., 0 if the flag is to be
    unset, or the same value as bit if it is to be set).

    The return value is a tuple (handled, msg).
    If bit is handled, then handled will be True, else False.
    if msg is a string, it will be used as part of a log message.
    If msg is None, there will be no log message.
    If msg is anything else "truthy", an "enabled" log message is generated.
    If msg is anything else "falsy", a "disabled" log message is generated.
    msg is only used when handled is True.
    """
    if bit == OFPPC_NO_STP:
      if value == 0:
        # we also might send OFPBRC_EPERM if trying to disable this bit
        self.log.warn("Port %s: Can't enable 802.1D STP", port.port_no)
      return (True, None)

    if bit not in (OFPPC_PORT_DOWN, OFPPC_NO_STP, OFPPC_NO_RECV, OFPPC_NO_RECV_STP,
                   OFPPC_NO_FLOOD, OFPPC_NO_FWD, OFPPC_NO_PACKET_IN):
      return (False, None)

    if port.set_config(value, bit):
      if bit == OFPPC_PORT_DOWN:
        # Note (Peter Peresini): Although the spec is not clear about it,
        # we will assume that config.OFPPC_PORT_DOWN implies
        # state.OFPPS_LINK_DOWN. This is consistent with Open vSwitch.

        #TODO: for now, we assume that there is always physical link present
        # and that the link state depends only on the configuration.
        old_state = port.state & OFPPS_LINK_DOWN
        port.state = port.state & ~OFPPS_LINK_DOWN
        if port.config & OFPPC_PORT_DOWN:
          port.state = port.state | OFPPS_LINK_DOWN
        new_state = port.state & OFPPS_LINK_DOWN
        if old_state != new_state:
          self.send_port_status(port, OFPPR_MODIFY)

      # Do default log message.
      return (True, value)

    # No change -- no log message.
    return (True, None)

  def _output_packet_physical (self, packet, port_no):
    """
    send a packet out a single physical port

    This is called by the more general _output_packet().

    Override this.
    """
    self.log.info("Sending packet %s out port %s", str(packet), port_no)

  def _output_packet (self, packet, out_port, in_port, max_len=None):
    """
    send a packet out some port

    This handles virtual ports and does validation.

    packet: instance of ethernet
    out_port, in_port: the integer port number
    max_len: maximum packet payload length to send to controller
    """
    assert assert_type("packet", packet, ethernet, none_ok=False)

    def real_send (port_no, allow_in_port=False):
      if type(port_no) == ofp_phy_port:
        port_no = port_no.port_no
      if port_no == in_port and not allow_in_port:
        self.log.warn("Dropping packet sent on port %i: Input port", port_no)
        return
      if port_no not in self.ports:
        self.log.warn("Dropping packet sent on port %i: Invalid port", port_no)
        return
      if self.ports[port_no].config & OFPPC_NO_FWD:
        self.log.warn("Dropping packet sent on port %i: Forwarding disabled",
                      port_no)
        return
      if self.ports[port_no].config & OFPPC_PORT_DOWN:
        self.log.warn("Dropping packet sent on port %i: Port down", port_no)
        return
      if self.ports[port_no].state & OFPPS_LINK_DOWN:
        self.log.debug("Dropping packet sent on port %i: Link down", port_no)
        return
      self.port_stats[port_no].tx_packets += 1
      self.port_stats[port_no].tx_bytes += len(packet.pack()) #FIXME: Expensive
      self._output_packet_physical(packet, port_no)

    if out_port < OFPP_MAX:
      real_send(out_port)
    elif out_port == OFPP_IN_PORT:
      real_send(in_port, allow_in_port=True)
    elif out_port == OFPP_FLOOD:
      for no,port in self.ports.items():
        if no == in_port: continue
        if port.config & OFPPC_NO_FLOOD: continue
        real_send(port)
    elif out_port == OFPP_ALL:
      for no,port in self.ports.items():
        if no == in_port: continue
        real_send(port)
    elif out_port == OFPP_CONTROLLER:
      buffer_id = self._buffer_packet(packet, in_port)
      # Should we honor OFPPC_NO_PACKET_IN here?
      self.send_packet_in(in_port, buffer_id, packet, reason=OFPR_ACTION,
                          data_length=max_len)
    elif out_port == OFPP_TABLE:
      # Do we disable send-to-controller when performing this?
      # (Currently, there's the possibility that a table miss from this
      # will result in a send-to-controller which may send back to table...)
      self.rx_packet(packet, in_port)
    else:
      self.log.warn("Unsupported virtual output port: %d", out_port)

  def _buffer_packet (self, packet, in_port=None):
    """
    Buffer packet and return buffer ID

    If no buffer is available, return None.
    """
    # Do we have an empty slot?
    for (i, value) in enumerate(self._packet_buffer):
      if value is None:
        # Yes -- use it
        self._packet_buffer[i] = (packet, in_port)
        return i + 1
    # No -- create a new slow
    if len(self._packet_buffer) >= self.max_buffers:
      # No buffers available!
      return None
    self._packet_buffer.append( (packet, in_port) )
    return len(self._packet_buffer)

  def _process_actions_for_packet_from_buffer (self, actions, buffer_id,
                                               ofp=None):
    """
    output and release a packet from the buffer

    ofp is the message which triggered this processing, if any (used for error
    generation)
    """
    buffer_id = buffer_id - 1
    if (buffer_id >= len(self._packet_buffer)) or (buffer_id < 0):
      self.log.warn("Invalid output buffer id: %d", buffer_id + 1)
      return
    if self._packet_buffer[buffer_id] is None:
      self.log.warn("Buffer %d has already been flushed", buffer_id + 1)
      return
    (packet, in_port) = self._packet_buffer[buffer_id]
    self._process_actions_for_packet(actions, packet, in_port, ofp)
    self._packet_buffer[buffer_id] = None

  def _process_actions_for_packet (self, actions, packet, in_port, ofp=None):
    """
    process the output actions for a packet

    ofp is the message which triggered this processing, if any (used for error
    generation)
    """
    assert assert_type("packet", packet, (ethernet, bytes), none_ok=False)
    if not isinstance(packet, ethernet):
      packet = ethernet.unpack(packet)

    for action in actions:
      #if action.type is ofp_action_resubmit:
      #  self.rx_packet(packet, in_port)
      #  return
      h = self.action_handlers.get(action.type)
      if h is None:
        self.log.warn("Unknown action type: %x " % (action.type,))
        self.send_error(type=OFPET_BAD_ACTION, code=OFPBAC_BAD_TYPE, ofp=ofp)
        return
      packet = h(action, packet, in_port)

  def _flow_mod_add (self, flow_mod, connection, table):
    """
    Process an OFPFC_ADD flow mod sent to the switch.
    """
    match = flow_mod.match
    priority = flow_mod.priority

    if flow_mod.flags & OFPFF_EMERG:
      if flow_mod.idle_timeout != 0 or flow_mod.hard_timeout != 0:
        # Emergency flow mod has non-zero timeouts. Do not add.
        self.log.warn("Rejecting emergency flow with nonzero timeout")
        self.send_error(type=OFPET_FLOW_MOD_FAILED,
                        code=OFPFMFC_BAD_EMERG_TIMEOUT,
                        ofp=flow_mod, connection=connection)
        return
      if flow_mod.flags & OFPFF_SEND_FLOW_REM:
        # Emergency flows can't send removal messages, we we might want to
        # reject this early.  Sadly, there's no error code for this, so we just
        # abuse EPERM.  If we eventually support Nicira extended error codes,
        # we should use one here.
        self.log.warn("Rejecting emergency flow with flow removal flag")
        self.send_error(type=OFPET_FLOW_MOD_FAILED,
                        code=OFPFMFC_EPERM,
                        ofp=flow_mod, connection=connection)
        return
      #NOTE: An error is sent anyways because the current implementation does
      #      not support emergency entries.
      self.log.warn("Rejecting emergency flow (not supported)")
      self.send_error(type=OFPET_FLOW_MOD_FAILED,
                      code=OFPFMFC_ALL_TABLES_FULL,
                      ofp=flow_mod, connection=connection)
      return

    new_entry = TableEntry.from_flow_mod(flow_mod)

    if flow_mod.flags & OFPFF_CHECK_OVERLAP:
      if table.check_for_overlapping_entry(new_entry):
        # Another entry overlaps. Do not add.
        self.send_error(type=OFPET_FLOW_MOD_FAILED, code=OFPFMFC_OVERLAP,
                        ofp=flow_mod, connection=connection)
        return

    if flow_mod.command == OFPFC_ADD:
      # Exactly matching entries have to be removed if OFPFC_ADD
      table.remove_matching_entries(match, priority=priority, strict=True)

    if len(table) >= self.max_entries:
      # Flow table is full. Respond with error message.
      self.send_error(type=OFPET_FLOW_MOD_FAILED,
                      code=OFPFMFC_ALL_TABLES_FULL,
                      ofp=flow_mod, connection=connection)
      return

    table.add_entry(new_entry)

  def _flow_mod_modify (self, flow_mod, connection, table, strict=False):
    """
    Process an OFPFC_MODIFY flow mod sent to the switch.
    """
    match = flow_mod.match
    priority = flow_mod.priority

    modified = False
    for entry in table.entries:
      # update the actions field in the matching flows
      if entry.is_matched_by(match, priority=priority, strict=strict):
        entry.actions = flow_mod.actions
        modified = True

    if not modified:
      # if no matching entry is found, modify acts as add
      self._flow_mod_add(flow_mod, connection, table)

  def _flow_mod_modify_strict (self, flow_mod, connection, table):
    """
    Process an OFPFC_MODIFY_STRICT flow mod sent to the switch.
    """
    self._flow_mod_modify(flow_mod, connection, table, strict=True)

  def _flow_mod_delete (self, flow_mod, connection, table, strict=False):
    """
    Process an OFPFC_DELETE flow mod sent to the switch.
    """
    match = flow_mod.match
    priority = flow_mod.priority

    out_port = flow_mod.out_port
    if out_port == OFPP_NONE: out_port = None # Don't filter
    table.remove_matching_entries(match, priority=priority, strict=strict,
                                  out_port=out_port, reason=OFPRR_DELETE)

  def _flow_mod_delete_strict (self, flow_mod, connection, table):
    """
    Process an OFPFC_DELETE_STRICT flow mod sent to the switch.
    """
    self._flow_mod_delete(flow_mod, connection, table, strict=True)

  def _action_output (self, action, packet, in_port):
    self._output_packet(packet, action.port, in_port, action.max_len)
    return packet
  def _action_set_vlan_vid (self, action, packet, in_port):
    if not isinstance(packet.payload, vlan):
      vl = vlan()
      vl.eth_type = packet.type
      vl.payload = packet.payload
      packet.type = ethernet.VLAN_TYPE
      packet.payload = vl
    packet.payload.id = action.vlan_vid
    return packet
  def _action_set_vlan_pcp (self, action, packet, in_port):
    if not isinstance(packet.payload, vlan):
      vl = vlan()
      vl.payload = packet.payload
      vl.eth_type = packet.type
      packet.payload = vl
      packet.type = ethernet.VLAN_TYPE
    packet.payload.pcp = action.vlan_pcp
    return packet
  def _action_strip_vlan (self, action, packet, in_port):
    if isinstance(packet.payload, vlan):
      packet.type = packet.payload.eth_type
      packet.payload = packet.payload.payload
    return packet
  def _action_set_dl_src (self, action, packet, in_port):
    packet.src = action.dl_addr
    return packet
  def _action_set_dl_dst (self, action, packet, in_port):
    packet.dst = action.dl_addr
    return packet
  def _action_set_nw_src (self, action, packet, in_port):
    nw = packet.payload
    if isinstance(nw, vlan):
      nw = nw.payload
    if isinstance(nw, ipv4):
      nw.srcip = action.nw_addr
    return packet
  def _action_set_nw_dst (self, action, packet, in_port):
    nw = packet.payload
    if isinstance(nw, vlan):
      nw = nw.payload
    if isinstance(nw, ipv4):
      nw.dstip = action.nw_addr
    return packet
  def _action_set_nw_tos (self, action, packet, in_port):
    nw = packet.payload
    if isinstance(nw, vlan):
      nw = nw.payload
    if isinstance(nw, ipv4):
      nw.tos = action.nw_tos
    return packet
  def _action_set_tp_src (self, action, packet, in_port):
    nw = packet.payload
    if isinstance(nw, vlan):
      nw = nw.payload
    if isinstance(nw, ipv4):
      tp = nw.payload
      if isinstance(tp, udp) or isinstance(tp, tcp):
        tp.srcport = action.tp_port
    return packet
  def _action_set_tp_dst (self, action, packet, in_port):
    nw = packet.payload
    if isinstance(nw, vlan):
      nw = nw.payload
    if isinstance(nw, ipv4):
      tp = nw.payload
      if isinstance(tp, udp) or isinstance(tp, tcp):
        tp.dstport = action.tp_port
    return packet
  def _action_enqueue (self, action, packet, in_port):
    self.log.warn("Enqueue not supported.  Performing regular output.")
    self._output_packet(packet, action.tp_port, in_port)
    return packet
#  def _action_push_mpls_tag (self, action, packet, in_port):
#    bottom_of_stack = isinstance(packet.next, mpls)
#    packet.next = mpls(prev = packet.pack())
#    if bottom_of_stack:
#      packet.next.s = 1
#    packet.type = action.ethertype
#    return packet
#  def _action_pop_mpls_tag (self, action, packet, in_port):
#    if not isinstance(packet.next, mpls):
#      return packet
#    if not isinstance(packet.next.next, str):
#      packet.next.next = packet.next.next.pack()
#    if action.ethertype in ethernet.type_parsers:
#      packet.next = ethernet.type_parsers[action.ethertype](packet.next.next)
#    else:
#      packet.next = packet.next.next
#    packet.ethertype = action.ethertype
#    return packet
#  def _action_set_mpls_label (self, action, packet, in_port):
#    if not isinstance(packet.next, mpls):
#      mock = ofp_action_push_mpls()
#      packet = push_mpls_tag(mock, packet)
#    packet.next.label = action.mpls_label
#    return packet
#  def _action_set_mpls_tc (self, action, packet, in_port):
#    if not isinstance(packet.next, mpls):
#      mock = ofp_action_push_mpls()
#      packet = push_mpls_tag(mock, packet)
#    packet.next.tc = action.mpls_tc
#    return packet
#  def _action_set_mpls_ttl (self, action, packet, in_port):
#    if not isinstance(packet.next, mpls):
#      mock = ofp_action_push_mpls()
#      packet = push_mpls_tag(mock, packet)
#    packet.next.ttl = action.mpls_ttl
#    return packet
#  def _action_dec_mpls_ttl (self, action, packet, in_port):
#    if not isinstance(packet.next, mpls):
#      return packet
#    packet.next.ttl = packet.next.ttl - 1
#    return packet


  def _stats_desc (self, ofp, connection):
    try:
      from pox.core import core
      return ofp_desc_stats(mfr_desc="POX",
                            hw_desc=core._get_platform_info(),
                            sw_desc=core.version_string,
                            serial_num=str(self.dpid),
                            dp_desc=type(self).__name__)
    except:
      return ofp_desc_stats(mfr_desc="POX",
                            hw_desc="Unknown",
                            sw_desc="Unknown",
                            serial_num=str(self.dpid),
                            dp_desc=type(self).__name__)


  def _stats_flow (self, ofp, connection):
    if ofp.body.table_id not in (TABLE_ALL, 0):
      return [] # No flows for other tables
    out_port = ofp.body.out_port
    if out_port == OFPP_NONE: out_port = None # Don't filter
    return self.table.flow_stats(ofp.body.match, out_port)

  def _stats_aggregate (self, ofp, connection):
    if ofp.body.table_id not in (TABLE_ALL, 0):
      return [] # No flows for other tables
    out_port = ofp.body.out_port
    if out_port == OFPP_NONE: out_port = None # Don't filter
    return self.table.aggregate_stats(ofp.body.match, out_port)

  def _stats_table (self, ofp, connection):
    # Some of these may come from the actual table(s) in the future...
    r = ofp_table_stats()
    r.table_id = 0
    r.name = "Default"
    r.wildcards = OFPFW_ALL
    r.max_entries = self.max_entries
    r.active_count = len(self.table)
    r.lookup_count = self._lookup_count
    r.matched_count = self._matched_count
    return r

  def _stats_port (self, ofp, connection):
    req = ofp.body
    if req.port_no == OFPP_NONE:
      return list(self.port_stats.values())
    else:
      return self.port_stats[req.port_no]

  def _stats_queue (self, ofp, connection):
    # We don't support queues whatsoever so either send an empty list or send
    # an OFP_ERROR if an actual queue is requested.
    req = ofp.body
    #if req.port_no != OFPP_ALL:
    #  self.send_error(type=OFPET_QUEUE_OP_FAILED, code=OFPQOFC_BAD_PORT,
    #                  ofp=ofp, connection=connection)
    # Note: We don't care about this case for now, even if port_no is bogus.
    if req.queue_id == OFPQ_ALL:
      return []
    else:
      self.send_error(type=OFPET_QUEUE_OP_FAILED, code=OFPQOFC_BAD_QUEUE,
                      ofp=ofp, connection=connection)


  def __repr__ (self):
    return "%s(dpid=%s, num_ports=%d)" % (type(self).__name__,
                                          dpid_to_str(self.dpid),
                                          len(self.ports))


class SoftwareSwitch (SoftwareSwitchBase, EventMixin):
  _eventMixin_events = set([DpPacketOut])

  def _output_packet_physical (self, packet, port_no):
    """
    send a packet out a single physical port

    This is called by the more general _output_packet().
    """
    self.raiseEvent(DpPacketOut(self, packet, self.ports[port_no]))


class ExpireMixin (object):
  """
  Adds expiration to a switch

  Inherit *before* switch base.
  """
  _expire_period = 2

  def __init__ (self, *args, **kw):
    expire_period = kw.pop('expire_period', self._expire_period)
    super(ExpireMixin,self).__init__(*args, **kw)
    if not expire_period:
      # Disable
      return
    self._expire_timer = Timer(expire_period,
                               self.table.remove_expired_entries,
                               recurring=True)


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

  # See _error_handler for information the meanings of these
  ERR_BAD_VERSION = 1
  ERR_NO_UNPACKER = 2
  ERR_BAD_LENGTH  = 3
  ERR_EXCEPTION   = 4

  # These methods are called externally by IOWorker
  def msg (self, m):
    self.log.debug("%s %s", str(self), str(m))
  def err (self, m):
    self.log.error("%s %s", str(self), str(m))
  def info (self, m):
    self.log.info("%s %s", str(self), str(m))

  def __init__ (self, io_worker):
    self.starting = True # No data yet
    self.io_worker = io_worker
    self.io_worker.rx_handler = self.read
    self.controller_id = io_worker.socket.getpeername()
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
    #FIXME: Do we need to pass io_worker here?
    while True:
      message = io_worker.peek()
      if len(message) < 4:
        break

      # Parse head of OpenFlow message by hand
      ofp_version = message[0]
      ofp_type = message[1]

      if ofp_version != OFP_VERSION:
        info = ofp_version
        r = self._error_handler(self.ERR_BAD_VERSION, info)
        if r is False: break
        continue

      message_length = message[2] << 8 | message[3]
      if message_length > len(message):
        break

      if ofp_type >= 0 and ofp_type < len(self.unpackers):
        unpacker = self.unpackers[ofp_type]
      else:
        unpacker = None
      if unpacker is None:
        info = (ofp_type, message_length)
        r = self._error_handler(self.ERR_NO_UNPACKER, info)
        if r is False: break
        io_worker.consume_receive_buf(message_length)
        continue

      new_offset, msg_obj = self.unpackers[ofp_type](message, 0)
      if new_offset != message_length:
        info = (msg_obj, message_length, new_offset)
        r = self._error_handler(self.ERR_BAD_LENGTH, info)
        if r is False: break
        # Assume sender was right and we should skip what it told us to.
        io_worker.consume_receive_buf(message_length)
        continue

      io_worker.consume_receive_buf(message_length)
      self.starting = False

      if self.on_message_received is None:
        raise RuntimeError("on_message_receieved hasn't been set yet!")

      try:
        self.on_message_received(self, msg_obj)
      except Exception as e:
        info = (e, message[:message_length], msg_obj)
        r = self._error_handler(self.ERR_EXCEPTION, info)
        if r is False: break
        continue

    return True

  def _error_handler (self, reason, info):
      """
      Called when read() has an error

      reason is one of OFConnection.ERR_X

      info depends on reason:
      ERR_BAD_VERSION: claimed version number
      ERR_NO_UNPACKER: (claimed message type, claimed length)
      ERR_BAD_LENGTH: (unpacked message, claimed length, unpacked length)
      ERR_EXCEPTION: (exception, raw message, unpacked message)

      Return False to halt processing of subsequent data (makes sense to
      do this if you called connection.close() here, for example).
      """
      if reason == OFConnection.ERR_BAD_VERSION:
        ofp_version = info
        self.log.warn('Unsupported OpenFlow version 0x%02x', info)
        if self.starting:
          message = self.io_worker.peek()
          err = ofp_error(type=OFPET_HELLO_FAILED, code=OFPHFC_INCOMPATIBLE)
          #err = ofp_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_VERSION)
          err.xid = self._extract_message_xid(message)
          err.data = 'Version unsupported'
          self.send(err)
        self.close()
        return False
      elif reason == OFConnection.ERR_NO_UNPACKER:
        ofp_type, message_length = info
        self.log.warn('Unsupported OpenFlow message type 0x%02x', ofp_type)
        message = self.io_worker.peek()
        err = ofp_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_TYPE)
        err.xid = self._extract_message_xid(message)
        err.data = message[:message_length]
        self.send(err)
      elif reason == OFConnection.ERR_BAD_LENGTH:
        msg_obj, message_length, new_offset = info
        t = type(msg_obj).__name__
        self.log.error('Different idea of message length for %s '
                       '(us:%s them:%s)' % (t, new_offset, message_length))
        message = self.io_worker.peek()
        err = ofp_error(type=OFPET_BAD_REQUEST, code=OFPBRC_BAD_LEN)
        err.xid = self._extract_message_xid(message)
        err.data = message[:message_length]
        self.send(err)
      elif reason == OFConnection.ERR_EXCEPTION:
        ex, raw_message, msg_obj = info
        t = type(ex).__name__
        self.log.exception('Exception handling %s' % (t,))
      else:
        self.log.error("Unhandled error")
        self.close()
        return False

  def _extract_message_xid (self, message):
    """
    Extract and return the xid (and length) of an openflow message.
    """
    xid = 0
    if len(message) >= 8:
      #xid = struct.unpack_from('!L', message, 4)[0]
      message_length, xid = struct.unpack_from('!HL', message, 2)
    elif len(message) >= 4:
      message_length = message[2] << 8 | message[3]
    else:
      message_length = len(message)
    return xid

  def close (self):
    self.io_worker.shutdown()

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
    for val,name in ofp_capabilities_map.items():
      name = name[5:].lower() # strip OFPC_
      name = "cap_" + name
      setattr(self, name, False)
      self._cap_info[name] = val

    self._act_info = {}
    for val,name in ofp_action_type_map.items():
      name = name[6:].lower() # strip OFPAT_
      name = "act_" + name
      setattr(self, name, False)
      self._act_info[name] = val

    self._locked = True

    initHelper(self, kw)

  def __setattr__ (self, attr, value):
    if getattr(self, '_locked', False):
      if not hasattr(self, attr):
        raise AttributeError("No such attribute as '%s'" % (attr,))
    return super(SwitchFeatures,self).__setattr__(attr, value)

  @property
  def capability_bits (self):
    """
    Value used in features reply
    """
    return sum( (v if getattr(self, k) else 0)
                for k,v in self._cap_info.items() )

  @property
  def action_bits (self):
    """
    Value used in features reply
    """
    return sum( (1<<v if getattr(self, k) else 0)
                for k,v in self._act_info.items() )

  def __str__ (self):
    l = list(k for k in self._cap_info if getattr(self, k))
    l += list(k for k in self._act_info if getattr(self, k))
    return ",".join(l)
