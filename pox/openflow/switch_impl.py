"""
Software OpenFlow Switch

@author: Colin Scott (cs@cs.berkeley.edu)

Based heavily on pylibopenflow:

Copyright(C) 2009, Stanford University
Date November 2009
Created by ykk
"""

# TODO: Don't have SwitchImpl take a socket object... Should really have a
# OF_01 like task that listens for socket connections, creates a new socket,
# wraps it in a ControllerConnection object, and calls SwitchImpl._handle_ConnectionUp

from pox.lib.util import assert_type
from pox.lib.revent import Event, EventMixin
from pox.core import core
from pox.openflow.libopenflow_01 import *
from pox.openflow.of_01 import make_type_to_class_table, deferredSender
from pox.openflow.flow_table import TableEntry, SwitchFlowTable

from errno import EAGAIN
from collections import namedtuple
import itertools

class SwitchDpPacketOut (Event):
  """ Event raised by SwitchImpl when a dataplane packet is sent out a port """
  def __init__ (self, switch, packet, port):
    assert_type("switch", switch, SwitchImpl, none_ok=False)
    assert_type("packet", packet, ethernet, none_ok=False)
    assert_type("port", port, ofp_phy_port, none_ok=False)
    Event.__init__(self)
    self.switch = switch
    self.packet = packet
    self.port = port

def _default_port_list(num_ports=4, prefix=0):
  return [ofp_phy_port(port_no=i, hw_addr=EthAddr("00:00:00:00:%2x:%2x" % (prefix % 255, i))) for i in range(1, num_ports+1)]

class SwitchImpl(EventMixin):
  _eventMixin_events = set([SwitchDpPacketOut])

  # ports is a list of ofp_phy_ports
  def __init__(self, dpid, name=None, ports=4, miss_send_len=128,
      n_buffers=100, n_tables=1, capabilities=None):
    """Initialize switch"""
    ##Datapath id of switch
    self.dpid = dpid
    ## Human-readable name of the switch
    self.name = name
    if self.name is None:
      self.name = str(dpid)
    self.log = core.getLogger(self.name)
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
    for port in ports:
      self.ports[port.port_no] = port
    ## (OpenFlow Handler map)
    self.ofp_handlers = {
       # Reactive handlers
       ofp_type_rev_map['OFPT_HELLO'] : self._receive_hello,
       ofp_type_rev_map['OFPT_ECHO_REQUEST'] : self._receive_echo,
       ofp_type_rev_map['OFPT_FEATURES_REQUEST'] : self._receive_features_request,
       ofp_type_rev_map['OFPT_FLOW_MOD'] : self._receive_flow_mod,
       ofp_type_rev_map['OFPT_PACKET_OUT'] : self._receive_packet_out,
       ofp_type_rev_map['OFPT_BARRIER_REQUEST'] : self._receive_barrier_request,
       ofp_type_rev_map['OFPT_SET_CONFIG'] : self._receive_set_config,

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

  def set_socket(self, socket):
    self._connection = ControllerConnection(socket, self.ofp_handlers)
    return self._connection

  def set_connection(self, connection):
    connection.ofp_handlers = self.ofp_handlers
    self._connection = connection

  def demux_openflow(self, raw_bytes):
    pass

  # ==================================== #
  #    Reactive OFP processing           #
  # ==================================== #
  def _receive_hello(self, ofp):
    self.log.debug("Receive hello %s" % self.name)
    # How does the OpenFlow protocol prevent an infinite loop of Hello messages?
    self.send_hello()

  def _receive_echo(self, ofp):
    """Reply to echo request
    """
    self.log.debug("Reply echo of xid: %s %s" % (str(ofp), self.name))
    msg = ofp_echo_reply(xid=ofp.xid)
    self._connection.send(msg)

  def _receive_features_request(self, ofp):
    """Reply to feature request
    """
    self.log.debug("Reply features request of xid %s %s" % (str(ofp), self.name))
    msg = ofp_features_reply(datapath_id = self.dpid, xid = ofp.xid, n_buffers = self.n_buffers,
                             n_tables = self.n_tables,
                             capabilities = self.capabilities.get_capabilities(),
                             actions = self.capabilities.get_actions(),
                             ports = self.ports.values())
    self._connection.send(msg)

  def _receive_flow_mod(self, ofp):
    """Handle flow mod: just print it here
    """
    self.log.debug("Flow mod %s: %s" % (self.name, ofp.show()))
    self.table.process_flow_mod(ofp)
    if(ofp.buffer_id >=0 ):
      self._process_actions_for_packet_from_buffer(ofp.actions, ofp.buffer_id)

  def _receive_packet_out(self, packet_out):
    """
    Send the packet out the given port
    """
    self.log.debug("Packet out") # , str(packet))

    if(packet_out.data != None):
      self._process_actions_for_packet(packet_out.actions, packet_out.data, packet_out.in_port)
    elif(packet_out.buffer_id > 0):
      self._process_actions_for_packet_from_buffer(packet_out.actions, packet_out.buffer_id)
    else:
      self.log.warn("packet_out: No data and no buffer_id -- don't know what to send")

  def _receive_echo_reply(self, ofp):
    self.log.debug("Echo reply: %s %s" % (str(ofp), self.name))

  def _receive_barrier_request(self, ofp):
    self.log.debug("Barrier request %s %s" % (self.name, str(ofp)))
    msg = ofp_barrier_reply(xid = ofp.xid)
    self._connection.send(msg)

  def _receive_set_config(self, config):
    self.log.debug("Set  config %s %s" % (self.name, str(config)))

  # ==================================== #
  #    Proactive OFP processing          #
  # ==================================== #
  def send_hello(self):
    """Send hello
    """
    self.log.debug("Send hello %s " % self.name)
    msg = ofp_hello()
    self._connection.send(msg)

  def send_packet_in(self, in_port, buffer_id=None, packet="", xid=None, reason=None):
    """Send PacketIn
    Assume no match as reason, buffer_id = 0xFFFFFFFF,
    and empty packet by default
    """
    assert_type("packet", packet, ethernet)
    self.log.debug("Send PacketIn %s " % self.name)
    if (reason == None):
      reason = ofp_packet_in_reason_rev_map['OFPR_NO_MATCH']
    if (buffer_id == None):
      buffer_id = int("0xFFFFFFFF",16)

    if xid == None: xid = self.xid_count.next()
    msg = ofp_packet_in(xid=xid, in_port = in_port, buffer_id = buffer_id, reason = reason,
                        data = packet.pack())
    self._connection.send(msg)

  def send_echo(self, xid=0):
    """Send echo request
    """
    self.log.debug("Send echo %s" % self.name)
    msg = ofp_echo_request()
    self._connection.send(msg)

  def process_packet(self, packet, in_port):
    """ process a packet the way a real OpenFlow switch would.
        packet: an instance of ethernet
        in_port: the integer port number
    """
    assert_type("packet", packet, ethernet, none_ok=False)

    entry = self.table.entry_for_packet(packet, in_port)
    if(entry != None):
      entry.touch_packet(len(packet))
      self._process_actions_for_packet(entry.actions, packet, in_port)
    else:
      # no matching entry
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_count.next(), reason=OFPR_NO_MATCH)

  # ==================================== #
  #    Helper Methods                    #
  # ==================================== #

  def _output_packet(self, packet, out_port, in_port):
    """ send a packet out some port.
        packet: instance of ethernet
        out_port, in_port: the integer port number """
    assert_type("packet", packet, ethernet, none_ok=False)
    def real_send(port_no):
      if port_no not in self.ports:
        raise RuntimeError("Invalid physical output port: %x" % port_no)
      self.raiseEvent(SwitchDpPacketOut(self, packet, self.ports[port_no]))

    if out_port < OFPP_MAX:
      real_send(out_port)
    elif out_port == OFPP_IN_PORT:
      real_send(in_port)
    elif out_port == OFPP_FLOOD or out_port == OFPP_ALL:
      # no support for spanning tree yet -> flood=all
      for (no,port) in self.ports.iteritems():
        if no != in_port:
          real_send(port)
    elif out_port == OFPP_CONTROLLER:
      buffer_id = self._buffer_packet(packet, in_port)
      self.send_packet_in(in_port, buffer_id, packet, self.xid_iter.next(), reason=OFPR_ACTION)
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
    if(buffer_id > len(self.packet_buffer) or self.packet_buffer[buffer_id] == None):
      self.log.warn("Invalid output buffer id: %x" % buffer_id)
      return
    (packet, in_port) = self.packet_buffer[buffer_id]
    self._process_actions_for_packet(actions, packet, in_port)
    self.packet_buffer[buffer_id] = None

  def _process_actions_for_packet(self, actions, packet, in_port):
    """ process the output actions for a packet """
    assert_type("packet", packet, ethernet, none_ok=False)

    def output_packet(action, packet):
      self._output_packet(packet, action.port, in_port)
    def set_vlan_id(action, packet):
      if not isinstance(packet, vlan): packet = vlan(packet)
      packet.id = action.vlan_id
    def set_vlan_pcp(action, packet):
      if not isinstance(packet, vlan): packet = vlan(packet)
      packet.pcp = action.vlan_pcp
    def strip_vlan(action, packet):
      if not isinstance(packet, vlan): packet = vlan(packet)
      packet.pcp = action.vlan_pcp
    def set_dl_src(action, packet):
      packet.src = action.dl_addr
    def set_dl_dst(action, packet):
      packet.dst = action.dl_addr
    def set_nw_src(action, packet):
      if(isinstance(packet, ipv4)):
        packet.nw_src = action.nw_addr
    def set_nw_dst(action, packet):
      if(isinstance(packet, ipv4)):
        packet.nw_dst = action.nw_addr
    def set_nw_tos(action, packet):
      if(isinstance(packet, ipv4)):
        packet.tos = action.nw_tos
    def set_tp_src(action, packet):
      if(isinstance(packet, udp) or isinstance(packet, tcp)):
        packet.srcport = action.tp_port
    def set_tp_dst(action, packet):
      if(isinstance(packet, udp) or isinstance(packet, tcp)):
        packet.dstport = action.tp_port
    def enqueue(action, packet):
      self.log.warn("output_enqueue not supported yet. Performing regular output")
      output_packet(action.tp_port, packet)

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
        OFPAT_ENQUEUE: enqueue
    }
    for action in actions:
      if(action.type not in handler_map):
        raise NotImplementedError("Unknown action type: %x " % type)
      handler_map[action.type](action, packet)

  def __repr__(self):
    return "SwitchImpl(dpid=%d, num_ports=%d)" % (self.dpid, len(self.ports))

class ControllerConnection (object):
  # Unlike of_01.Connection, this is persistent (at least until we implement a proper
  # recoco Connection Listener loop)
  # Globally unique identifier for the Connection instance
  ID = 0

  def msg (self, m):
    #print str(self), m
    self.log.debug(str(self) + " " + str(m))
  def err (self, m):
    #print str(self), m
    self.log.error(str(self) + " " + str(m))
  def info (self, m):
    pass
    #print str(self), m
    self.log.info(str(self) + " " + str(m))

  def __init__ (self, sock, ofp_handlers):
    self.sock = sock
    self.buf = ''
    ControllerConnection.ID += 1
    self.ID = ControllerConnection.ID
    self.log = core.getLogger("ControllerConnection(id=%d)" % self.ID)
    ## OpenFlow Message map
    self.ofp_msgs = make_type_to_class_table()
    ## Hash from ofp_type -> handler(packet)
    self.ofp_handlers = ofp_handlers

  def fileno (self):
    return self.sock.fileno()

  def send (self, data):
    """
    Send raw data to the controller.

    Generally, data is a bytes object. If not, we check if it has a pack()
    method and call it (hoping the result will be a bytes object).  This
    way, you can just pass one of the OpenFlow objects from the OpenFlow
    library to it and get the expected result, for example.
    """
    # TODO: this is taken directly from of_01.Connection. Refoactor to reduce
    # redundancy
    if type(data) is not bytes:
      if hasattr(data, 'pack'):
        data = data.pack()

    if deferredSender.sending:
      self.log.debug("deferred sender is sending!")
      deferredSender.send(self, data)
      return
    try:
      l = self.sock.send(data)
      if l != len(data):
        self.msg("Didn't send complete buffer.")
        data = data[l:]
        deferredSender.send(self, data)
    except socket.error as (errno, strerror):
      if errno == EAGAIN:
        self.msg("Out of send buffer space.  Consider increasing SO_SNDBUF.")
        deferredSender.send(self, data)
      else:
        self.msg("Socket error: " + strerror)
        self.disconnect()

  def read (self):
    """
    Read data from this connection.

    Note: if no data is available to read, this method will block. Only invoke
    after select() has returned this socket.
    """
    # TODO: this is taken directly from of_01.Connection. The only difference is the
    # event handlers. Refactor to reduce redundancy.
    d = self.sock.recv(2048)
    if len(d) == 0:
      return False
    self.buf += d
    l = len(self.buf)
    while l > 4:
      if ord(self.buf[0]) != OFP_VERSION:
        self.log.warning("Bad OpenFlow version (" + str(ord(self.buf[0])) +
                    ") on connection " + str(self))
        return False
      # OpenFlow parsing occurs here:
      ofp_type = ord(self.buf[1])
      packet_length = ord(self.buf[2]) << 8 | ord(self.buf[3])
      if packet_length > l: break
      msg = self.ofp_msgs[ofp_type]()
      msg.unpack(self.buf)
      self.buf = self.buf[packet_length:]
      l = len(self.buf)
      try:
        if ofp_type not in self.ofp_handlers:
          raise RuntimeError("No handler for ofp_type %d" % ofp_type)

        h = self.ofp_handlers[ofp_type]
        h(msg)
      except Exception as e:
        self.log.exception(e)
        #self.log.exception("%s: Exception while handling OpenFlow message:\n%s %s",
        #              self,self,("\n" + str(self) + " ").join(str(msg).split('\n')))
        continue
    return True

  def disconnect(self):
    # not yet implemented
    pass

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
    self.flow_stats = True
    self.table_stats = True
    self.port_stats = True
    self.stp = True
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
