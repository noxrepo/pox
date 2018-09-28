# Copyright 2013,2017 James McCauley
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
DHCP Client stuff
"""

from pox.core import core
log = core.getLogger()

import pox.lib.packet as pkt

from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.revent import EventMixin, Event
import pox.lib.recoco as recoco

import pox.openflow.libopenflow_01 as of

import time
import random


class DHCPOffer (Event):
  """
  Fired when an offer has been received

  If you want to immediately accept it, do accept().
  If you want to reject it, do reject().
  If you want to defer acceptance, do nothing.
  """
  def __init__ (self, p):
    super(DHCPOffer,self).__init__()

    self.offer = p

    self.address = p.yiaddr
    self.server = p.siaddr
    o = p.options.get(p.SERVER_ID_OPT)
    if o: self.server = o.addr

    o = p.options.get(p.SUBNET_MASK_OPT)
    self.subnet_mask = o.addr if o else None
    o = p.options.get(p.ROUTERS_OPT)
    self.routers = o.addrs if o else []
    o = p.options.get(p.DNS_SERVER_OPT)
    self.dns_servers = o.addrs if o else []
    o = p.options.get(p.REQUEST_LEASE_OPT)
    o = o.seconds if o is not None else 86400 # Hmmm...

    self._accept = None

  def reject (self):
    self._accept = False

  def accept (self):
    self._accept = True

  def option (self, option, default=None):
    return self.offer.options.get(option, default=None)


class DHCPOffers (Event):
  """
  Fired when all offers in time window have been received
  """
  def __init__ (self, offers):
    super(DHCPOffers,self).__init__()
    self.offers = offers
    self.accepted = None

  def accept (self, offer):
    assert offer in self.offers
    self.accepted = offer


class DHCPLeased (Event):
  """
  Fired when a lease has been confirmed
  """
  def __init__ (self, lease):
    super(DHCPLeased,self).__init__()
    # Lease is the appropriate offer.
    self.lease = lease


class DHCPClientError (Event):
  pass


class DHCPClientBase (EventMixin):
  """
  A DHCP client

  Currently doesn't do lots of stuff "right" according the RFC2131 Section 4.4,
  and the state/timeout management is pretty bad.  It does mostly serve to get
  you an address under simple circumstances, though.
  Feel free to add improvements!
  """
  """
  TODO:
  * Renew
  * Keep track of lease times
  """
  """
  Usage (subclasses):
  * Implement _send_data()
  * Call _rx() with packets
  Usage (consumers):
  * Set .state = INIT
  * Handle events
  """

  _eventMixin_events = set([DHCPOffer, DHCPOffers, DHCPLeased,
                            DHCPClientError])

  _xid = random.randint(1000,0xffFFffFF)

  TOTAL_TIMEOUT = 8
  OFFER_TIMEOUT = 2
  REQUEST_TIMEOUT = 2
  DISCOVER_TIMEOUT = 2

  # Client states
  INIT = 'INIT'
  INIT_REBOOT = 'INIT_REBOOT'
  SELECTING = 'SELECTING'
  REBOOTING = 'REBOOTING'
  REQUESTING = 'REQUESTING'
  REBINDING = 'REBINDING'
  BOUND = 'BOUND'
  RENEWING = 'RENEWING'

  # Not real DHCP states
  NEW = '<NEW>'
  ERROR = '<ERROR>'
  IDLE = '<IDLE>'

  # Parameters to request (in discover)
  param_requests = [
    pkt.DHCP.DHCPDNSServersOption,
    pkt.DHCP.DHCPRoutersOption,
    pkt.DHCP.DHCPSubnetMaskOption,
  ]

  #FIXME: install_flows doesn't belong here?
  def __init__ (self,
                port_eth = None,
                auto_accept = False,
                install_flows = True,
                offer_timeout = None,
                request_timeout = None,
                total_timeout = None,
                discovery_timeout = None,
                name = None):

    # Eth addr of port
    self.port_eth = port_eth

    # Accept first offer?
    # If True the first non-rejected offer is used immediately, without
    # waiting for the offer_timeout window to close.
    self.auto_accept = auto_accept

    self.install_flows = install_flows

    if name is None:
      self.log = log
    else:
      self.log = core.getLogger(name)

    self._state = self.NEW
    self._start = None

    # We keep track of all offers we received
    self.offers = []

    # XID that messages should have to us should have
    self.offer_xid = None
    self.ack_xid = None

    ### Accepted offer
    ##self.accepted = None

    # Requested offer
    self.requested = None

    # Bound offer
    self.bound = None

    # How long to wait total
    self.total_timeout = total_timeout or self.TOTAL_TIMEOUT
    self.total_timer = None

    # How long to wait for the first offer following a discover
    # If we don't hear one, we'll resend the discovery
    self.discover_timeout = discovery_timeout or self.DISCOVER_TIMEOUT
    self.discover_timer = None

    # How long to wait for offers after the first one
    self.offer_timeout = offer_timeout or self.OFFER_TIMEOUT
    self.offer_timer = None

    # How long to wait for ACK/NAK on requested offer
    self.request_timeout = request_timeout or self.REQUEST_TIMEOUT
    self.request_timer = None

    # We add and remove the PacketIn listener.  This is its event ID
    self._packet_listener = None

  def _total_timeout (self):
    # If this goes off and we haven't finished, tell the user we failed
    self.log.warn('Did not complete successfully')
    self.state = self.ERROR

  @property
  def _secs (self):
    return time.time() - self._start

  @property
  def state (self):
    return self._state

  @state.setter
  def state (self, state):
    old = self._state

    self.log.debug("Transition: %s -> %s", old, state)

    def killtimer (name):
      name += '_timer'
      a = getattr(self, name)
      if a is not None:
        a.cancel()
      setattr(self, name, None)

    def set_state (s, debug = None, warn = None, info = None):
      def state_setter ():
        if debug: self.log.debug(debug)
        if warn: self.log.debug(warn)
        if info: self.log.debug(info)
        self.state = s
      return state_setter


    if old == self.INIT:
      killtimer('discover')
    elif old == self.SELECTING:
      killtimer('offer')
    elif old == self.REQUESTING:
      killtimer('request')
      self.requested = None

    self._state_transition(old, state)

    self._state = state

    if state == self.INIT:
      assert old in (self.NEW,self.INIT)
      # We transition INIT->INIT when discovery times out
      if old == self.NEW:
        # In this case, we want to set a total timeout
        killtimer('total')
        self.total_timer = recoco.Timer(self.total_timeout,
                                        self._do_total_timeout)
        self._start = time.time()
      self._discover()
      self.discover_timer = recoco.Timer(self.discover_timeout,
                                         set_state(self.INIT))
    elif state == self.SELECTING:
      assert old == self.INIT
      self.offer_timer = recoco.Timer(self.offer_timeout,
                                      self._do_accept)
    elif state == self.REQUESTING:
      assert old == self.SELECTING
      assert self.requested
      self._request()
      self.request_timer = recoco.Timer(self.request_timeout,
                                        set_state(self.INIT,info='Timeout'))
    elif state == self.BOUND:
      killtimer('total')
      ev = DHCPLeased(self.bound)
      routers = ','.join(str(g) for g in self.bound.routers)
      if not routers: routers = "(No routers)"
      self.log.info("Got %s/%s -> %s",
                    self.bound.address, self.bound.subnet_mask, routers)

      self.raiseEventNoErrors(ev)
      #TODO: Handle expiring leases

    elif state == self.ERROR:
      #TODO: Error info
      self.raiseEventNoErrors(DHCPClientError())

  def _state_transition (self, old, state):
    pass

  def _do_total_timeout (self):
    self.log.error('Did not successfully bind in time')
    self.state = self.ERROR

  def _add_param_requests (self, msg):
    req = pkt.DHCP.DHCPParameterRequestOption(self.param_requests)
    msg.add_option(req)

  def _discover (self):
    self.offers = []

    msg = pkt.dhcp()
    self._add_param_requests(msg)

    self.offer_xid = self._send(msg, msg.DISCOVER_MSG)

  def _request (self):
    msg = pkt.dhcp()
    msg.siaddr = self.requested.server
    #self._add_param_requests(msg)
    msg.add_option(pkt.DHCP.DHCPServerIdentifierOption(msg.siaddr))
    msg.add_option(pkt.DHCP.DHCPRequestIPOption(self.requested.address))
    self.request_xid = self._send(msg, msg.REQUEST_MSG)

  @classmethod
  def _new_xid (cls):
    if cls._xid == 0xffffFFFF:
      cls._xid = 0
    else:
      cls._xid += 1

    return cls._xid

  def _send (self, msg, msg_type):
    msg.flags |= msg.BROADCAST_FLAG
    msg.htype = 1
    msg.hlen = 6
    msg.op = msg.BOOTREQUEST
    msg.secs = self._secs
    msg.xid = self._new_xid()
    msg.chaddr = self.port_eth

    #if msg.siaddr != pkt.ipv4.IP_ANY:
    #  msg.add_option(pkt.DHCP.DHCPServerIdentifierOption(self.msg.siaddr))
    msg.add_option(pkt.DHCP.DHCPMsgTypeOption(msg_type))

    self._send_dhcp(msg)

    return msg.xid

  def _send_dhcp (self, msg):
    ethp = pkt.ethernet(src=self.port_eth, dst=pkt.ETHER_BROADCAST)
    ethp.type = pkt.ethernet.IP_TYPE
    ipp = pkt.ipv4()
    ipp.srcip = pkt.IP_ANY #NOTE: If rebinding, use existing local IP?
    ipp.dstip = pkt.IP_BROADCAST
    ipp.protocol = ipp.UDP_PROTOCOL
    udpp = pkt.udp()
    udpp.srcport = pkt.dhcp.CLIENT_PORT
    udpp.dstport = pkt.dhcp.SERVER_PORT
    udpp.payload = msg
    ipp.payload = udpp
    ethp.payload = ipp
    self._send_data(ethp.pack())

  def _send_data (self, data):
    raise RuntimeError("_send_data() unimplemented")

  def _rx (self, parsed):
    """
    Input packet here
    """
    # Is it to us?  (Or at least not specifically NOT to us...)
    ipp = parsed.find('ipv4')
    if not ipp or not ipp.parsed:
      return
    if self.bound and self.bound.address == ipp.dstip:
      pass # Okay.
    elif ipp.dstip not in (pkt.IP_ANY,pkt.IP_BROADCAST):
      return
    p = parsed.find('dhcp')
    if p is None:
      return
    if not isinstance(p.prev, pkt.udp):
      return
    udpp = p.prev
    if udpp.dstport != pkt.dhcp.CLIENT_PORT:
      return
    if udpp.srcport != pkt.dhcp.SERVER_PORT:
      return
    if p.op != p.BOOTREPLY:
      return
    t = p.options.get(p.MSG_TYPE_OPT)
    if t is None:
      return

    if t.type == p.OFFER_MSG:
      if p.xid != self.offer_xid:
        if self.state in (self.INIT,self.SELECTING):
          self.log.info('Received offer with wrong XID')
        else:
          self.log.debug('Received unexpected offer with wrong XID')
        return
      if self.state == self.INIT:
        # First offer switches states
        self.state = self.SELECTING
      if self.state != self.SELECTING:
        self.log.warn('Recieved an offer while in state %s', self.state)
        return
      self._exec_offer(p)
    elif t.type in (p.ACK_MSG, p.NAK_MSG):
      if p.xid != self.request_xid:
        if self.state in (self.REQUESTING):
          self.log.info('Received ACK/NAK with wrong XID')
        else:
          self.log.debug('Received unexpected ACK/NAK with wrong XID')
        return
      if self.state != self.REQUESTING:
        self.log.warn('Recieved an ACK/NAK while in state %s', self.state)
        return
      if t.type == p.NAK_MSG:
        self._exec_request_nak(p)
      else:
        self._exec_request_ack(p)

  def _exec_offer (self, p):
    o = DHCPOffer(p)
    self.offers.append(o)
    self.raiseEventNoErrors(o)

    if self.auto_accept and (o._accept is not False):
      # Good enough!
      o._accept = True
      self._do_accept()

  def _exec_request_ack (self, p):
    self.bound = self.requested
    self.state = self.BOUND

  def _exec_request_nak (self, p):
    self.log.warn('DHCP server NAKed our attempted acceptance of an offer')

    # Try again...
    self.state = INIT

  def _do_accept (self):
    ev = DHCPOffers(self.offers)
    for o in self.offers:
      if o._accept is True:
        ev.accepted = o
        break
    if ev.accepted is None:
      for o in self.offers:
        if o._accept is not False:
          ev.accepted = o
          break

    self.raiseEventNoErrors(ev)

    #TODO: Properly decline offers

    if ev.accepted is None:
      self.log.info('No offer accepted')
      self.state = self.IDLE
      return

    self.requested = ev.accepted

    self.state = self.REQUESTING


class OFDHCPClient (DHCPClientBase):
  """
  DHCP client via an OpenFlow switch
  """

  """
  TODO:
  * Bind port_name -> port_no later?
  """

  def __init__ (self, dpid, port, **kw):
    """
    Initializes

    port_eth can be True to use the MAC associated with the port by the
      switch, None to use the 'dpid MAC', or an EthAddr.
    """
    self.port_name = port

    if hasattr(dpid, 'dpid'):
      dpid = dpid.dpid
    self.dpid = dpid

    super(OpenFlowDHCPClient,self).__init__(**kw)

    self._try_start()
    if self.state != self.INIT:
      self._listen_for_connection()

  def _handle_PacketIn (self, event):
    if event.dpid != self.dpid: return
    if event.port != self.portno: return
    self._rx(event.parsed)

  def _send_data (self, data):
    po = of.ofp_packet_out(data=data)
    po.actions.append(of.ofp_action_output(port=self.portno))
    self._send_of(po)

  def _send_of (self, data):
    return core.openflow.connections[self.dpid].send(data)

  def _handle_ConnectionUp (self, event):
    self._try_start()

  def _listen_for_connection (self):
    core.openflow.addListenerByName('ConnectionUp', self._handle_ConnectionUp,
                                    once = True)

  def _try_start (self):
    if self.state != self.NEW:
      return

    dpid = self.dpid
    port = self.port_name

    con = core.openflow.connections.get(dpid, None)

    if con is None:
      #raise RuntimeError('DPID %s not connected' % (dpid_to_str(dpid),))
      self._listen_for_connection()
      return

    if isinstance(port, str):
      if port not in con.ports:
        self.log.error('No such port as %s.%s' % (dpid_to_str(dpid), port))
        #raise RuntimeError('No such port as %s.%s' % (dpid_to_str(dpid),port))
        self.state = self.ERROR
        return
      self.portno = con.ports[port].port_no

    if self.port_eth is None:
      self.port_eth = con.eth_addr
    elif self.port_eth is True:
      self.port_eth = con.ports[port].hw_addr

    self.state = self.INIT

  def _state_transition (self, old, state):
    # Make sure we're seeing packets if needed...

    def get_flow (broadcast = False):
      fm = of.ofp_flow_mod()
      if broadcast:
        fm.match.dl_dst = pkt.ETHER_BROADCAST
      else:
        fm.match.dl_dst = self.port_eth
      fm.match.in_port = self.portno
      fm.match.dl_type = pkt.ethernet.IP_TYPE
      fm.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
      fm.match.tp_src = pkt.dhcp.SERVER_PORT
      fm.match.tp_dst = pkt.dhcp.CLIENT_PORT
      fm.priority += 1
      return fm

    if state not in (self.IDLE, self.ERROR, self.BOUND):
      if self._packet_listener is None:
        self._packet_listener = core.openflow.addListenerByName('PacketIn',
            self._handle_PacketIn)
        if self.install_flows:
          fm = get_flow(False)
          fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
          self._send_of(fm)
          fm = get_flow(True)
          fm.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
          self._send_of(fm)
    else:
      if self._packet_listener is not None:
        core.openflow.removeListener(self._packet_listener)
        self._packet_listener = None
        if self.install_flows:
          fm = get_flow(False)
          fm.command = of.OFPFC_DELETE_STRICT
          self._send_of(fm)
          fm = get_flow(True)
          fm.command = of.OFPFC_DELETE_STRICT
          self._send_of(fm)


def launch (dpid, port, port_eth = None, name = None, __INSTANCE__ = None):
  """
  Launch

  port_eth unspecified: "DPID MAC"
  port_eth enabled: Port MAC
  port_eth specified: Use that
  """
  if port_eth in (True, None):
    pass
  else:
    port_eth = EthAddr(port_eth)

  dpid = str_to_dpid(dpid)
  try:
    port = int(port)
  except:
    pass

  def dhcpclient_init ():
    n = name
    if n is None:
      s = ''
      while True:
        if not core.hasComponent("DHCPClient" + s):
          n = "DHCPClient" + s
          break
        s = str(int('0' + s) + 1)
    else:
      if core.hasComponent(n):
        self.log.error("Already have component %s", n)
        return

    client = OFDHCPClient(port=port, dpid=dpid, name=n, port_eth=port_eth)
    core.register(n, client)

  core.call_when_ready(dhcpclient_init, ['openflow'])
