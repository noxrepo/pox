# Copyright 2013 James McCauley
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
A very quick and dirty DHCP server

This is currently missing lots of features and sort of limited with
respect to subnets and so on, but it's a start.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.addresses import IP_BROADCAST, IP_ANY
from pox.lib.revent import *
from pox.lib.util import dpid_to_str

log = core.getLogger()


def ip_for_event (event):
  """
  Use a switch's DPID as an EthAddr
  """
  eth = dpid_to_str(event.dpid,True).split("|")[0].replace("-",":")
  return EthAddr(eth)


class DHCPLease (Event):
  """
  Raised when a lease is given

  Call nak() to abort this lease
  """
  def __init__ (self, host_mac, ip):
    super(DHCPLease, self).__init__()
    self.host_mac = host_mac
    self.ip = ip
    self._nak = False

  def nak (self):
    self._nak = True


class AddressPool (object):
  """
  Superclass for DHCP address pools

  Note that it's just a subset of a list (thus, you can always just use
  a list as a pool).  The one exception is an optional "subnet_mask" hint.

  It probably makes sense to change this abstraction so that we can more
  easily return addresses from multiple ranges, and because some things
  (e.g., getitem) are potentially difficult to implement and not particularly
  useful (since we only need to remove a single item at a time).
  """
  def __init__ (self):
    """
    Initialize this pool.
    """
    pass

  def __contains__ (self, item):
    """
    Is this IPAddr in the pool?
    """
    return False

  def append (self, item):
    """
    Add this IP address back into the pool
    """
    pass

  def remove (self, item):
    """
    Remove this IPAddr from the pool
    """
    pass

  def __len__ (self):
    """
    Returns number of IP addresses in the pool
    """
    return 0

  def __getitem__ (self, index):
    """
    Get an IPAddr from the pool.

    Note that this will only be called with index = 0!
    """
    pass


class SimpleAddressPool (AddressPool):
  """
  Simple AddressPool for simple subnet based pools.
  """
  def __init__ (self, network = "192.168.0.0/24", first = 1, last = None,
                count = None):
    """
    Simple subnet-based address pool

    Allocates count IP addresses out of network/network_size, starting
    with the first'th.  You may specify the end of the range with either
    last (to specify the last'th address to use) or count to specify the
    number to use.  If both are None, use up to the end of all
    legal addresses.

    Example for all of 192.168.x.x/16:
      SimpleAddressPool("192.168.0.0/16", 1, 65534)
    """
    network,network_size = parse_cidr(network)

    self.first = first
    self.network_size = network_size
    self.host_size = 32-network_size
    self.network = IPAddr(network)

    if last is None and count is None:
      self.last = (1 << self.host_size) - 2
    elif last is not None:
      self.last = last
    elif count is not None:
      self.last = self.first + count - 1
    else:
      raise RuntimeError("Cannot specify both last and count")

    self.removed = set()

    if self.count <= 0: raise RuntimeError("Bad first/last range")
    if first == 0: raise RuntimeError("Can't allocate 0th address")
    if self.host_size < 0 or self.host_size > 32:
      raise RuntimeError("Bad network")
    if IPAddr(self.last | self.network.toUnsigned()) not in self:
      raise RuntimeError("Bad first/last range")

  def __repr__ (self):
    return str(self)

  def __str__ (self):
    t = self.network.toUnsigned()
    t = (IPAddr(t|self.first),IPAddr(t|self.last))
    return "<Addresses from %s to %s>" % t

  @property
  def subnet_mask (self):
    return IPAddr(((1<<self.network_size)-1) << self.host_size)

  @property
  def count (self):
    return self.last - self.first + 1

  def __contains__ (self, item):
    item = IPAddr(item)
    if item in self.removed: return False
    n = item.toUnsigned()
    mask = (1<<self.host_size)-1
    nm = (n & mask) | self.network.toUnsigned()
    if nm != n: return False
    if (n & mask) == mask: return False
    if (n & mask) < self.first: return False
    if (n & mask) > self.last: return False
    return True

  def append (self, item):
    item = IPAddr(item)
    if item not in self.removed:
      if item in self:
        raise RuntimeError("%s is already in this pool" % (item,))
      else:
        raise RuntimeError("%s does not belong in this pool" % (item,))
    self.removed.remove(item)

  def remove (self, item):
    item = IPAddr(item)
    if item not in self:
      raise RuntimeError("%s not in this pool" % (item,))
    self.removed.add(item)

  def __len__ (self):
    return (self.last-self.first+1) - len(self.removed)

  def __getitem__ (self, index):
    if index < 0:
      raise RuntimeError("Negative indices not allowed")
    if index >= len(self):
      raise IndexError("Item does not exist")
    c = self.first

    # Use a heuristic to find the first element faster (we hope)
    # Note this means that removing items changes the order of
    # our "list".
    c += len(self.removed)
    while c > self.last:
      c -= self.count

    while True:
      addr = IPAddr(c | self.network.toUnsigned())
      if addr not in self.removed:
        assert addr in self
        index -= 1
        if index < 0: return addr
      c += 1
      if c > self.last: c -= self.count


class DHCPD (EventMixin):
  _eventMixin_events = set([DHCPLease])
  _servers = []

  def __init__ (self, ip_address = "192.168.0.254", router_address = (),
                dns_address = (), pool = None, subnet = None,
                install_flow = True, dpid = None, ports = None):

    def fix_addr (addr, backup):
      if addr is None: return None
      if addr is (): return IPAddr(backup)
      return IPAddr(addr)

    self._install_flow = install_flow

    self.ip_addr = IPAddr(ip_address)
    self.router_addr = fix_addr(router_address, ip_address)
    self.dns_addr = fix_addr(dns_address, self.router_addr)

    if dpid is None:
      self.dpid = None
    else:
      try:
        dpid = int(dpid)
      except:
        dpid = util.str_to_dpid(dpid)
      self.dpid = dpid

    if ports is None:
      self.ports = None
    else:
      self.ports = set(ports)
    if self.ports:
      assert self.dpid is not None # Doesn't make sense
      self._servers.append(self)

    if pool is None:
      self.pool = [IPAddr("192.168.0."+str(x)) for x in range(100,199)]
      self.subnet = IPAddr(subnet or "255.255.255.0")
    else:
      self.pool = pool
      self.subnet = subnet
      if hasattr(pool, 'subnet_mask'):
        self.subnet = pool.subnet_mask
      if self.subnet is None:
        raise RuntimeError("You must specify a subnet mask or use a "
                           "pool with a subnet hint")

    self.lease_time = 60 * 60 # An hour
    #TODO: Actually make them expire :)

    self.offers = {} # Eth -> IP we offered
    self.leases = {} # Eth -> IP we leased

    if self.ip_addr in self.pool:
      log.debug("Removing my own IP (%s) from address pool", self.ip_addr)
      self.pool.remove(self.ip_addr)

    core.openflow.addListeners(self)

  @classmethod
  def get_server_for_port (cls, dpid, port):
    """
    Given a dpid.port, returns DHCPD instance responsible for it or None

    If there is a server, but the connection to the relevant switch is down,
    returns None.
    """
    for s in cls.servers:
      if s.dpid != dpid: continue
      conn = core.openflow.getConnection(s.dpid)
      if not conn: continue
      if s.ports is None: return s
      port_no = conn.ports.get(port)
      if port_no is None: continue
      port_no = port_no.port_no
      for p in s.ports:
        p = conn.ports.get(p)
        if p is None: continue
        if p.port_no == port_no:
          return s
    return None

  @classmethod
  def get_ports_for_dpid (cls, dpid):
    """
    Given a dpid, returns all port,server that are configured for it

    If the switch is disconnected, returns None.
    """
    r = set()
    for s in cls._servers:
      if s.dpid != dpid: continue
      conn = core.openflow.getConnection(s.dpid)
      if not conn: continue
      if s.ports is None:
        for p in conn.ports:
          r.add((p.port_no,s))
      else:
        for p in s.ports:
          p = conn.ports.get(p)
          if p is None: continue
          r.add((p.port_no,s))
    return r

  def _handle_ConnectionUp (self, event):
    if self.dpid is not None and self.dpid != event.dpid: return
    if self._install_flow:
      msg = self._get_flow_mod()
      event.connection.send(msg)

  def _get_flow_mod (self, msg_type=of.ofp_flow_mod):
    """
    Get flow mods that will send DHCP to the controller
    """
    #TODO: We might over-match right now since we don't limit by port
    msg = msg_type()
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    #msg.match.nw_dst = IP_BROADCAST
    msg.match.tp_src = pkt.dhcp.CLIENT_PORT
    msg.match.tp_dst = pkt.dhcp.SERVER_PORT
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    return msg

  def _get_pool (self, event):
    """
    Get an IP pool for this event.

    Return None to not issue an IP.  You should probably log this.
    """
    return self.pool

  def _handle_PacketIn (self, event):
    # Is it to us?  (Or at least not specifically NOT to us...)
    if self.dpid is not None and self.dpid != event.dpid: return
    if self.ports:
      for p in self.ports:
        if p == event.port: break
        if p in event.connection.ports:
          if event.connection.ports[p].port_no == event.port: break
      else:
        return
    ipp = event.parsed.find('ipv4')
    if not ipp or not ipp.parsed:
      return
    if ipp.dstip not in (IP_ANY,IP_BROADCAST,self.ip_addr):
      return

    # Is it full and proper DHCP?
    nwp = ipp.payload
    if not nwp or not nwp.parsed or not isinstance(nwp, pkt.udp):
      return
    if nwp.srcport != pkt.dhcp.CLIENT_PORT:
      return
    if nwp.dstport != pkt.dhcp.SERVER_PORT:
      return
    p = nwp.payload
    if not p:
      log.debug("%s: no packet", str(event.connection))
      return
    if not isinstance(p, pkt.dhcp):
      log.debug("%s: packet is not DHCP", str(event.connection))
      return
    if not p.parsed:
      log.debug("%s: DHCP packet not parsed", str(event.connection))
      return

    if p.op != p.BOOTREQUEST:
      return

    t = p.options.get(p.MSG_TYPE_OPT)
    if t is None:
      return

    pool = self._get_pool(event)
    if pool is None:
      return

    if t.type == p.DISCOVER_MSG:
      self.exec_discover(event, p, pool)
    elif t.type == p.REQUEST_MSG:
      self.exec_request(event, p, pool)
    elif t.type == p.RELEASE_MSG:
      self.exec_release(event, p, pool)

  def reply (self, event, msg):
    orig = event.parsed.find('dhcp')
    broadcast = (orig.flags & orig.BROADCAST_FLAG) != 0
    msg.op = msg.BOOTREPLY
    msg.chaddr = event.parsed.src
    msg.htype = 1
    msg.hlen = 6
    msg.xid = orig.xid
    msg.add_option(pkt.DHCP.DHCPServerIdentifierOption(self.ip_addr))

    ethp = pkt.ethernet(src=ip_for_event(event),dst=event.parsed.src)
    ethp.type = pkt.ethernet.IP_TYPE
    ipp = pkt.ipv4(srcip = self.ip_addr)
    ipp.dstip = event.parsed.find('ipv4').srcip
    if broadcast:
      ipp.dstip = IP_BROADCAST
      ethp.dst = pkt.ETHERNET.ETHER_BROADCAST
    ipp.protocol = ipp.UDP_PROTOCOL
    udpp = pkt.udp()
    udpp.srcport = pkt.dhcp.SERVER_PORT
    udpp.dstport = pkt.dhcp.CLIENT_PORT
    udpp.payload = msg
    ipp.payload = udpp
    ethp.payload = ipp
    po = of.ofp_packet_out(data=ethp.pack())
    po.actions.append(of.ofp_action_output(port=event.port))
    event.connection.send(po)

  def nak (self, event, msg = None):
    if msg is None:
      msg = pkt.dhcp()
    msg.add_option(pkt.DHCP.DHCPMsgTypeOption(msg.NAK_MSG))
    msg.siaddr = self.ip_addr
    self.reply(event, msg)

  def exec_release (self, event, p, pool):
    src = event.parsed.src
    if src != p.chaddr:
      log.warn("%s tried to release %s with bad chaddr" % (src,p.ciaddr))
      return
    if self.leases.get(p.chaddr) != p.ciaddr:
      log.warn("%s tried to release unleased %s" % (src,p.ciaddr))
      return
    del self.leases[p.chaddr]
    pool.append(p.ciaddr)
    log.info("%s released %s" % (src,p.ciaddr))

  def exec_request (self, event, p, pool):
    if not p.REQUEST_IP_OPT in p.options:
      # Uhhh...
      return
    wanted_ip = p.options[p.REQUEST_IP_OPT].addr
    src = event.parsed.src
    got_ip = None
    if src in self.leases:
      if wanted_ip != self.leases[src]:
        pool.append(self.leases[src])
        del self.leases[src]
      else:
        got_ip = self.leases[src]
    if got_ip is None:
      if src in self.offers:
        if wanted_ip != self.offers[src]:
          pool.append(self.offers[src])
          del self.offers[src]
        else:
          got_ip = self.offers[src]
    if got_ip is None:
      if wanted_ip in pool:
        pool.remove(wanted_ip)
        got_ip = wanted_ip
    if got_ip is None:
      log.warn("%s asked for un-offered %s", src, wanted_ip)
      self.nak(event)
      return

    assert got_ip == wanted_ip
    self.leases[src] = got_ip
    ev = DHCPLease(src, got_ip)
    self.raiseEvent(ev)
    if ev._nak:
      self.nak(event)
      return
    log.info("Leased %s to %s" % (got_ip, src))

    reply = pkt.dhcp()
    reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.ACK_MSG))
    reply.yiaddr = wanted_ip
    reply.siaddr = self.ip_addr

    wanted_opts = set()
    if p.PARAM_REQ_OPT in p.options:
      wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
    self.fill(wanted_opts, reply)

    self.reply(event, reply)

  def exec_discover (self, event, p, pool):
    reply = pkt.dhcp()
    reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.OFFER_MSG))
    src = event.parsed.src
    if src in self.leases:
      offer = self.leases[src]
      del self.leases[src]
      self.offers[src] = offer
    else:
      offer = self.offers.get(src)
      if offer is None:
        if len(pool) == 0:
          log.error("Out of IP addresses")
          self.nak(event)
          return

        offer = pool[0]
        if p.REQUEST_IP_OPT in p.options:
          wanted_ip = p.options[p.REQUEST_IP_OPT].addr
          if wanted_ip in pool:
            offer = wanted_ip
        pool.remove(offer)
        self.offers[src] = offer
    reply.yiaddr = offer
    reply.siaddr = self.ip_addr

    wanted_opts = set()
    if p.PARAM_REQ_OPT in p.options:
      wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
    self.fill(wanted_opts, reply)

    self.reply(event, reply)

  def fill (self, wanted_opts, msg):
    """
    Fill out some options in msg
    """
    if msg.SUBNET_MASK_OPT in wanted_opts:
      msg.add_option(pkt.DHCP.DHCPSubnetMaskOption(self.subnet))
    if msg.ROUTERS_OPT in wanted_opts and self.router_addr is not None:
      msg.add_option(pkt.DHCP.DHCPRoutersOption(self.router_addr))
    if msg.DNS_SERVER_OPT in wanted_opts and self.dns_addr is not None:
      msg.add_option(pkt.DHCP.DHCPDNSServersOption(self.dns_addr))
    msg.add_option(pkt.DHCP.DHCPIPAddressLeaseTimeOption(self.lease_time))


def default (no_flow = False,
            network = "192.168.0.0/24",            # Address range
            first = 100, last = 199, count = None, # Address range
            ip = "192.168.0.254",
            router = (),                   # Auto
            dns = ()):                     # Auto
  """
  Launch DHCP server defaulting to 192.168.0.100-199
  """
  launch(no_flow, network, first, last, count, ip, router, dns)


def launch (no_flow = False,
            network = "192.168.0.0/24",            # Address range
            first = 1, last = None, count = None, # Address range
            ip = "192.168.0.254",
            router = (),                   # Auto
            dns = (),                      # Auto
            dpid = None,                   # All
            ports = None,                  # All
            __INSTANCE__ = None):
  """
  Launch DHCP server

  Defaults to serving 192.168.0.1 to 192.168.0.253

  network  Subnet to allocate addresses from
  first    First'th address in subnet to use (256 is x.x.1.0 in a /16)
  last     Last'th address in subnet to use
  count    Alternate way to specify last address to use
  ip       IP to use for DHCP server
  router   Router IP to tell clients. Defaults to 'ip'. 'None' will
           stop the server from telling clients anything
  dns      DNS IP to tell clients.  Defaults to 'router'.  'None' will
           stop the server from telling clients anything.
  """
  def fixint (i):
    i = str(i)
    if i.lower() == "none": return None
    if i.lower() == "true": return None
    return int(i)
  def fix (i):
    i = str(i)
    if i.lower() == "none": return None
    if i.lower() == "true": return None
    if i == '()': return ()
    return i
  first,last,count = map(fixint,(first,last,count))
  router,dns = map(fix,(router,dns))

  if ports is not None:
    ports = ports.split(",")
    ports = set(int(p) if p.isdigit() else p for p in ports)

  pool = SimpleAddressPool(network = network, first = first, last = last,
                           count = count)

  inst = DHCPD(install_flow = not no_flow, pool = pool,
               ip_address = ip, router_address = router,
               dns_address = dns, dpid = dpid, ports = ports)

  if __INSTANCE__[0] == 0:
    # First or only instance
    core.register(inst)

  log.debug("DHCP serving a%s", str(pool)[2:-1])
