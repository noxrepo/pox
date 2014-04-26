# Copyright 2013,2014 James McCauley
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
An OpenFlow switch aggregator

This example component takes a bunch of OVS instances connected by tunnels
and then exposes them via OpenFlow to some other controller as if they were
all one big switch.

This is a very early prototype.

Run like:
./pox.py edge_pairs --ips=172.16.0.x,172.16.0.y

Configure the OVS instances to have tunnels along the lines of:
ovs-vsctl add-port br0 tun0 -- set Interface tun0 type=gre \
  options:remote_ip=flow

Then run another OpenFlow controller which the aggregate switch will connect
to.  It currently tries to connect to 127.0.0.1:7744, but you can adjust it
from the commandline.  So try something like:
./pox.py openflow.of_01 --port=7744 forwarding.l2_learning

This may require a recent (2.1.0+) version of OVS to work correctly.

The IPs are the IPs of the tunnel endpoints on the OVS instances. We do a
discovery thing to figure out which IP goes with which switch.

The tunnel interfaces should be named tunX where X is a number.  There should
only be one such interface per switch.  The tunnel type shouldn't really matter
as long as it has at least a 16 bit tunnel ID/key.

See "Using it with Mininet" later in this document for tips on setting up the
tunnels with Mininet.

See edge_switch for a similar but more proactive version.
"""

"""
Using it with Mininet
=====================

First, note that you may need to upgrade your version of Open vSwitch.  Try
2.1.0 or beyond if you have problems.

Fire up a topology with no links between the switches.  Add tunnels between
the switches.  I use the following (bad) base script:
#!/bin/bash
num=$1
echo Adding tunnels for $num switches
rmmod dummy
modprobe dummy numdummies=$((num+1))

for x in $(seq 1 $1); do
  ifconfig dummy$x 172.16.0.$x
  ovs-vsctl del-port s$x tun$x 2> /dev/null
  ovs-vsctl add-port s$x tun$x -- set Interface tun$x type=gre \
    options:remote_ip=flow options:local_ip=172.16.0.$x options:key=flow
done

This sets up tunnels with 172.16.0.x addresses.  I then pass these addresses
into the edge_switch component's --ips argument.
"""

from pox.core import core

import pox.lib.packet as pkt

from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
from pox.openflow.discovery import LLDPSender

from pox.openflow.nicira import (
  nx_reg_load,
  nx_packet_in_format,
  nxt_packet_in,
  NXM_NX_TUN_IPV4_DST,
  NXM_NX_TUN_ID,
  ofp_flow_mod_table_id,
  nx_flow_mod_table_id,
  nx_flow_mod,
  nx_action_resubmit,
  )

from pox.openflow.libopenflow_01 import (
  ofp_action_output,
  ofp_port_mod,
  ofp_packet_out,
  ofp_phy_port,
  OFPP_FLOOD,
  OFPP_ALL,
  OFPP_CONTROLLER,
  OFPP_MAX,
  OFPPC_NO_FLOOD,
  OFPPF_10MB_HD,
  OFPFC_DELETE,
  )

# Shortcuts
nx_resubmit = nx_action_resubmit.resubmit_table

from pox.datapaths import do_launch
from pox.datapaths.switch import SoftwareSwitchBase, OFConnection
from pox.datapaths.switch import ExpireMixin
import logging


# For the metadata in tun_id, we set up a bunch of handy "constants"...

TUN_ID_SIZE = 24
PORTSIZE = 8 # Number of bits to use for ports
MFLOOD = 0x7f
MALL = MFLOOD - 1


# Table IDs

# Just splits things between the other tables
ENTER_TABLE = 0

# Used to handle local delivery of remote packets
RX_REMOTE_TABLE = 1

# The actual normal OpenFlow table (equivalent of table 0)
OPENFLOW_TABLE = 2



class TableSender (object):
  """
  A helper for constructing tables

  Sends them for you!  Clears them!  Can order the entries!  Packs a bunch
  together into a single send() (can be a significant performance improvement)!
  Etc. Etc.!
  """
  def __init__ (self, connection, table_id = None, clear=False,
                order=False, priority=None, **kw):
    self._connection = connection
    self._fms = []
    self._entered = False
    self._done = False
    self.table_id = table_id
    self.order = order
    self.clear = clear
    self._priority = priority

  @property
  def last (self):
    return self._fms[-1]

  def entry (self, adj_priority=0, **kw):
    if self.table_id is not None:
      if 'table_id' not in kw:
        kw['table_id'] = self.table_id
    fm = nx_flow_mod(**kw)
    #if self._order is not False:
    #  fm.priority += self._order
    #  self._order += 1
    if self._priority is not None:
      fm.priority = self._priority
    fm.priority += adj_priority # Probably a bad idea if ordering
    self._fms.append(fm)
    return fm

  def __enter__ (self):
    assert not self._entered
    assert not self._done
    self._entered = True
    return self

  def __exit__ (self, type, value, tb):
    assert self._entered
    self._done = True
    if type is not None:
      # Exception -- do nothing
      return

    if self.order:
      for i,fm in enumerate(self._fms):
        fm.priority -= i

    if self.clear:
      fm = nx_flow_mod(command=OFPFC_DELETE, table_id=self.table_id)
      self._fms.insert(0, fm)

    data = b''.join(x.pack() for x in self._fms)
    self._connection.send(data)
    #self._connection.msg("sending %i entries" % (len(self._fms),))


class Switch (object):
  """
  Represents one actual edge switch
  """
  #TODO: We currently only really support packet-out and flow-mod commands.
  #      And we only send packet-ins up.

  def __init__ (self, edge_core, dpid):
    self.dpid = dpid       # DPID of this edge switch
    self.tun_port = None   # Port number which leads to other switches
    self.ip = None         # Our tunnel port IP
    self.log = core.getLogger("es:" + dpid_to_str(dpid))
    self.core = edge_core  # The EdgeSwitchCore

    self.connection = None # Connection to switch or None
    self.listeners = None  # Current listeners on connection

    # Currently this is sort of kept here and in the core.  It's a mess.
    self.ports = {} # ofp_phy_port -> unique number

  @property
  def ready (self):
    return (self.connection
            and self.tun_port
            and self.tun_port in self.connection.ports)

  def __str__ (self):
    return "EdgeSwitch(dpid=%s)" % (dpid_to_str(self.dpid))

  def send_discovery (self, ip):
    """
    Sends a switch advertisement

    This actually is currently sort of useless except that it's how we
    automatically discovery what *our own* tunnel port's IP address is
    (and we need to know these to set up the flood table).  We don't
    automatically know this, and requiring the user to tell us seems sort
    of annoying.  So switches send out advertisements.  When we GET one, we
    actually don't care about the content, but we can look at the tunnel
    IP metadata. :)
    """
    if not self.ready: return
    if ip == self.ip: return
    po = ofp_packet_out()
    po.actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(ip)))
    po.actions.append(nx_reg_load(dst=NXM_NX_TUN_ID(0))) # Invalid for output
    po.actions.append(ofp_action_output(port=self.tun_port))

    # It doesn't really matter what we send here; why not send LLDP?
    port_addr = self.connection.ports[self.tun_port].hw_addr
    data = LLDPSender._create_discovery_packet(self.dpid, self.tun_port,
                                               port_addr, 120)
    po.data = data.pack()
    self.connection.send(po)

  def send_packet_out (self, port_no, packet):
    if not self.ready: return
    po = ofp_packet_out(data = packet)
    po.actions.append(ofp_action_output(port = port_no))
    self.connection.send(po)

  def send_rx_remote_table (self):
    """
    We use a separate table to handle input from the tunnel port (which should
    become outputs locally)
    """
    if not self.ready: return

    con = self.connection
    with TableSender(con, table_id=RX_REMOTE_TABLE, clear=True) as table:
      for port,gport in self.ports.items():
        table.entry()
        table.last.actions.append( ofp_action_output(port=port.port_no) )
        table.last.match.tun_id = gport

      table.entry()
      table.last.match.tun_id = MALL
      table.last.actions.append( ofp_action_output(port=OFPP_ALL) )

      table.entry()
      table.last.match.tun_id = MFLOOD
      table.last.actions.append( ofp_action_output(port=OFPP_FLOOD) )

      table.entry()
      table.last.match.tun_id = 0
      # 0 is an invalid port value; we use it for our discovery packets
      table.last.actions.append( ofp_action_output(port=OFPP_CONTROLLER) )


  def send_table (self, table):
    """
    Translate flow table from aggswitch to this actual switch
    """

    fms = []
    fms.append(ofp_flow_mod_table_id(command=OFPFC_DELETE,
                                     table_id=OPENFLOW_TABLE))

    for entry in table.entries:
      #TODO: We should use cookie or something to associate entries in real
      #      tables with the entries in our own tables for statistics and such.
      fm = ofp_flow_mod_table_id()
      fms.append(fm)
      fm.table_id = OPENFLOW_TABLE
      fm.priority = entry.priority
      #TODO: flags, etc.?

      em = entry.match
      fm.match = em.clone()
      if em.in_port is not None:
        sw,in_port = self.core.port_map_rev.get(em.in_port,(None,None))
        if sw is not self:
          # This flow never originates on this switch -- forget it
          # (or we don't know this port at all?!)
          continue
        fm.match.in_port = in_port

      for a in entry.actions:
        if isinstance(a, ofp_action_output):
          if a.port >= OFPP_MAX: # Off by one?
            if a.port == OFPP_ALL or a.port == OFPP_FLOOD:
              #FIXME: If we don't propagate the port config bits to the actual
              #       ports, we probably need to translate them here.
              #FIXME: We can't actually use ALL here because that'd send to
              #       the tunnel port, which is not what we want.  We should
              #       break it out into individual output actions, but we
              #       currently just do FLOOD when told to do ALL.
              fm.actions.append(ofp_action_output(port=FLOOD))
              p = MALL if a.port == OFPP_ALL else MFLOOD
              fm.actions.append(nx_reg_load(value=p, dst=NXM_NX_TUN_ID))
              for rsw in self.core.switches:
                if rsw.ip is None: continue
                fm.actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(rsw.ip)))
                fm.actions.append(ofp_action_output(port=self.tun_port))
            else:
              #FIXME: LOCAL is meaningless and should probaby be stripped.
              #       We need special handling for IN_PORT (in case the
              #       in port is the tunnel).  What about the rest of them?
              #       For the moment, we'll just pretend things will be okay.
              fm.actions.append(a)
          else: # A plain old port
            osw,out_port = self.core.port_map_rev.get(a.port,(None,None))
            if osw is None:
              # Don't know this switch?!
              continue
            if osw is self:
              # Local port; easy.
              fm.actions.append(ofp_action_output(port=out_port))
            else:
              # Remote port
              fm.actions.append(nx_reg_load(value=out_port, dst=NXM_NX_TUN_ID))
              fm.actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(osw.ip)))
              fm.actions.append(ofp_action_output(port=self.tun_port))
        #TODO: Convert other actions?
        else:
          fm.actions.append(a)

    fm = ofp_flow_mod_table_id(table_id=OPENFLOW_TABLE)
    fm.priority = 0
    fm.actions.append(ofp_action_output(port=OFPP_CONTROLLER))
    fms.append(fm)

    data = b''.join(fm.pack() for fm in fms)
    self.connection.send(data)
    self.log.debug("Sent %s table entries", len(fms))

  def disconnect (self):
    if self.connection:
      self.connection.removeListeners(self.listeners)
      self.listeners = None
    self.connection = None

  def connect (self):
    self.disconnect()
    self.connection = core.openflow.connections[self.dpid]
    self.listeners = self.connection.addListeners(self)
    self.update_ports()

  def setup_switch (self):
    """
    Do some switch setup once we know tun_port
    """
    send = self.connection.send
    con = self.connection

    # Disable flood on tun port
    port = self.connection.ports[self.tun_port]
    send(ofp_port_mod(port_no = port.port_no,
                      hw_addr = port.hw_addr,
                      config  = OFPPC_NO_FLOOD,
                      mask    = OFPPC_NO_FLOOD))

    # Turn on Nicira packet-ins
    send(nx_packet_in_format())

    # Turn on ability to specify table in flow_mods
    send(nx_flow_mod_table_id())

    # Send the entry table
    with TableSender(con,table_id=ENTER_TABLE,order=True,clear=True) as table:
      table.entry()
      table.last.match.in_port = self.tun_port
      table.last.actions.append( nx_resubmit(RX_REMOTE_TABLE) )

      table.entry()
      table.last.actions.append( nx_resubmit(OPENFLOW_TABLE) )

    self.log.info("Switch configured")

  def update_ports (self):
    if not self.connection: return

    do_setup = False

    for p in self.connection.ports.values():
      if p.name.startswith("tun"):
        try:
          dummy = int(p.name[3:])
        except:
          pass

        if p.port_no != self.tun_port:
          self.log.debug("Tunnel port %s is OF port %s", p.name, p.port_no)
        self.tun_port = p.port_no

        do_setup = True
      else:
        if p not in self.ports:
          self.ports[p] = self.core.add_interface(self, p)
          #FIXME: The above doesn't deal correctly with ports that change
          #       properties

    if do_setup:
      self.setup_switch()

    #TODO: Only send this when necessary
    self.send_rx_remote_table()


  def _handle_discovery (self, event):
    """
    Handle a discovery packet

    See send_discovery() for what this does and why.
    """
    if event.ofp.match.tun_ipv4_dst != self.ip:
      if self.ip is not None:
        self.log.warn("Tunnel IP changed")
      self.ip = event.ofp.match.tun_ipv4_dst
      self.log.debug("Discovered that tunnel is %s", self.ip)

  def _handle_PacketIn (self, event):
    if not self.ready: return
    if not isinstance(event.ofp, nxt_packet_in): return
    packet = event.parsed
    from_tunnel = event.port == self.tun_port

    if from_tunnel:
      self._handle_discovery(event) # Doesn't actually matter if it is

      if event.ofp.match.tun_id not in (0, None):
        # We use the tun_id as the output port.  It *should* be zero since
        # if it's being sent to a port, it should have been handled at the
        # switch!
        self.log.warn("Got non-discovery from tunnel at controller")
        print event.ofp
      return

    # Translate in_port
    in_port = self.core.port_map.get((self, event.ofp.in_port))
    if in_port is None:
      self.log.warn("No port: %s", event.ofp.in_port)
      return

    self.core.rx_packet(event.parsed, in_port, event.data)
    self.log.debug("Translated packet-in")



class AggregateSwitch (ExpireMixin, SoftwareSwitchBase):
  # Default level for loggers of this class
  default_log_level = logging.INFO

  MAX_DISCOVERY_BACKOFF = 10


  def __init__ (self, **kw):
    """
    Create a switch instance

    Additional options over superclass:
    log_level (default to default_log_level) is level for this instance
    ports is a list of interface names
    """
    tunnel_ips = kw.pop('tunnel_ips')
    self.ips = tunnel_ips # IPs the tunnel ports on the switches.  The user
                          # told us these, but didn't tell us which switch
                          # actually goes with which IP.  We discover that.

    self.switches = {}    # dpid->Switch
    self.table = {}       # MAC->(dpid,port)



    log_level = kw.pop('log_level', self.default_log_level)

    core.addListeners(self)

    super(AggregateSwitch,self).__init__(**kw)

    self.log.setLevel(log_level)

    self.port_map = {} # (Switch,port_no) -> global port_no
    self.port_map_rev = {} # gport_no -> (Switch,port_no)

    core.listen_to_dependencies(self)

    self.table.addListenerByName("FlowTableModification", self._handle_flowmod)

    # How long between discovery attempts (backs off exponentially up to
    # MAX_DISCOVERY_BACKOFF)
    self.discovery_timer_period = 0.5

    self._send_discovery()


  def _output_packet_physical (self, packet, gport_no):
    sw,port_no = self.port_map_rev[gport_no]
    sw.send_packet_out(port_no, packet)

  def _handle_flowmod (self, event):
    """
    Fired when our flow table has been modified
    """
    # We need to update our flow tables on the south side
    log.debug("Translating flow table")
    for sw in self.switches.values():
      sw.send_table(self.table)

  def add_interface (self, switch, port):
    """
    Adds interface to agswitch and returns unique global port number
    """
    if (switch,port.port_no) in self.port_map:
      return self.port_map[switch,port.port_no]
    gport = len(self.port_map) + 1
    self.port_map[switch,port.port_no] = gport
    self.port_map_rev[gport] = (switch,port.port_no)

    #FIXME: What if this doesn't fit?
    name = "%s.%s" % (switch.dpid, port.name)

    phy = ofp_phy_port()
    phy.port_no = gport
    phy.hw_addr = port.hw_addr
    phy.name = name
    # Fill in features sort of arbitrarily
    phy.curr = OFPPF_10MB_HD
    phy.advertised = OFPPF_10MB_HD
    phy.supported = OFPPF_10MB_HD
    phy.peer = OFPPF_10MB_HD

    #TODO: Copy state and stuff

    self.add_port(phy)

    return len(self.port_map) # Global port number


  def _send_discovery (self):
    """
    Send discovery messages

    See EdgeSwitch.send_discovery() for more.
    """
    # This could be improved, possibly by using more of the actual
    # discovery component!
    for sw in self.switches.values():
      for ip in self.ips:
        sw.send_discovery(ip)

    self.discovery_timer_period *= 2
    if self.discovery_timer_period > self.MAX_DISCOVERY_BACKOFF:
      self.discovery_timer_period = self.MAX_DISCOVERY_BACKOFF
    core.callDelayed(self.discovery_timer_period, self._send_discovery)

  def _handle_openflow_ConnectionUp (self, event):
    if event.dpid not in self.switches:
      self.switches[event.dpid] = Switch(self, event.dpid)

    self.switches[event.dpid].connect()
    self.switches[event.dpid].send_table(self.table)

  def _handle_openflow_ConnectionDown (self, event):
    if event.dpid in self.switches:
      self.switches[event.dpid].disconnect()

  def _handle_openflow_PortStatus (self, event):
    self.switches[event.dpid].update_ports()



def launch (ips,
            address = '127.0.0.1', port = 7744, max_retry_delay = 16,
            dpid = None, extra = None
  ):
  """
  Initialize the switch aggregator component

  ips is a list of the IPs of the tunnel endpoints.  We'll figure out which
  IP goes with with switch automatically.

  address and port are the address of the controller we try to connect to.
  """

  global log
  log = core.getLogger()

  import pox.openflow.nicira
  pox.openflow.nicira.launch(convert_packet_in = True)

  # It'd be nice, but we don't currently try to use buffer_ids on the switches.
  # We'd need to A) translate their numbers (since they may not be unique), and
  # B) have a way to either shunt a buffer from one switch to another or to make
  # sure a packet-out (or the packet output portion of a flow-mod) makes it back
  # to the correct switch where the buffer actually lives.
  # This is too much work right now, so we just deal in full packets on the
  # south side.  On the north side we have our own buffer management.
  # (Actually this doesn't make any difference anymore because we use a low
  # priority send-to-controller in OPENFLOW_TABLE, but the basic issue raised
  # by the comment is still valid.)
  core.openflow.miss_send_len = 0x7fff


  #TODO: Support an "auto" IPs mode, where we grab the source IP from each
  #      OpenFlow connection and assume that can be used as a tunnel?  (Won't
  #      work in Mininet, since they'll all have the same source IP.)
  ips = [IPAddr(x) for x in ips.replace(",", " ").split()]

  def up (event):
    #global sw
    sw = do_launch(AggregateSwitch, address, port, max_retry_delay, dpid,
                   ports=[], extra_args=extra, tunnel_ips=ips)
    core.register("aggregate", sw)
  core.addListenerByName("UpEvent", up)


