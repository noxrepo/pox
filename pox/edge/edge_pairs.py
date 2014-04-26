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
An edge-based pairs switch

This example component takes a bunch of OVS instances connected by tunnels and
turns them into one big learning switch using a technique much like l2_pairs.

Run like:
./pox.py edge_pairs --ips=172.16.0.x,172.16.0.y

Configure the OVS instances to have tunnels along the lines of:
ovs-vsctl add-port br0 tun0 -- set Interface tun0 type=gre \
  options:remote_ip=flow

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
  )

from pox.openflow.libopenflow_01 import (
  ofp_flow_mod,
  ofp_action_output,
  ofp_port_mod,
  ofp_packet_out,
  OFPP_FLOOD,
  OFPPC_NO_FLOOD,
  )


HARD_TIMEOUT  = 30
IDLE_TIMEOUT  = 5
FLOOD_TIMEOUT = 10


class Switch (object):
  """
  Represents one actual edge switch
  """
  def __init__ (self, edge_core, dpid):
    self.dpid = dpid       # DPID of this edge switch
    self.tun_port = None   # Port number which leads to other switches
    self.ip = None         # Our tunnel port IP
    self.log = core.getLogger("es:" + dpid_to_str(dpid))
    self.core = edge_core  # The EdgeSwitchCore

    self.connection = None # Connection to switch or None
    self.listeners = None  # Current listeners on connection

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
    #po.actions.append(nx_reg_load(dst=NXM_NX_TUN_ID, value=1)) # Mark as disco
    po.actions.append(ofp_action_output(port=self.tun_port))

    # It doesn't really matter what we send here; why not send LLDP?
    port_addr = self.connection.ports[self.tun_port].hw_addr
    data = LLDPSender._create_discovery_packet(self.dpid, self.tun_port,
                                               port_addr, 120)
    po.data = data.pack()
    self.connection.send(po)

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

    self.log.info("Switch configured")

  def update_ports (self):
    if not self.connection: return

    for p in self.connection.ports.values():
      if p.name.startswith("tun"):
        try:
          dummy = int(p.name[3:])
        except:
          pass

        if p.port_no != self.tun_port:
          self.log.debug("Tunnel port %s is OF port %s", p.name, p.port_no)
        self.tun_port = p.port_no

        self.setup_switch()
        break

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


    def flood_actions (include_tunnel):
      """
      Builds an action list for flooding, possibly including remote switches
      """
      actions = []
      actions.append(ofp_action_output(port = OFPP_FLOOD))

      # We've disabled flooding on the tunnel.  If the packet came from the
      # tunnel, we don't want to send it back out.  But if it's local we
      # do want to send it to all the other edge switches.
      if include_tunnel:
        for sw in self.core.switches.values():
          if sw is self: continue
          if sw.ip is None: continue

          actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(sw.ip)))
          actions.append(ofp_action_output(port = self.tun_port))

      return actions


    if from_tunnel:
      self._handle_discovery(event) # Doesn't actually matter if it is

      if packet.dst == pkt.ETHERNET.NDP_MULTICAST:
        # It was to us.  Don't deliver it to anyone.
        return
    else:
       # Learn the source
      self.core.table[packet.src] = (self.dpid,event.port)


    if packet.dst.is_multicast:
      # Just install a flow to handle this src/dst pair for a while
      msg = ofp_flow_mod(data = event.ofp)
      msg.match.dl_dst = packet.dst
      msg.match.dl_src = packet.src
      msg.match.in_port = event.port
      msg.hard_timeout = FLOOD_TIMEOUT
      msg.actions = flood_actions(not from_tunnel)
      event.connection.send(msg)
      #self.log.debug("Flood multicast (%s actions)", len(msg.actions))
    else: # Unicast
      r = self.core.table.get(event.parsed.dst)
      if r is None:
        # We don't know where the destination is yet.  So, we'll just
        # send the packet out all ports (except the one it came in on!)
        # and hope the destination is out there somewhere. :)
        # We actually install the flow for one second so that a torrent of
        # packets to a nonexistent destination won't keep coming to the
        # controller.  If we do actually discover the destination, this will
        # be overridden because we install it at lower priority.
        msg = ofp_flow_mod()
        msg.priority -= 1
        msg.data = event.ofp # Forward the incoming packet
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.match.in_port = event.port
        msg.hard_timeout = 1
        msg.actions = flood_actions(not from_tunnel)

        event.connection.send(msg)
        #self.log.debug("%s->%s Flood unknown", packet.src, packet.dst)
      else:
        dst_dpid,dst_port = r

        # Packets we like: From a local port and to anywhere, or from a remote
        # port and to a local port.
        if dst_dpid != self.dpid and from_tunnel:
          # We got a packet from a remote switch which isn't to us!
          # We don't want it!
          #self.log.debug("Drop to bad dest")
          return

        # We know the destination, so we can obviously install the forward
        # rule, which we do below.  We also obviously know the source, so
        # we can proactively install the reverse rule too.  We could also leave
        # that out and just deal with it reactively when/if the destination
        # replies.
        # Also, note that we include input ports on all these rules.  It
        # probably doesn't really matter if we do or not.

        # This is the reverse direction
        msg = ofp_flow_mod()
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.hard_timeout = HARD_TIMEOUT
        msg.idle_timeout = IDLE_TIMEOUT
        if from_tunnel:
          # Packet came from the tunnel
          # Reverse: go TO the tunnel
          assert dst_dpid == self.dpid
          msg.in_port = dst_port
          # The following line is the only reason we need to use Nicira
          # packet-ins besides tunnel-port IP discovery.  And as mentioned
          # above, we could actually leave out this reverse case altogether.
          msg.actions.append(nx_reg_load(
                dst=NXM_NX_TUN_IPV4_DST(event.ofp.match.tun_ipv4_src)))
          msg.actions.append(ofp_action_output(port = self.tun_port))
        elif dst_dpid == self.dpid:
          # Packet came from local port and goes to local port
          # Reverse: Goes from one local to another
          msg.in_port = dst_port
          msg.actions.append(ofp_action_output(port = event.port))
        else:
          # Packet came from local port and goes to tunnel
          # Reverse: Packet comes from tunnel and goes to local port
          msg.in_port = self.tun_port
          msg.actions.append(ofp_action_output(port = event.port))
        event.connection.send(msg)

        # This is the packet that just came in -- we want to
        # install the forward rule and also resend the packet.
        msg = ofp_flow_mod()
        msg.data = event.ofp # Forward the incoming packet
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.hard_timeout = HARD_TIMEOUT
        msg.idle_timeout = IDLE_TIMEOUT
        msg.in_port = event.port
        if dst_dpid == self.dpid:
          # This is to a local port
          msg.actions.append(ofp_action_output(port = dst_port))
          #self.log.debug("%s->%s to local port %s",
          #               packet.src, packet.dst, dst_port)
        else:
          # This is to another switch
          ip = self.core.switches[dst_dpid].ip
          if ip is None:
            #self.log.warn("Don't know destination IP for %s yet",
            #              dpid_to_str(dst_dpid))
            # Just kill it for a while
            msg.hard_timeout = 1
            msg.idle_timeout = 1
            msg.priority -= 1
          else:
            msg.actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(ip)))
            msg.actions.append(ofp_action_output(port = self.tun_port))
            #self.log.debug("%s->%s to remote port %s.%s via %s", packet.src,
            #               packet.dst, dst_dpid, dst_port, ip)

        event.connection.send(msg)

        self.log.debug("Installing %s <-> %s" % (packet.src, packet.dst))



class EdgeSwitchCore (object):
  """
  The EdgeSwitch component
  """
  MAX_DISCOVERY_BACKOFF = 10

  def __init__ (self, ips):
    self.ips = ips        # IPs the tunnel ports on the switches.  The user
                          # told us these, but didn't tell us which switch
                          # actually goes with which IP.  We discover that.

    self.switches = {}    # dpid->Switch
    self.table = {}       # MAC->(dpid,port)

    core.listen_to_dependencies(self)

    # How long between discovery attempts (backs off exponentially up to
    # MAX_DISCOVERY_BACKOFF)
    self.discovery_timer_period = 0.5

    self._send_discovery()

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

  def _handle_openflow_ConnectionDown (self, event):
    if event.dpid in self.switches:
      self.switches[event.dpid].disconnect()

  def _handle_openflow_PortStatus (self, event):
    self.switches[event.dpid].update_ports()



def launch (ips):
  """
  Initialize the edge switch component

  ips is a list of the IPs of the tunnel endpoints.  We'll figure out which
  IP goes with with switch automatically.
  """
  global log
  log = core.getLogger()

  import pox.openflow.nicira
  pox.openflow.nicira.launch(convert_packet_in = True)

  #TODO: Support an "auto" IPs mode, where we grab the source IP from each
  #      OpenFlow connection and assume that can be used as a tunnel?  (Won't
  #      work in Mininet, since they'll all have the same source IP.)
  ips = [IPAddr(x) for x in ips.replace(",", " ").split()]

  core.registerNew(EdgeSwitchCore, ips)
