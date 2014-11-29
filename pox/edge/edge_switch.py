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
An edge-based big switch

This example component takes a bunch of OVS instances connected by tunnels and
turns them into one big learning switch.  Almost everything is implemented on
the switches themselves; the one exception is that the controller helps to set
up flooding.  See "How it all works" in this file for more.

There are, of course, all sorts of improvements that you could make to this.
Also, by reading this, you are now an official member of the QA team and are
tasked with finding all the many bugs.

Run like:
./pox.py edge_switch --ips=172.16.0.x,172.16.0.y

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

See edge_pairs for a similar but more reactive version.
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


How it all works
================

Uses the tunnel ID to store metadata in the format:

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Unused    |    SPort    |    DPort    |OP |F|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

OP identifies the packet's command/operation/whatever.  OP_OUT means to output
the packet.  OP_LRN means the receiver should learn the packet's source
address.  OP_ADV is an advertisement of one edge switch to another (currently
this is actually used so that the controller can learn the IPs associated
with the switch tunnel ports).

F is the flood flag.  If it's set, the sender is flooding this packet because
it doesn't know where the destination is.  If the destination gets this packet
and the F bit is set, it should notify the sender so that it can learn the
destination.

SPort and DPort are ports numbers.  The SPort contains the port number on
the sending switch from which the packet originated.  DPort varies depending
on OP.  Special value MFLOOD means to flood out all ports (same as OFPP_FLOOD,
but that doesn't fit in the DPort field).

The below is a shorthand explanation of the tables we use.  A lot of them are
basically used like programming language functions.

tdip is the tunnel_dst_ip
tsip is the tunnel_src_ip
tid is the tunnel_id

ENTER
F,OP,SPort,DPort = tid, tid.SPort=in_port, tid.DPort=0, tid.F=0, EXECUTE


EXECUTE
in_port == tun_port and op == ADV: controller
in_port == tun_port and op == LRN: REMOTE_LEARN
in_port == tun_port and op == OUT: REMOTE_LEARN, REMOTE_DELIVER, MAYBE_NOTIFY
in_port == tun_port: nothing # rest are only for local ports
multicast: LOCAL_LEARN, flood(), tid.DPort=MFLOOD, tid.OP=OP_OUT,
           SEND_REMOTE_FLOOD # learn notification this might send isn't valuable
!multicast: LOCAL_LEARN, DO_DELIVER_LOCAL


REMOTE_DELIVER - Sends a remote packet out local port specified DPort
DPort == MFLOOD: flood()
*: output(DPort)

REMOTE_LEARN - Learns a remote src MAC address/port
*: LOAD_SRC, learn(MACPARMx: PORTPARM=SPort, tdip=tsip to REMOTE_MACS)

DO_DELIVER_LOCAL - Deliver a packet from a local port
*: LOAD_DST, LOCAL_MACS, DO_DELIVER_LOCAL_1

DO_DELIVER_LOCAL_1
- Here, we try to deliver it to a local port
PORTPARM == 0: /*LOAD_DST,*/ REMOTE_MACS, DO_DELIVER_LOCAL_2
*: output(PORTPARM)

DO_DELIVER_LOCAL_2
- Here we deliver remotely or fail and flood it
PORTPARM == 0: flood(), tid.DPort=MFLOOD, tid.F=1, tid.OP=OP_OUT,
               SEND_REMOTE_FLOOD
* : tid.DPort=PORTPARM, tid.OP=OP_OUT, output(tun_port)

SEND_REMOTE_FLOOD - Output packet to each other switch
- Currently populated by the controller
- tid should already be set
*: tdip = a1, output(tun_port), tdip = a2, output(tun_port), ... # Controller

MAYBE_NOTIFY - Alert sender that we have a MAC/port it doesn't know.
- If a packet didn't know the destination (F=1) and the destination is local
  to us, set src=dst and send it back with OP=LRN.
- Alters the packet, so must be done last
- The tun_dst_ip must still be set correctly
F == 0: nothing # It already knows where it is
*: LOAD_DST, LOCAL_MACS, MAYBE_NOTIFY_1

MAYBE_NOTIFY_1
PORTPARM == 0: nothing # We don't know where it is
*: tid.SPort=PORTPARM, src_mac=dst_mac,
   tid.OP=LRN, output(in_port/tun_port), exit

LOAD_SRC - Load packet src ethaddr into MACPARMx
*: MACPARM1=src_mac[0:31],MACPARM2=src_mac[32:48]

LOAD_DST - Load packet dst ethaddr into MACPARMx
*: MACPARM1=dst_mac[0:31],MACPARM2=dst_mac[32:48]

LOCAL_MACS - Look up port number for MACPARMx
- Returns port number or 0 in PORTPARM
- Except catch-all, populated by learn action
MACPARMx == y: PORTPARM=<port where y lives> # From learn action
...
*: PORTPARM=0

REMOTE_MACS - Look up tdip and port for MACPARMx
- Returns port in PORTPARM and sets tdip or 0 for both on failure
- Except catch-all, populated by learn action
MACPARMx == y: PORTPARM=<port for y>, tdip=<ip for y> # From learn action
...
*: PORTPARM=0, tdip=0

LOCAL_LEARN - Learn to LOCAL_MACS and send notifications
*: LOAD_SRC, LOCAL_MACS, LOCAL_LEARN_1

LOCAL_LEARN_1
PORTPARM == 0: learn(MACPARMx: PORTPARM=SPort to LOCAL_MACS, timeout=T),
               tid.OP=LRN, SEND_REMOTE_FLOOD
"""

from pox.core import core

import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.openflow.nicira as ovs

from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.recoco import Timer
from pox.openflow.discovery import LLDPSender

from pox.openflow.nicira import (
  NXM_NX_TUN_ID,
  nx_reg_move,
  nx_reg_load,
  NXM_NX_TUN_IPV4_DST,
  NXM_NX_TUN_IPV4_SRC,
  NXM_OF_IN_PORT,
  nx_action_learn,
  NXM_OF_ETH_DST,
  NXM_OF_ETH_SRC,
  nx_output_reg,
  nx_action_exit,
  nx_flow_mod,
  )

from pox.openflow.libopenflow_01 import (
  OFPP_FLOOD,
  ofp_action_output,
  OFPFC_DELETE,
  ofp_port_mod,
  OFPPC_NO_FLOOD,
  ofp_packet_out,
  OFPP_IN_PORT,
  )

# Shortcuts
nx_resubmit = ovs.nx_action_resubmit.resubmit_table
nx_controller = ovs.nx_action_controller



LOCAL_TIMEOUT   = 0
REMOTE_TIMEOUT  = 0


# For the metadata in tun_id, we set up a bunch of handy "constants"...

def make_mask (size, offset):
  return ((2**size)-1)<<offset

def regreg (name, nbits, offset):
  globals()[name+"_SIZE"] = nbits
  globals()[name+"_OFFS"] = offset
  globals()[name+"_MASK"] = make_mask(nbits, offset)

TUN_ID_SIZE = 24
PORTSIZE = 7 # Number of bits to use for ports
MFLOOD = make_mask(PORTSIZE, 0)

regreg('F', 1, 0)
regreg('OP', 2, F_SIZE)

regreg('DPort', PORTSIZE, F_SIZE + OP_SIZE)
regreg('SPort', PORTSIZE, F_SIZE + OP_SIZE + DPort_SIZE)


# Nicer names for registers we use...

rPORTPARM = ovs.NXM_NX_REG1
rMACPARM1 = ovs.NXM_NX_REG2
rMACPARM2 = ovs.NXM_NX_REG3

rF = ovs.NXM_NX_REG4
rOP = ovs.NXM_NX_REG6
rSPort = ovs.NXM_NX_REG7
rDPort = ovs.NXM_NX_REG5


# Names for the operations...

OP_ADV = 1
OP_LRN = 2
OP_OUT = 3


# Names for our tables...

all_tables = {n:i for i,n in enumerate("""
ENTER
EXECUTE

REMOTE_DELIVER
DO_DELIVER_LOCAL
 DO_DELIVER_LOCAL_1
 DO_DELIVER_LOCAL_2

MAYBE_NOTIFY
 MAYBE_NOTIFY_1

REMOTE_LEARN
LOCAL_LEARN
 LOCAL_LEARN_1

LOAD_SRC
LOAD_DST

SEND_REMOTE_FLOOD

LOCAL_MACS
REMOTE_MACS
""".strip().split())}

for n,i in all_tables.items():
  globals()[n] = i

# Handy for debugging...
#bkwd = {v:k for k,v in all_tables.items()}
#for i in sorted(bkwd.keys()):
#  print "%-23s %s" % (bkwd[i],i)



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
    Sends an OP_ADV switch advertisement

    This actually is currently sort of useless except that it's how we
    automatically discover what *our own* tunnel port's IP address is
    (and we need to know these to set up the flood table).  We don't
    automatically know this, and requiring the user to tell us seems sort
    of annoying.  So switches send out advertisements.  When we GET one, we
    actually don't care about the content, but we can look at the tunnel
    IP metadata. :)
    """
    if not self.ready: return
    po = ofp_packet_out()
    po.actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(ip)))
    po.actions.append(nx_reg_load(dst=NXM_NX_TUN_ID, value=0))
    po.actions.append(nx_reg_load(value=OP_ADV, dst=NXM_NX_TUN_ID,
                                  offset=OP_OFFS, nbits=OP_SIZE))
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
    send(ovs.nx_packet_in_format())

    # Turn on ability to specify table in flow_mods
    send(ovs.nx_flow_mod_table_id())

    # I have an idea.  Let's install a whole bunch of tables, okay?

    with TableSender(con, table_id=ENTER) as table:
      table.clear = True
      table.entry(actions = [
        nx_reg_move(src=NXM_NX_TUN_ID, dst=rF, src_ofs=F_OFFS, nbits=F_SIZE),
        nx_reg_move(src=NXM_NX_TUN_ID, dst=rOP, src_ofs=OP_OFFS, nbits=OP_SIZE),
        nx_reg_move(src=NXM_NX_TUN_ID, dst=rSPort,
                    src_ofs=SPort_OFFS, nbits=SPort_SIZE),
        nx_reg_move(src=NXM_NX_TUN_ID, dst=rDPort,
                    src_ofs=DPort_OFFS, nbits=DPort_SIZE),

        nx_reg_load(dst=NXM_NX_TUN_ID, value=0, nbits = TUN_ID_SIZE),
        nx_reg_move(dst=NXM_NX_TUN_ID, src=NXM_OF_IN_PORT,
                    dst_ofs=SPort_OFFS, nbits=SPort_SIZE),
        nx_resubmit(EXECUTE),
      ])

    with TableSender(con, table_id=EXECUTE,
                     clear=True, order=True) as table:

      msg = table.entry()
      msg.match.in_port = self.tun_port
      msg.match.append( rOP(OP_ADV) )
      msg.actions.append( nx_controller() )

      msg = table.entry()
      msg.match.in_port = self.tun_port
      msg.match.append( rOP(OP_LRN) )
      msg.actions.append( nx_resubmit(REMOTE_LEARN) )

      msg = table.entry()
      msg.match.in_port = self.tun_port
      msg.match.append( rOP(OP_OUT) )
      msg.actions.append( nx_resubmit(REMOTE_LEARN) )
      msg.actions.append( nx_resubmit(REMOTE_DELIVER) )
      msg.actions.append( nx_resubmit(MAYBE_NOTIFY) )

      msg = table.entry()
      msg.match.in_port = self.tun_port

      msg = table.entry() # Multicast local
      msg.match.eth_dst = EthAddr("01:00:00:00:00:00")
      msg.match.eth_dst_mask = EthAddr("01:00:00:00:00:00")
      msg.actions = [
        nx_resubmit(LOCAL_LEARN),
        ofp_action_output(port=OFPP_FLOOD),
        nx_reg_load(dst=NXM_NX_TUN_ID, value=MFLOOD,
                    offset=DPort_OFFS, nbits=DPort_SIZE),
        nx_reg_load(value=OP_OUT, dst=NXM_NX_TUN_ID,
                    offset=OP_OFFS, nbits=OP_SIZE),
        nx_resubmit(SEND_REMOTE_FLOOD),
      ]

      msg = table.entry() # Non-Multicast local
      msg.actions = [
        nx_resubmit(LOCAL_LEARN),
        nx_resubmit(DO_DELIVER_LOCAL),
      ]

    with TableSender(con, table_id=REMOTE_DELIVER,
                     clear=True, order=True) as table:
      table.entry(action=ofp_action_output(port=OFPP_FLOOD)
                  ).match.append(rDPort(MFLOOD))
      table.entry(action = nx_output_reg(reg = rDPort))

    with TableSender(con, clear=True, table_id=REMOTE_LEARN) as table:
      learn = nx_action_learn(table_id=REMOTE_MACS, hard_timeout=REMOTE_TIMEOUT)
      learn.spec.chain(match = rMACPARM1, field = rMACPARM1).chain(
                       match = rMACPARM2, field = rMACPARM2).chain(
                       load = rPORTPARM, field = rSPort).chain(
                       load = NXM_NX_TUN_IPV4_DST, field = NXM_NX_TUN_IPV4_SRC)
      table.entry(actions=[nx_resubmit(LOAD_SRC), learn])

    with TableSender(con, clear=True, table_id=DO_DELIVER_LOCAL) as table:
      table.entry().actions = [
        nx_resubmit(LOAD_DST),
        nx_resubmit(LOCAL_MACS),
        nx_resubmit(DO_DELIVER_LOCAL_1),
      ]

    with TableSender(con, table_id=DO_DELIVER_LOCAL_1,
                     clear=True, order=True) as table:
      table.entry(actions = [
        nx_resubmit(REMOTE_MACS),
        nx_resubmit(DO_DELIVER_LOCAL_2),
      ]).match.append( rPORTPARM(0) )

      table.entry(action = nx_output_reg(reg = rPORTPARM))

    with TableSender(con, table_id=DO_DELIVER_LOCAL_2,
                     clear=True, order=True) as table:
      table.entry(actions = [
        ofp_action_output(port = OFPP_FLOOD),
        nx_reg_load(value=OP_OUT, dst=NXM_NX_TUN_ID,
                    offset=OP_OFFS, nbits=OP_SIZE),
        nx_reg_load(value = MFLOOD, dst = NXM_NX_TUN_ID,
                    offset = DPort_OFFS, nbits = DPort_SIZE),
        nx_reg_load(value = 1, dst = NXM_NX_TUN_ID,
                    offset = F_OFFS, nbits = F_SIZE),
        nx_resubmit(SEND_REMOTE_FLOOD),
      ]).match.append( rPORTPARM(0) )

      table.entry(actions = [
        nx_reg_move(src = rPORTPARM, dst = NXM_NX_TUN_ID,
                    dst_ofs = DPort_OFFS, nbits = DPort_SIZE),
        nx_reg_load(value=OP_OUT, dst=NXM_NX_TUN_ID,
                    offset=OP_OFFS, nbits=OP_SIZE),
        ofp_action_output(port=self.tun_port),
      ])

    with TableSender(con, table_id=SEND_REMOTE_FLOOD) as table:
      table.clear = True
      # Filled in later

    with TableSender(con, table_id=MAYBE_NOTIFY) as table:
      table.clear = True
      table.order = True
      table.entry().match.append( rF(0) )
      table.entry(actions = [
        nx_resubmit(LOAD_DST),
        nx_resubmit(LOCAL_MACS),
        nx_resubmit(MAYBE_NOTIFY_1),
      ])

    with TableSender(con, table_id=MAYBE_NOTIFY_1) as table:
      table.clear = True
      table.order = True
      table.entry().match.append( rPORTPARM(0) )
      table.entry(actions = [
        nx_reg_move(src=NXM_OF_ETH_DST, dst=NXM_OF_ETH_SRC),
        nx_reg_move(src=rPORTPARM, dst=NXM_NX_TUN_ID,
                    dst_ofs=SPort_OFFS, nbits=SPort_SIZE),
        nx_reg_load(value=OP_LRN, dst=NXM_NX_TUN_ID,
                    offset=OP_OFFS, nbits=OP_SIZE),
        ofp_action_output(port=OFPP_IN_PORT),
        nx_action_exit(),
      ])

    with TableSender(con, table_id=LOAD_SRC) as table:
      table.clear = True
      table.entry(actions = [
        nx_reg_move(src=NXM_OF_ETH_SRC, dst=rMACPARM1, nbits=32),
        nx_reg_move(src=NXM_OF_ETH_SRC, dst=rMACPARM2, nbits=16, src_ofs=32),
      ])

    with TableSender(con, table_id=LOAD_DST) as table:
      table.clear = True
      table.entry(actions = [
        nx_reg_move(src=NXM_OF_ETH_DST, dst=rMACPARM1, nbits=32),
        nx_reg_move(src=NXM_OF_ETH_DST, dst=rMACPARM2, nbits=16, src_ofs=32),
      ])

    with TableSender(con, table_id=LOCAL_MACS) as table:
      table.clear = True
      # Filled in by learning
      table.entry(action=nx_reg_load(dst=rPORTPARM,value=0), adj_priority=-1)

    with TableSender(con, table_id=REMOTE_MACS) as table:
      table.clear = True
      # Filled in by learning
      table.entry(adj_priority=-1, actions = [
        nx_reg_load(dst=rPORTPARM, value=0),
        nx_reg_load(dst=NXM_NX_TUN_IPV4_DST, value=0),
      ])

    with TableSender(con, table_id=LOCAL_LEARN) as table:
      table.clear = True
      table.entry(actions = [
        nx_resubmit(LOAD_SRC),
        nx_resubmit(LOCAL_MACS),
        nx_resubmit(LOCAL_LEARN_1),
      ])

    with TableSender(con, table_id=LOCAL_LEARN_1) as table:
      table.clear = True
      table.order = True

      learn = nx_action_learn(table_id=LOCAL_MACS, hard_timeout=LOCAL_TIMEOUT)
      learn.spec.chain(match = rMACPARM1, field = rMACPARM1).chain(
                       match = rMACPARM2, field = rMACPARM2).chain(
                       load = rPORTPARM, immediate = '\x00'*4).chain(# unneeded?
                       load = rPORTPARM, field = NXM_OF_IN_PORT, n_bits = 16)
      table.entry(actions = [
        learn,
        nx_reg_load(value=OP_LRN, dst=NXM_NX_TUN_ID,
                    offset=OP_OFFS, nbits=OP_SIZE),
        nx_resubmit(SEND_REMOTE_FLOOD),
      ]).match.append( rPORTPARM(0) )

    self.update_flood_rule()

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

  def _exec_ADV (self, event):
    """
    Handle an OP_ADV

    See send_discovery() for what this does and why.
    """
    if event.ofp.match.tun_ipv4_dst != self.ip:
      if self.ip is not None:
        self.log.warn("Tunnel IP changed")
      self.ip = event.ofp.match.tun_ipv4_dst
      self.log.debug("Discovered that tunnel is %s", self.ip)
      self.core.discover(self.ip, self.dpid)

  def _handle_PacketIn (self, event):
    if not self.ready: return
    if not isinstance(event.ofp, ovs.nxt_packet_in): return

    if event.port == self.tun_port:
      op = event.ofp.match.find(rOP)
      if op is not None: op = op.value

      if op == OP_ADV:
        self._exec_ADV(event)
        #print event.ofp
      else:
        self.log.warn("Unexpected tunnel packet with OP %s", op)
        #print event.ofp
    else:
      self.log.warn("Packet from unexpected port %s", event.port)
      #print event.ofp

  def update_flood_rule (self):
    """
    Update the flood rule (it needs to know about all the other switches)
    """
    if not self.ready: return

    # Set up the flood rule
    actions = []

    num = 0
    for sw in self.core.switches.values():
      if sw is self: continue
      if not sw.ip: continue
      num += 1
      actions.append(nx_reg_load(dst=NXM_NX_TUN_IPV4_DST(sw.ip)))
      actions.append(ofp_action_output(port = self.tun_port))

    msg = nx_flow_mod()
    msg.table_id = SEND_REMOTE_FLOOD
    msg.actions = actions

    self.connection.send(msg)

    self.log.debug("Updated flood rule (%s output%s)",num,"" if num==1 else "s")



class EdgeSwitchCore (object):
  """
  The EdgeSwitch component
  """

  def __init__ (self, ips):
    self.ips = ips        # IPs the tunnel ports on the switches.  The user
                          # told us these, but didn't tell us which switch
                          # actually goes with which IP.

    self.dpid_to_ip = {}  # Here's the missing mapping of switch to tunnel IP.
                          # These discovered via OP_ADV.
                          # (The RIGHT way to get them would probably be to
                          # query ovsdb, but that's future work.)

    core.listen_to_dependencies(self)

    self.switches = {}    # dpid->Switch

    # Send discovery messages (eventually stopped when we discover everything)
    self.discovery_timer = Timer(2.5, self._send_discovery, recurring=True)

  def _send_discovery (self):
    """
    Send discovery messages

    See EdgeSwitch.send_discovery() for more.
    """
    ips = set(self.ips).difference(self.dpid_to_ip.values())
    if not ips:
      self.discovery_timer.cancel()
      return

    for sw in self.switches.values():
      for ip in ips:
        sw.send_discovery(ip)

  def discover (self, ip, dpid):
    """
    Called when an EdgeSwitch gets a discovery message.

    See EdgeSwitch.send_discovery() for more.
    """
    assert ip in self.ips
    dirty = self.dpid_to_ip.get(dpid) != ip
    self.dpid_to_ip[dpid] = ip
    if len(self.ips) == len(self.dpid_to_ip):
      log.info("All datapaths discovered")
    if dirty:
      for sw in self.switches.values():
        sw.update_flood_rule()

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

  ovs.launch(convert_packet_in = True)

  #TODO: Support an "auto" IPs mode, where we grab the source IP from each
  #      OpenFlow connection and assume that can be used as a tunnel?  (Won't
  #      work in Mininet, since they'll all have the same source IP.)
  ips = [IPAddr(x) for x in ips.replace(",", " ").split()]

  core.registerNew(EdgeSwitchCore, ips)
