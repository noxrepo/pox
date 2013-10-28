# toll_way_l3.py
# Copyright 2013 Xeonkung
#
# This file is part of POX.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
A stupid L3 switch

For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
import pprint
import sqlite3
import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

tree = {}

tollway_port = {}

ipTable = defaultdict(lambda:defaultdict(lambda:None))

tollway_rule = []
lastTID = 0

db_path = '/Users/xeonkung/Documents/KMUTNB/Programing/tollway/tollway.db'

# Toll way priority
TOLLWAY_PRIORITY = 40000 # OFP_DEFAULT_PRIORITY = 32768

# Timeout for flows
FLOW_IDLE_TIMEOUT = 60

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5

def test_table ():
  print ipTable

def _toll_way_daemon():
  # log.debug("run daemon...")

  rules = []
  global tollway_rule
  global lastTID
  # get new rule
  conn = sqlite3.connect(db_path)
  c = conn.cursor()
  q = "SELECT * FROM ticket WHERE ruleEnd > %i AND t_id > %i" % (time.time() - 100000, lastTID)
  # print q
  c.execute(q)
  for row in c:
    rule = {}
    rule['t_id'] = row[0]
    rule['end'] = row[1]
    rule['ip_src'] = str(row[2])
    rule['ip_dst'] = str(row[3])
    rule['tp_src'] = row[4]
    rule['tp_dst'] = row[5]
    tollway_rule.append(rule)
    lastTID = rule['t_id']
    print row
  while len(tollway_rule) > 0:
    rule = tollway_rule.pop()
    if rule['end'] < time.time():
      # kill rule
      continue
    else:
      if not _mod_tollway(rule):
        rules.append(rule)
        log.debug("\tt_id( %i ) unknown normal way" % rule['t_id'])
        
  tollway_rule = rules

def _mod_tollway(rule):
  # Check normal way
  global ipTable
  for conn in core.openflow.connections:
    dpid = conn.dpid
    # log.debug("_mod_tollway %i" % dpid)
    if rule.get('ip_src') is not None:
      if not dpid in ipTable:
        return False
      if not IPAddr(rule.get('ip_src')) in ipTable[dpid]:
        return False
    if rule.get('ip_dst') is not None:
      if not dpid in ipTable:
        return False
      if not IPAddr(rule.get('ip_dst')) in ipTable[dpid]:
        return False
  # Now we have know normal way path
  for conn in core.openflow.connections:
    dpid = conn.dpid
    if rule.get('ip_dst') is not None:
      entry = ipTable[dpid][IPAddr(rule.get('ip_dst'))]
      if tollway_port[dpid][entry.port] is not None:
        #msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = IPAddr(rule.get('ip_dst'))
        if rule.get('ip_src') is not None: msg.match.nw_src = IPAddr(rule.get('ip_src'))
        if rule.get('tp_src') is not None: msg.match.tp_src = rule.get('tp_src')
        if rule.get('tp_dst') is not None: msg.match.tp_dst = rule.get('tp_dst')
        if rule.get('end') is not None: msg.hard_timeout = int(rule.get('end') - time.time())
        msg.priority = TOLLWAY_PRIORITY
        port = tollway_port[dpid][entry.port]
        msg.actions.append(of.ofp_action_output(port = port))
        conn.send(msg)
        print msg
        log.debug("sw %i install %s --> p %i" % ( dpid, rule.get('ip_dst'), port ))
      else:
        # SW hasn't tollway port for this flow
        pass
    else:
      # wildcard
      pass
    if rule.get('ip_src') is not None:
      entry = ipTable[dpid][IPAddr(rule.get('ip_src'))]
      if tollway_port[dpid][entry.port] is not None:
        # SW has tollway port
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = IPAddr(rule.get('ip_src'))
        if rule.get('ip_dst') is not None: msg.match.nw_src = IPAddr(rule.get('ip_dst'))
        if rule.get('tp_dst') is not None: msg.match.tp_src = rule.get('tp_dst')
        if rule.get('tp_src') is not None: msg.match.tp_dst = rule.get('tp_src')
        if rule.get('end') is not None: msg.hard_timeout = int(rule.get('end') - time.time())
        msg.priority = TOLLWAY_PRIORITY
        port = tollway_port[dpid][entry.port]
        msg.actions.append(of.ofp_action_output(port = port))
        conn.send(msg)
        log.debug("sw %i install %s --> p %i" % ( dpid, rule.get('ip_src'), port ))
      else:
        # SW hasn't tollway port for this flow
        pass
  return True

# def _install_toll_way (port, dst):


def _calc_tree():
  """
  Calculates the actual spanning tree

  Returns it as dictionary where the keys are DPID1, and the
  values are tuples of (DPID2, port-num), where port-num
  is the port on DPID1 connecting to DPID2.
  """
  def flip (link):
    return Discovery.Link(link[2],link[3], link[0],link[1])

  adj = defaultdict(lambda:defaultdict(lambda:[]))
  normal = defaultdict(lambda:defaultdict(lambda:None))
  tollway = defaultdict(lambda:defaultdict(lambda:None))
  switches = set()
  # tollway port
  tp = defaultdict(lambda:defaultdict(lambda:None))

  # Add all links and switches
  for l in core.openflow_discovery.adjacency:
    adj[l.dpid1][l.dpid2].append(l)
    switches.add(l.dpid1)
    switches.add(l.dpid2)

  # Cull links -- we want a single symmetric link connecting nodes
  for s1 in switches:
    for s2 in switches:
      if s2 not in adj[s1]:
        continue
      if not isinstance(adj[s1][s2], list):
        continue
      assert s1 is not s2
      for l in adj[s1][s2]:
        if flip(l) in core.openflow_discovery.adjacency:
          # This is Full Duplex Link
          if normal[s1][s2] is None:
            normal[s1][s2] = l.port1
            normal[s2][s1] = l.port2
          elif tollway[s1][s2] is None:
            tollway[s1][s2] = l.port1
            tollway[s2][s1] = l.port2
            # add toll way port
            tp[s1][normal[s1][s2]] = l.port1
            tp[s2][normal[s2][s1]] = l.port2 


  # cal normal tree
  q = []
  more = set(switches)

  done = set()

  nTree = defaultdict(set)
  
  while True:
    q = sorted(list(more)) + q
    more.clear()
    if len(q) == 0: break
    v = q.pop(False)
    if v in done: continue
    done.add(v)
    for w,p in normal[v].iteritems():
      if w in nTree: continue
      more.add(w)
      nTree[v].add((w,p))
      nTree[w].add((v,normal[w][v]))

  global tree
  tree = nTree

  global tollway_port
  tollway_port = tp
  # log.debug("Finish _calc_tree()")

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout

def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = ipTable

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    self.listenTo(core)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpidToStr(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    #self.listenTo(core.openflow)
    core.openflow.addListeners(self, priority=0)
    core.openflow_discovery.addListeners(self)
    log.debug("Up...")

  def _handle_LinkEvent (self, event):
    # log.debug("Link Up...")
    _calc_tree()

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    is_tollway = False
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = defaultdict(lambda:defaultdict(lambda:None))
      # Get User FIX port

      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
      else:
        log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # Try to forward
      dstaddr = packet.next.dstip
      if dstaddr in self.arpTable[dpid]:
        # We have info about what port to send it out on...

        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, str(dstaddr)))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          match = of.ofp_match.from_packet(packet, inport)
          match.dl_src = None # Wildcard source MAC

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               inport))
          event.connection.send(msg.pack())
      elif self.arp_for_unknowns:
        # We don't know this destination.
        # First, we track this buffer so that we can try to resend it later
        # if we learn the destination, second we ARP for the destination,
        # which should ultimately result in it responding and us learning
        # where it is

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        # Expire things from our outstanding ARP list...
        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.iteritems() if v > time.time()}

        # Check if we've already ARPed recently
        if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
          return

        # And ARP...
        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.in_port = inport
        # Send to every port Not FLOOD
        tree_ports = [p[1] for p in tree.get(event.dpid, [])]

        for p in event.connection.ports:
          if p >= of.OFPP_MAX:
            # Not a normal port
            continue

          if not core.openflow_discovery.is_edge_port(event.dpid, p):
            # If the port isn't a switch-to-switch port, it's fine to flood
            # through it.  But if it IS a switch-to-switch port, we only
            # want to use it if it's on the spanning tree.
            if p not in tree_ports:
              continue

          msg.actions.append(of.ofp_action_output(port = p))
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
            else:
              log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                if not self.arpTable[dpid][a.protodst].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

      # msg = of.ofp_packet_out(in_port = inport, action = of.ofp_action_output(port = of.OFPP_FLOOD))
      msg = of.ofp_packet_out()
      msg.in_port = inport
      # Send to every port Not FLOOD
      tree_ports = [p[1] for p in tree.get(event.dpid, [])]
      for p in event.connection.ports:
          if p >= of.OFPP_MAX: continue
          if not core.openflow_discovery.is_edge_port(event.dpid, p):
            if p not in tree_ports: continue
          msg.actions.append(of.ofp_action_output(port = p))

      if event.ofp.buffer_id is of.NO_BUFFER:
        # Try sending the (probably incomplete) raw data
        msg.data = event.data
      else:
        msg.buffer_id = event.ofp.buffer_id
      event.connection.send(msg.pack())


def launch (fakeways="", arp_for_unknowns=None):
  def start():
    core.registerNew(l3_switch, fakeways, arp_for_unknowns)
    log.info("Toll Way Mod switch running.")
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.call_when_ready(start, "openflow_discovery")
  Timer(10, _toll_way_daemon, recurring = True)
  

