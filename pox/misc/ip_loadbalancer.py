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
An IP load balancer that allows user to select the load balancer algorithm and
the weights for each server.

Run it with --ip=<Service IP> --servers=IP1,IP2,...

By default, it will do load balancing on the first switch that connects.  If
you want, you can add --dpid=<dpid> to specify a particular switch.

Also by default, the load balancer algorithm will be random, if you want to 
change it, add --algorithm=<algorithm> (you can select random, round-robin or
least-bandwidth). You can select the weights for each server using
--weight=WEIGHT_IP1,WEIGHT_IP2,... in the same order as the servers.

If you run with py module, you will be able to change the algorithm any time,
using:
POX> change_algorithm(<algorithm>)
You can also change the weights for each server:
POX> change_weights({"IP1": WEIGHT1, ... })

Please submit improvements. :)
"""

from pox.core import core
import pox
import thread
log = core.getLogger("iplb")

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import EventRemove
from pox.lib.util import str_to_bool, dpid_to_str, str_to_dpid

# include as part of the betta branch
from pox.openflow.of_json import *

import pox.openflow.libopenflow_01 as of

import time
import random

FLOW_IDLE_TIMEOUT = 5
FLOW_MEMORY_TIMEOUT = 60 * 5
UPDATE_DATA_TRANSFERRED = 14

class MemoryEntry (object):
  """
  Record for flows we are balancing

  Table entries in the switch "remember" flows for a period of time, but
  rather than set their expirations to some long value (potentially leading
  to lots of rules for dead connections), we let them expire from the
  switch relatively quickly and remember them here in the controller for
  longer.

  Another tactic would be to increase the timeouts on the switch and use
  the Nicira extension which can match packets with FIN set to remove them
  when the connection closes.
  """
  def __init__ (self, server, first_packet, client_port):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return self.server,ipp.srcip,tcpp.dstport,tcpp.srcport

class iplb (object):
  """
  An IP load balancer

  Give it a service_ip and a list of server IP addresses.  New TCP flows
  to service_ip will be redirected to one of the servers using the selected 
  algorithm and using the weights map.

  We probe the servers to see if they're alive by sending them ARPs.
  """
  def __init__ (self, connection, algorithm, service_ip, weights, servers = []):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers]
    self.con = connection
    self.mac = self.con.eth_addr
    self.live_servers = {} # IP -> MAC,port
    self.algorithm = algorithm
    self.weights = weights

    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
      # Be nice to Python 2.6 (ugh)
      self.log = log

    self.outstanding_probes = {} # IP -> expire_time

    # How quickly do we probe?
    self.probe_cycle_time = 5

    # Last update in the map of data transferred.
    self.last_update = time.time()

    # Data transferred map (IP -> data transferred in the last 
    # UPDATE_DATA_TRANSFERRED seconds).
    self.data_transferred = {}
    for server in self.servers:
      self.data_transferred[server] = 0

    # Variables used in round-robin algorithm.
    self.round_robin_index = 0
    self.round_robin_pck_sent = 0

    # How long do we wait for an ARP reply before we consider a server dead?
    self.arp_timeout = 3

    # We remember where we directed flows so that if they start up again,
    # we can send them to the same server if it's still up.  Alternate
    # approach: hashing.
    self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry

    self._do_probe() # Kick off the probing

    # As part of a gross hack, we now do this from elsewhere
    #self.con.addListeners(self)

    # Allow user to change algorithm and weights at any time.
    core.Interactive.variables['change_algorithm'] = self._change_algorithm
    core.Interactive.variables['change_weights'] = self._change_weights

  def _change_algorithm(self, algorithm):
    """
    Change the algorithm for load balancing.
    """
    if algorithm not in ALGORITHM_LIST:
      log.error("Algorithm %s is not allowed, allowed algorithms: %s", 
        algorithm, ALGORITHM_LIST.keys())
    else:
      self.algorithm = algorithm
      log.info("Setting algorithm to %s.", self.algorithm)

  def _change_weights(self, weights):
    """
    Change the weights for each server in the balancing.
    """
    if type(weights) is not dict:
      log.error("Weigths should be a dictionary { IP: WEIGHT }.")
    elif sorted(weights.keys()) != sorted(self.weights.keys()):
      log.error("Weights needs to contains all servers")
    else:
      self.weights = { IPAddr(ip): weight for ip, weight in weights.items() }
      log.info("Setting weights to %s.", self.weights)

  def _do_expire (self):
    """
    Expire probes and "memorized" flows

    Each of these should only have a limited lifetime.
    """
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:
          self.log.warn("Server %s down", ip)
          del self.live_servers[ip]
          # Delete each entry in the table.
          del self.data_transferred[ip]
          del self.weights[ip]
          # Set the count of packet for round robin as 0.
          self.round_robin_pck_sent = 0

    # Expire old flows
    c = len(self.memory)
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory))

  def _do_probe (self):
    """
    Send an ARP to a server to see if it's still up
    """
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    r = max(.25, r) # Cap it at four per second
    return r

  def _pick_server (self, key, inport):
    """
    Pick a server for a (hopefully) new connection
    """
    self.log.debug("Balancing done by the %s algorithm.", self.algorithm)
    return ALGORITHM_LIST[self.algorithm](self)

  def _handle_PacketIn (self, event):
    inport = event.port
    packet = event.parsed

    def drop ():
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
              # Ah, nothing new here.
              pass
            else:
              # Ooh, new server.
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
              self.data_transferred[arpp.protosrc] = 0
              if arpp.protosrc not in self.weights.keys():
                self.weights[arpp.protosrc] = 1
              self.log.info("Server %s up", arpp.protosrc)
        return

      # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
      return drop()

    # It's TCP.
    ipp = packet.find('ipv4')

    # Update the data count table, if needed.
    if time.time() - self.last_update > UPDATE_DATA_TRANSFERRED:
      for server in self.data_transferred.keys():
        self.data_transferred[server] = 0
      self.last_update = time.time()

    if ipp.srcip in self.servers:
      # It's FROM one of our balanced servers.
      # Rewrite it BACK to the client

      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)

      if entry is None:
        # We either didn't install it, or we forgot about it.
        self.log.debug("No client for %s", key)
        return drop()

      # Refresh time timeout and reinstall.
      entry.refresh()
      #self.log.debug("Install reverse flow for %s", key)

      # Install reverse table entry
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      
      self.con.send(msg)

    elif ipp.dstip == self.service_ip:
      # Ah, it's for our service IP and needs to be load balanced
      # Do we already know this flow?
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)
      if entry is None or entry.server not in self.live_servers:
        # Don't know it (hopefully it's new!)
        if len(self.live_servers) == 0:
          self.log.warn("No servers!")
          return drop()

        # Pick a server for this flow
        server = self._pick_server(key, inport)
        self.log.debug("Directing traffic to %s", server)
        entry = MemoryEntry(server, packet, inport)
        self.memory[entry.key1] = entry
        self.memory[entry.key2] = entry

      # Update timestamp
      entry.refresh()

      # Set up table entry towards selected server
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      
      self.con.send(msg)

def round_robin_alg (balancer):
  """
  Select the next server for load balancing using the round-robin algorithm.
  """
  length = len(balancer.live_servers.keys())
  if balancer.round_robin_index >= length:
    balancer.round_robin_index = 0
  server_selected = list(balancer.live_servers.keys())[balancer.round_robin_index]
  balancer.round_robin_pck_sent = balancer.round_robin_pck_sent + 1
  
  if balancer.round_robin_pck_sent == balancer.weights[server_selected]:
    balancer.round_robin_index += 1
    balancer.round_robin_pck_sent = 0

  return server_selected

def least_bandwidth_alg (balancer):
  """
  Select the next server for load balancing using the least bandwidth algorithm.
  """
  length = len(balancer.live_servers.keys())
  servers = list(balancer.live_servers.keys())
  data_transferred = balancer.data_transferred
  weights = balancer.weights

  for i in range(length):
    if weights[servers[i]] > 0:
      best_server = servers[i]

      # Weighted least-bandwidth based on weighted least-connection scheduling
      # algorithm (see http://kb.linuxvirtualserver.org/wiki/Weighted_Least-Connection_Scheduling)
      for ii in range(i + 1, length):
        if data_transferred[best_server] * weights[servers[ii]] > \
         data_transferred[servers[ii]] * weights[best_server]:
          best_server = servers[ii]
      return best_server

def random_alg (balancer):
  """
  Select a random server for load balancer.
  """
  return random.choice(balancer.live_servers.keys())

# List of algorithms allowed in the load balancer.
ALGORITHM_LIST = { 
  'round-robin': round_robin_alg, 
  'least-bandwidth': least_bandwidth_alg, 
  'random': random_alg 
}

# Remember which DPID we're operating on (first one to connect)
_dpid = None

def launch (ip, servers, weights_val = [], dpid = None, algorithm = 'random'):
  global _dpid
  global _algorithm

  if dpid is not None:
    _dpid = str_to_dpid(dpid)

  if algorithm not in ALGORITHM_LIST:
    log.error("Algorithm %s is not allowed, allowed algorithms: %s", 
      algorithm, ALGORITHM_LIST.keys())
    exit(1)

  # Getting the servers IP.
  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]

  # Parsing the weights for each server.
  weights = {}
  if len(weights_val) is 0:
    weights_val = ""
    for x in servers:
      weights_val += "1,"

  weights_val = weights_val.replace(",", " ").split()

  if len(weights_val) is not len(servers):
    log.error("Weights array is not the same length than servers array")
    exit(1)

  for i in range(len(servers)):
    weights[servers[i]] = int(weights_val[i])

  # Getting the controller IP.
  ip = IPAddr(ip)

  # We only want to enable ARP Responder *only* on the load balancer switch,
  # so we do some disgusting hackery and then boot it up.
  from proto.arp_responder import ARPResponder
  old_pi = ARPResponder._handle_PacketIn

  def new_pi (self, event):
    if event.dpid == _dpid:
      # Yes, the packet-in is on the right switch
      return old_pi(self, event)
  ARPResponder._handle_PacketIn = new_pi

  # Hackery done.  Now start it.
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})

  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      _dpid = event.dpid

    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      if not core.hasComponent('iplb'):
        # Need to initialize first...
  
        core.registerNew(iplb, event.connection, algorithm, 
          IPAddr(ip), weights, servers)

        log.info("IP Load Balancer Ready.")
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)

  def _handle_FlowStatsReceived (event):
    for f in event.stats:
      ip_dst = f.match.nw_dst
      ip_src = f.match.nw_src

      if ip_dst != None and IPAddr(ip_dst) in core.iplb.servers:
        core.iplb.data_transferred[IPAddr(ip_dst)] += f.byte_count

      if ip_src != None and IPAddr(ip_src) in core.iplb.servers:
        core.iplb.data_transferred[IPAddr(ip_src)] += f.byte_count

  core.openflow.addListenerByName("FlowStatsReceived", _handle_FlowStatsReceived)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

  from pox.lib.recoco import Timer

  # Send the flow stats to all the switches connected to the controller.
  def _timer_func ():
    for connection in core.openflow._connections.values():
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  # Request flow stats every FLOW_IDLE_TIMEOUT second.
  Timer(FLOW_IDLE_TIMEOUT, _timer_func, recurring=True) 

