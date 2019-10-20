from pox.misc.loadbalancing.base.iplb_base import *

class iplb(iplb_base):
  def _pick_server(self, key, inport):
    """Randomly picks a server to 'balance the load' """
    self.log.info('Using random choice load balancing algorithm.')
    return random.choice(self.live_servers.keys())

# Remember which DPID we're operating on (first one to connect)
_dpid = None


def launch (ip, servers, dpid = None):
  global _dpid
  if dpid is not None:
    _dpid = str_to_dpid(dpid)

  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]
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
        core.registerNew(iplb, event.connection, IPAddr(ip), servers)
        log.info("IP Load Balancer Ready.")
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)


  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
