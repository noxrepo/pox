from pox.misc.iplb_base import *

class iplb(iplb_base):

	def __init__ (self, server, first_packet, client_port):
		"""Extend the __init__ function with extra fields"""
		super(iplb, self).__init__(server, first_packet, client_port)

		# create dictionary to track how much load each server has
		self.server_load = {k:0 for k in self.live_servers.keys()}

	def _pick_server(self, key, inport):
		"""Applies least connection load balancing algorithm"""
		log.info('Using Least Connection load balancing algorithm.')

		"""
		Find the server with the least load. If several servers all have the
		minimum load, pick the first one that was found with that min load.
		"""
		server = self.find_minimum_load()

		# increment that server's load counter
		server_load[server] = server_load[server] + 1

		return server

	@staticmethod
	def find_minimum_load():
		"""Return the key within server_load that has the minimum load"""
		minval = Integer.MAX_VALUE
		result = 0

		for k,v in self.server_load.items():
			if v < minval:
				minval = v
				result = k

		if result == 0:
			# if result was not changed, no servers are up
			raise Exception('Error: no servers are online!')

		return result


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
