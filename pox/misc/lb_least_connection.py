from pox.misc.iplb_base import *
from threading import Lock


class iplb(iplb_base):

    def __init__(self, server, first_packet, client_port):
        """Extend the __init__ function with extra fields"""
        super(iplb, self).__init__(server, first_packet, client_port)

        # create dictionary to track how much load each server has
        self.server_load = {k: 0 for k in self.live_servers.keys()}

        # create mutex used for tracking server_load table
        self.mutex = Lock()

    def _pick_server(self, key, inport):
        """Applies least connection load balancing algorithm"""
        self.log.info('Using Least Connection load balancing algorithm.')

        if not bool(self.live_servers):
            log.error('Error: No servers are online!')
            return

        """
        Find the server with the least load. If several servers all have the
        minimum load, pick the first one that was found with that min load.
        """
        server = min(self.server_load, key=self.server_load.get)

        # increment that server's load counter
        # TODO: consider cases where this table may not be accurate
        #       i.e. race conditions, connections that have been dropped, etc
        #       maybe add mutex locking?
        # NOTE: When evaluating these algorithms, create a more realistic env
        self._mutate_server_load(server, 'inc')

        return server

    def _mutate_server_load(self, server, op):
        """Increments/Decrements one of the live server's load by 1. A mutex is used to prevent race conditions.

        :param server:  key that represents the server node
        :param op:      opcode string that either increments or decrements
        """
        if op not in ['inc', 'dec']:
            raise ValueError('Error: Invalid op argument')

        self.mutex.acquire()
        try:
            if op == 'inc':
                self.server_load[server] = self.server_load[server] + 1
            elif op == 'dec':
                self.server_load[server] = self.server_load[server] - 1
            else:
                raise ValueError('Error: Invalid op argument')
        finally:
            self.mutex.release()

    def _handle_PacketIn(self, event):
        """Extending method in superclass to decrement load.
        This is a wild guess, but this might be the place to decrement the load.
        """
        server = super(iplb, self)._handle_PacketIn(event)
        if(server):
            self._mutate_server_load(server, 'dec')
        else:
            self.log.error('No server was chosen! Cannot decrease load counter.')


# Remember which DPID we're operating on (first one to connect)
_dpid = None


def launch(ip, servers, dpid=None):
    global _dpid
    if dpid is not None:
        _dpid = str_to_dpid(dpid)

    servers = servers.replace(",", " ").split()
    servers = [IPAddr(x) for x in servers]
    ip = IPAddr(ip)

    # We only want to enable ARP Responder *only* on the load balancer switch,
    # so we do some disgusting hackery and then boot it up.
    from proto.arp_responder import ARPResponder
    old_pi = ARPResponder._handle_PacketIn

    def new_pi(self, event):
        if event.dpid == _dpid:
            # Yes, the packet-in is on the right switch
            return old_pi(self, event)

    ARPResponder._handle_PacketIn = new_pi

    # Hackery done.  Now start it.
    from proto.arp_responder import launch as arp_launch
    arp_launch(eat_packets=False, **{str(ip): True})
    import logging
    logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

    def _handle_ConnectionUp(event):
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
