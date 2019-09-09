from pox.misc.iplb_base import *

class iplb(iplb_base):
  def _pick_server(self, key, inport):
    """Randomly picks a server to 'balance the load' """
    return random.choice(self.live_servers.keys())
