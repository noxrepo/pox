from pox.misc.iplb_base import *

class iplb(iplb_base):
	def _pick_server(self, key, inport):
		"""Applies weighted least connection load balancing algorithm"""

		# Get each live server's current load, as well as their weights

		# Get minimum load. If there are multiple servers with this load, pick the one with the highest weight among that set

		raise NotImplementedError
