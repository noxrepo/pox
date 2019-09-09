from pox.misc.ip_load_balancer import *

class iplb_least_connection(iplb):
	def _pick_server(self, key, inport):
		"""Applies least connection load balancing algorithm"""

		# Find a way to get each live server's current load, then find the minimum value

		raise NotImplementedError

class iplb_weighted_least_connection(iplb):
	def _pick_server(self, key, inport):
		"""Applies weighted least connection load balancing algorithm"""

		# Get each live server's current load, as well as their weights

		# Get minimum load. If there are multiple servers with this load, pick the one with the highest weight among that set

		raise NotImplementedError
