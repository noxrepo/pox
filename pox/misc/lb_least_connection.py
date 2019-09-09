from pox.misc.iplb_base import *

class iplb(iplb_base):
	def _pick_server(self, key, inport):
		"""Applies least connection load balancing algorithm"""

		# Find a way to get each live server's current load, then find the minimum value

		raise NotImplementedError
