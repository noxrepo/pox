"""
Fires up topology, discovery, and a switch
"""

def launch ():
  import pox.topology
  pox.topology.launch()
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.openflow.topology
  pox.openflow.topology.launch()
  import pox.dumb_l2_switch
  pox.dumb_l2_switch.launch()
