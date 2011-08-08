def launch ():
  import pox.topology.topology
  from pox.core import core
  core.registerNew(pox.topology.topology.Topology)
