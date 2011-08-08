def launch ():
  import dumb_l2_switch
  from pox.core import core
  core.registerNew(dumb_l2_switch.dumb_l2_switch)
