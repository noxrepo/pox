def launch ():
  import dumb_l3_switch
  from pox.core import core
  core.registerNew(dumb_l3_switch.dumb_l3_switch)
