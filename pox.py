#!/usr/bin/python

# Set default log level
import logging
logging.basicConfig(level=logging.DEBUG)

from pox.core import core
import pox.openflow.openflow
import pox.topology.topology
import pox.openflow.of_01
import pox.dumb_l3_switch.dumb_l3_switch

# Turn on extra info for event exceptions
import pox.lib.revent.revent as revent
revent.showEventExceptions = True


def startup ():
  core.register("topology", pox.topology.topology.Topology())
  core.register("openflow", pox.openflow.openflow.OpenFlowHub())
  core.register("switch", pox.dumb_l3_switch.dumb_l3_switch.dumb_l3_switch())

  pox.openflow.of_01.start()


if __name__ == '__main__':
  try:
    startup()
    core.goUp()
  except:
    import traceback
    traceback.print_exc()

  import code
  code.interact('Ready.', local=locals())
  pox.core.core.quit()
