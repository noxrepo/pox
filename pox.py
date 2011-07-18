#!/usr/bin/python

# Set default log level
import logging
logging.basicConfig(level=logging.DEBUG)

from pox.core import core
import pox.openflow.openflow
import pox.openflow.openflowtopology
import pox.topology.topology
import pox.openflow.discovery
import pox.openflow.of_01
import pox.dumb_l3_switch.dumb_l3_switch
import pox.messenger.messenger
from pox.gui_backend.guimessenger import GuiMessenger

# Turn on extra info for event exceptions
import pox.lib.revent.revent as revent
revent.showEventExceptions = True


def startup ():
  core.register("openflow_topology", pox.openflow.openflowtopology.OpenFlowTopology())
  core.register("topology", pox.topology.topology.Topology())
  core.register("openflow_discovery", pox.openflow.discovery.Discovery())
  core.register("openflow", pox.openflow.openflow.OpenFlowHub())
  core.register("switch", pox.dumb_l3_switch.dumb_l3_switch.dumb_l3_switch())

  pox.openflow.of_01.start()
  pox.messenger.messenger.start()
  
  GuiMessenger()

if __name__ == '__main__':
  try:
    startup()
    core.goUp()
  except:
    import traceback
    traceback.print_exc()

  import time
  time.sleep(1)
  import code
  import sys
  sys.ps1 = "POX> "
  sys.ps2 = " ... "
  code.interact('Ready.', local=locals())
  pox.core.core.quit()
