#!/usr/bin/env python

# Set default log level
import logging
logging.basicConfig(level=logging.DEBUG)

from pox.core import core
import pox.openflow.openflow
import pox.openflow.openflowtopology
import pox.topology.topology
import pox.openflow.discovery
import pox.openflow.of_01

# Turn on extra info for event exceptions
import pox.lib.revent.revent as revent
revent.showEventExceptions = True


def doLaunch ():
  import sys, os
  # Add pox directory to path
  sys.path.append(os.path.abspath('pox'))

  import collections
  components = collections.OrderedDict()
  curargs = None

  for arg in sys.argv[1:]:
    if not arg.startswith("--"):
      assert arg not in components
      curargs = collections.OrderedDict()
      components[arg] = curargs
    else:
      arg = arg[2:].split("=", 1)
      if len(arg) == 1: arg.append(True)
      curargs[arg[0]] = arg[1]

  for name,params in components.iteritems():
    if name not in sys.modules:
      try:
        __import__(name, globals(), locals())
      except:
        print "No such module:",name
        return False

    if 'launch' in sys.modules[name].__dict__:
      sys.modules[name].__dict__['launch'](**params)
    elif len(params):
      print "Module",name,"has no launch() but was passed arguments"
      return False

  return True

def startup ():
  core.register("openflow_topology", pox.openflow.openflowtopology.OpenFlowTopology())
  core.register("topology", pox.topology.topology.Topology())
  core.register("openflow_discovery", pox.openflow.discovery.Discovery())
  core.register("openflow", pox.openflow.openflow.OpenFlowHub())
  #core.register("switch", pox.dumb_l3_switch.dumb_l3_switch.dumb_l3_switch())

  pox.openflow.of_01.start()

  #GuiMessenger()

if __name__ == '__main__':
  launchOK = False
  try:
    startup()
    launchOK = doLaunch()
    if launchOK:
      core.goUp()
  except:
    import traceback
    traceback.print_exc()
    launchOK = False

  if not launchOK:
    import sys
    sys.exit(1)

  import time
  time.sleep(1)
  import code
  import sys
  sys.ps1 = "POX> "
  sys.ps2 = " ... "
  code.interact('Ready.', local=locals())
  pox.core.core.quit()
