#!/usr/bin/env python

# Set default log level
import logging
logging.basicConfig(level=logging.DEBUG)

from pox.core import core
import pox.openflow.openflow
import pox.openflow.of_01

# Turn on extra info for event exceptions
import pox.lib.revent.revent as revent
revent.showEventExceptions = True

options = None

def doLaunch ():
  import sys, os
  # Add pox directory to path
  sys.path.append(os.path.abspath('pox'))

  import collections
  components = collections.OrderedDict()
  #curargs = None

  curargs = collections.OrderedDict()
  global options
  options = curargs

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
    name = name.split(":", 1)
    launch = name[1] if len(name) == 2 else "launch"
    name = name[0]

    if "pox." + name in sys.modules:
      name = "pox." + name
    elif name not in sys.modules:
      try:
        __import__("pox." + name, globals(), locals())
        name = "pox." + name
      except:
        try:
          __import__(name, globals(), locals())
        except ImportError:
          print "No such module:",name
          return False
        except:
          import traceback
          traceback.print_exc()
          print "Could not import module:",name
          return False

    if launch in sys.modules[name].__dict__:
      sys.modules[name].__dict__[launch](**params)
    elif len(params) > 0 or launch is not "launch":
      print "Module %s has no %s(), but it was specified or passed arguments" % (name, launch)
      return False

  return True

cli = True

def process_options ():
  for k,v in options.iteritems():
    #print k,"=",v
    if k == "no-cli":
      if str(v).lower() == "true":
        global cli
        cli = False
    else:
      print "Unknown option: ", k
      import sys
      sys.exit(1)

def pre_startup ():
  pox.openflow.openflow.launch() # Always launch OpenFlow

def post_startup ():
  #core.register("openflow_topology", pox.openflow.openflowtopology.OpenFlowTopology())
  #core.register("topology", pox.topology.topology.Topology())
  #core.register("openflow_discovery", pox.openflow.discovery.Discovery())
  #core.register("switch", pox.dumb_l3_switch.dumb_l3_switch.dumb_l3_switch())

  pox.openflow.of_01.launch() # Always launch of_01

if __name__ == '__main__':
  launchOK = False
  try:
    pre_startup()
    launchOK = doLaunch()
    if launchOK:
      process_options()
      post_startup()
      core.goUp()
  except:
    import traceback
    traceback.print_exc()
    launchOK = False

  if not launchOK:
    import sys
    sys.exit(1)

  if cli:
    import time
    time.sleep(1)
    import code
    import sys
    sys.ps1 = "POX> "
    sys.ps2 = " ... "
    code.interact('Ready.', local=locals())
  else:
    try:
      import time
      while True:
        time.sleep(5)
    except:
      pass
    #core.scheduler._thread.join() # Sleazy

  pox.core.core.quit()
