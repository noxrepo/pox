#!/bin/bash -

# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

# If you have PyPy 1.6+ in a directory called pypy alongside pox.py, we
# use it.
# Otherwise, we try to use a Python interpreter called python2.7, which
# is a good idea if you're using Python from MacPorts, for example.
# We fall back to just "python" and hope that works.

''''echo -n
if [ -x pypy/bin/pypy ]; then
  exec pypy/bin/pypy -O "$0" "$@"
fi

if [ "$(type -P python2.7)" != "" ]; then
  exec python2.7 -O "$0" "$@"
fi
exec python -O "$0" "$@"
'''

from pox.core import core
import pox.openflow.openflow
import pox.openflow.of_01

# Turn on extra info for event exceptions
import pox.lib.revent.revent as revent
revent.showEventExceptions = True

import sys

options = None

def doImport (name):
  if name in sys.modules:
    return name

  def showFail ():
    import traceback
    traceback.print_exc()
    print "Could not import module:",name

  try:
    __import__(name, globals(), locals())
    return name
  except ImportError:
    # This can be because the one we tried to import wasn't found OR
    # because one IT tried to import wasn't found.  Try to sort this...
    s = str(sys.exc_info()[1]).rsplit(" ", 1)[1]
    if name.endswith(s):
      #print s,"|",name
      return True
    else:
      showFail()
      return False
  except:
    showFail()
    return False

def doLaunch ():
  import sys, os
  # Add pox directory to path
  sys.path.append(os.path.abspath(os.path.join(sys.path[0], 'pox')))
  sys.path.append(os.path.abspath(os.path.join(sys.path[0], 'ext')))

  component_order = []
  components = {}
  #curargs = None

  curargs = {}
  global options
  options = curargs

  for arg in sys.argv[1:]:
    if not arg.startswith("--"):
      pre_startup()
      if arg not in components:
        components[arg] = []
      curargs = {}
      components[arg].append(curargs)
      component_order.append(arg)
    else:
      arg = arg[2:].split("=", 1)
      if len(arg) == 1: arg.append(True)
      curargs[arg[0]] = arg[1]

  inst = {}
  for name in component_order:
    cname = name
    inst[name] = inst.get(name, -1) + 1
    params = components[name][inst[name]]
    name = name.split(":", 1)
    launch = name[1] if len(name) == 2 else "launch"
    name = name[0]

    r = doImport("pox." + name)
    if r is False: return False
    if r is True:
      r = doImport(name)
      if r is False: return False
      if r is True:
        print "Module", name, "not found"
        return False
    name = r
    #print ">>",name

    if launch in sys.modules[name].__dict__:
      f = sys.modules[name].__dict__[launch]
      if f.__class__ is not doLaunch.__class__:
        print launch, "in", name, "isn't a function!"
        return False
      multi = False
      if f.func_code.co_argcount > 0:
        if f.func_code.co_varnames[f.func_code.co_argcount-1] == '__INSTANCE__':
          multi = True
          params['__INSTANCE__'] = (inst[cname], len(components[cname]),
                                    inst[cname] + 1 == len(components[cname]))

      if multi == False and len(components[cname]) != 1:
        print name, "does not accept multiple instances"
        return False

      try:
        f(**params)
      except TypeError as exc:
        instText = ''
        if inst[cname] > 0:
          instText = "instance {0} of ".format(inst[cname] + 1)
        print "Error executing {2}{0}.{1}:".format(name,launch,instText)
        import inspect
        if inspect.currentframe() is sys.exc_info()[2].tb_frame:
          # Error is with calling the function
          # Try to give some useful feedback
          import traceback
          if options.get("verbose"):
            traceback.print_exc()
          else:
            exc = sys.exc_info()[0:2]
            print ''.join(traceback.format_exception_only(*exc)),
          print
          EMPTY = "<Unspecified>"
          code = f.__code__
          argcount = code.co_argcount
          argnames = code.co_varnames[:argcount]
          defaults = list((f.func_defaults) or [])
          defaults = [EMPTY] * (argcount - len(defaults)) + defaults
          args = {}
          for n, a in enumerate(argnames):
            args[a] = [EMPTY,EMPTY]
            if n < len(defaults):
              args[a][0] = defaults[n]
            if a in params:
              args[a][1] = params[a]
              del params[a]
          if '__INSTANCE__' in args:
            del args['__INSTANCE__']

          if f.__doc__ is not None:
            print "Documentation for {0}:".format(name)
            doc = f.__doc__.split("\n")
            #TODO: only strip the same leading space as was on the first
            #      line
            doc = map(str.strip, doc)
            print '',("\n ".join(doc)).strip()

          #print params
          #print args

          print "Parameters for {0}:".format(name)
          if len(args) == 0:
            print " None."
          else:
            print " {0:25} {1:25} {2:25}".format("Name", "Default",
                                                "Active")
            print " {0:25} {0:25} {0:25}".format("-" * 15)

            for k,v in args.iteritems():
              print " {0:25} {1:25} {2:25}".format(k,v[0],
              v[1] if v[1] is not EMPTY else v[0])

          if len(params):
            print "This component does not have a parameter named " + \
                  "'{0}'.".format(params.keys()[0])
            return False
          missing = [k for k,x in args.iteritems()
                     if x[1] is EMPTY and x[0] is EMPTY]
          if len(missing):
            print "You must specify a value for the '{0}' parameter.".format(
             missing[0])
            return False

          return False
        else:
          # Error is inside the function
          raise
    elif len(params) > 0 or launch is not "launch":
      print ("Module %s has no %s(), but it was specified or passed arguments"
             % (name, launch))
      return False

  # If no options, might not have done pre_startup yet.
  pre_startup()

  return True

cli = True
verbose = False
enable_openflow = True

def _opt_no_openflow (v):
  global enable_openflow
  enable_openflow = str(v).lower() != "true"

def _opt_no_cli (v):
  if str(v).lower() == "true":
    global cli
    cli = False

def _opt_verbose (v):
  global verbose
  verbose = str(v).lower() == "true"

def process_options ():
  # TODO: define this list somewhere else. Or use an option-parsing library.
  for k,v in options.iteritems():
    rk = '_opt_' + k.replace("-", "_")
    if rk in globals():
      globals()[rk](v)
    else:
      print "Unknown option:", k
      import sys
      sys.exit(1)

_done_pre_startup = False
def pre_startup ():
  global _done_pre_startup
  if _done_pre_startup: return True
  _done_pre_startup = True

  process_options()

  if enable_openflow:
    pox.openflow.openflow.launch() # Always launch OpenFlow

  return True

def post_startup ():
  #core.register("openflow_topology", pox.openflow.openflowtopology.OpenFlowTopology())
  #core.register("topology", pox.topology.topology.Topology())
  #core.register("openflow_discovery", pox.openflow.discovery.Discovery())
  #core.register("switch", pox.dumb_l3_switch.dumb_l3_switch.dumb_l3_switch())

  if enable_openflow:
    pox.openflow.of_01.launch() # Always launch of_01

def _monkeypatch_console ():
  """
  The readline in pypy (which is the readline from pyrepl) turns off output
  postprocessing, which disables normal NL->CRLF translation.  An effect of
  this is that output *from other threads* (like log messages) which try to
  print newlines end up just getting linefeeds and the output is all stair-
  stepped.  We monkeypatch the function in pyrepl which disables OPOST to turn
  OPOST back on again.  This doesn't immediately seem to break anything in the
  simple cases, and makes the console reasonable to use in pypy.
  """
  try:
    import termios
    import sys
    import pyrepl.unix_console
    uc = pyrepl.unix_console.UnixConsole
    old = uc.prepare
    def prep (self):
      old(self)
      f = sys.stdin.fileno()
      a = termios.tcgetattr(f)
      a[1] |= 1 # Turn on postprocessing (OPOST)
      termios.tcsetattr(f, termios.TCSANOW, a)
    uc.prepare = prep
  except:
    pass

def main ():
  _monkeypatch_console()
  try:
    if doLaunch():
      post_startup()
      core.goUp()
    else:
      return

  except SystemExit:
    return
  except:
    import traceback
    traceback.print_exc()
    return

  if cli:
    print "This program comes with ABSOLUTELY NO WARRANTY.  This program is " \
          "free software,"
    print "and you are welcome to redistribute it under certain conditions."
    print "Type 'help(pox.license)' for details."
    import pox.license
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

  try:
    pox.core.core.quit()
  except:
    pass

if __name__ == '__main__':
  main()
