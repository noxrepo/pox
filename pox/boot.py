#!/bin/sh -

# Copyright 2011,2012,2013,2017 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# If you have PyPy 1.6+ in a directory called pypy alongside pox.py, we
# use it.
# Otherwise, we try to use a Python interpreter called python2.7, which
# is a good idea if you're using Python from MacPorts, for example.
# We fall back to just "python" and hope that works.

#TODO: Make runnable by itself (paths need adjusting, etc.).


from __future__ import print_function

import logging
import logging.config
import os
import sys
import traceback
import time
import inspect
import types
import threading

import pox.core
core = None

import pox.openflow
from pox.lib.util import str_to_bool, first_of

# Function to run on main thread
_main_thread_function = None

try:
  import __pypy__
except ImportError:
  __pypy__ = None

def _do_import (name):
  """
  Try to import the named component.
  Returns its module name if it was loaded or False on failure.
  """
  #TODO: Update to use the Python 3 import facilities

  def show_fail ():
    traceback.print_exc()
    print("Could not import module:", name)

  def do_import2 (base_name, names_to_try):
    if len(names_to_try) == 0:
      print("Module not found:", base_name)
      return False

    name = names_to_try.pop(0)

    if name in sys.modules:
      return name

    try:
      __import__(name, level=0)
      return name
    except ModuleNotFoundError as exc:
      # There are two cases why this might happen:
      # 1. The named module could not be found
      # 2. Some dependent module (import foo) or some dependent
      #    name-in-a-module (e.g., from foo import bar) could not be found.
      # If it's the former, we might try a name variation (e.g., without
      # a leading "pox."), but if we ultimately can't find the named
      # module, we just say something along those lines and stop.
      # On the other hand, if the problem is with a dependency, we should
      # print a stack trace so that it can be fixed.
      # Sorting out the two cases is an ugly hack.

      if exc.name and name.endswith(exc.name):
        # It was the one we tried to import itself. (Case 1)
        # If we have other names to try, try them!
        return do_import2(base_name, names_to_try)
      elif name.endswith(".py"):
        print("Import by filename is not supported.")
        import os.path
        n = name.replace("/", ".").replace("\\", ".")
        n = n.replace( os.path.sep, ".")
        if n.startswith("pox.") or n.startswith("ext."):
          n = n[4:]
        if n.endswith(".py"):
          n = n[:-3]
        print("Maybe you meant to run '%s'?" % (n,))
        return False
      else:
        # This means we found the module we were looking for, but one
        # of its dependencies was missing.
        show_fail()
        return False
    except:
      # There was some other sort of exception while trying to load the
      # module.  Just print a trace and call it a day.
      show_fail()
      return False

  return do_import2(name, ["pox." + name, name])


def _do_imports (components):
  """
  Import each of the listed components

  Returns map of component_name->name,module,members on success,
  or False on failure
  """
  done = {}
  for name in components:
    if name in done: continue
    r = _do_import(name)
    if r is False:
      return False
    members = dict(inspect.getmembers(sys.modules[r]))
    done[name] = (r,sys.modules[r],members)

  return done


def _do_launch (argv, skip_startup=False):
  component_order = []
  components = {}

  curargs = {}
  pox_options = curargs

  for arg in argv:
    if not arg.startswith("-"):
      if "=" in arg:
        arg,first_arg = arg.split("=", 1)
        curargs = {None:first_arg}
      else:
        curargs = {}
      if arg not in components:
        components[arg] = []
      components[arg].append(curargs)
      component_order.append(arg)
    else:
      arg = arg.lstrip("-").split("=", 1)
      arg[0] = arg[0].replace("-", "_")
      if len(arg) == 1: arg.append(True)
      curargs[arg[0]] = arg[1]

  if not skip_startup:
    _options.process_options(pox_options)
    global core
    if pox.core.core is not None:
      core = pox.core.core
      core.getLogger('boot').debug('Using existing POX core')
    else:
      core = pox.core.initialize(_options.threaded_selecthub,
                                 _options.epoll_selecthub,
                                 _options.handle_signals)

    _pre_startup()

  modules = _do_imports(n.split("=")[0].split(':')[0] for n in component_order)
  if modules is False:
    return False

  inst = {}
  for name in component_order:
    cname = name
    inst[name] = inst.get(name, -1) + 1
    params = components[name][inst[name]]
    name = name.split(":", 1)
    launch = name[1] if len(name) == 2 else "launch"
    name = name[0]
    first_arg = params.pop(None, None)

    name,module,members = modules[name]

    if launch in members:
      f = members[launch]
      # We explicitly test for a function and not an arbitrary callable
      if type(f) is not types.FunctionType:
        print(launch, "in", name, "isn't a function!")
        return False

      if getattr(f, '_pox_eval_args', False):
        import ast
        for k,v in list(params.items()):
          if isinstance(v, str):
            try:
              params[k] = ast.literal_eval(v)
            except:
              # Leave it as a string
              pass

      multi = False
      if f.__code__.co_argcount > 0:
        #FIXME: This code doesn't look quite right to me and may be broken
        #       in some cases.  We should refactor to use inspect anyway,
        #       which should hopefully just fix it.
        if (f.__code__.co_varnames[f.__code__.co_argcount-1]
            == '__INSTANCE__'):
          # It's a multi-instance-aware component.

          multi = True

          # Special __INSTANCE__ paramter gets passed a tuple with:
          # 1. The number of this instance (0...n-1)
          # 2. The total number of instances for this module
          # 3. True if this is the last instance, False otherwise
          # The last is just a comparison between #1 and #2, but it's
          # convenient.
          params['__INSTANCE__'] = (inst[cname], len(components[cname]),
           inst[cname] + 1 == len(components[cname]))

      if multi == False and len(components[cname]) != 1:
        print(name, "does not accept multiple instances")
        return False

      try:
        if first_arg is not None:
          pparams = (first_arg,)
        else:
          pparams = ()
        if f(*pparams, **params) is False:
          # Abort startup
          return False
      except TypeError as exc:
        instText = ''
        if inst[cname] > 0:
          instText = "instance {0} of ".format(inst[cname] + 1)
        print("Error executing {2}{0}.{1}:".format(name,launch,instText))
        if inspect.currentframe() is sys.exc_info()[2].tb_frame:
          # Error is with calling the function
          # Try to give some useful feedback
          if _options.verbose:
            traceback.print_exc()
          else:
            exc = sys.exc_info()[0:2]
            print(''.join(traceback.format_exception_only(*exc)), end='')
          print()
          EMPTY = "<Unspecified>"
          code = f.__code__
          argcount = code.co_argcount
          argnames = code.co_varnames[:argcount]
          defaults = list((f.__defaults__) or [])
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
            print("Documentation for {0}:".format(name))
            doc = f.__doc__.split("\n")
            #TODO: only strip the same leading space as was on the first
            #      line
            doc = map(str.strip, doc)
            print('',("\n ".join(doc)).strip())

          #print(params)
          #print(args)

          print("Parameters for {0}:".format(name))
          if len(args) == 0:
            print(" None.")
          else:
            print(" {0:25} {1:25} {2:25}".format("Name", "Default",
                                                "Active"))
            print(" {0:25} {0:25} {0:25}".format("-" * 15))

            for k,v in args.items():
              print(" {0:25} {1:25} {2:25}".format(k,str(v[0]),
                    str(v[1] if v[1] is not EMPTY else v[0])))

          if len(params):
            print("This component does not have a parameter named "
                  + "'{0}'.".format(first_of(params.keys())))
            return False
          missing = [k for k,x in args.items()
                     if x[1] is EMPTY and x[0] is EMPTY]
          if len(missing):
            print("You must specify a value for the '{0}' "
                  "parameter.".format(missing[0]))
            return False

          return False
        else:
          # Error is inside the function
          raise
    elif len(params) > 0 or launch != "launch":
      print("Module %s has no %s(), but it was specified or passed " \
            "arguments" % (name, launch))
      return False

  return True


class Options (object):
  def set (self, given_name, value):
    name = given_name.replace("-", "_")
    if name.startswith("_") or hasattr(Options, name):
      # Hey, what's that about?
      print("Illegal option:", given_name)
      return False
    has_field = hasattr(self, name)
    has_setter = hasattr(self, "_set_" + name)
    if has_field == False and has_setter == False:
      print("Unknown option:", given_name)
      return False
    if has_setter:
      setter = getattr(self, "_set_" + name)
      setter(given_name, name, value)
    else:
      if isinstance(getattr(self, name), bool):
        # Automatic bool-ization
        value = str_to_bool(value)
      setattr(self, name, value)
    return True

  def process_options (self, options):
    for k,v in options.items():
      if self.set(k, v) is False:
        # Bad option!
        sys.exit(1)


_help_text = """
POX is a Software Defined Networking controller framework.

The commandline of POX is like:
pox.py [POX options] [C1 [C1 options]] [C2 [C2 options]] ...

Notable POX options include:
  --verbose       Print more debugging information (especially useful for
                  problems on startup)
  --no-openflow   Don't automatically load the OpenFlow module
  --log-config=F  Load a Python log configuration file (if you include the
                  option without specifying F, it defaults to logging.cfg)

C1, C2, etc. are component names (e.g., Python modules).  Options they
support are up to the module.  As an example, you can load a learning
switch app that listens on a non-standard port number by specifying an
option to the of_01 component, and loading the l2_learning component like:
  ./pox.py --verbose openflow.of_01 --port=6634 forwarding.l2_learning

The 'help' component can give help for other components.  Start with:
  ./pox.py help --help
""".strip()


class POXOptions (Options):
  def __init__ (self):
#    self.cli = True
    self.verbose = False
    self.enable_openflow = True
    self.log_config = None
    self.threaded_selecthub = True
    self.epoll_selecthub = False
    self.handle_signals = True

  def _set_h (self, given_name, name, value):
    self._set_help(given_name, name, value)

  def _set_help (self, given_name, name, value):
    print(_help_text)
    #TODO: Summarize options, etc.
    sys.exit(0)

  def _set_version (self, given_name, name, value):
    global core
    if core is None:
      core = pox.core.initialize()
    print(core._get_python_version())
    sys.exit(0)

  def _set_unthreaded_sh (self, given_name, name, value):
    self.threaded_selecthub = False

  def _set_epoll_sh (self, given_name, name, value):
    self.epoll_selecthub = str_to_bool(value)

  def _set_no_openflow (self, given_name, name, value):
    self.enable_openflow = not str_to_bool(value)

#  def _set_no_cli (self, given_name, name, value):
#    self.cli = not str_to_bool(value)

  def _set_log_config (self, given_name, name, value):
    if value is True:
      # I think I use a better method for finding the path elsewhere...
      p = os.path.dirname(os.path.realpath(__file__))
      value = os.path.join(p, "..", "logging.cfg")
    self.log_config = value

  def _set_debug (self, given_name, name, value):
    value = str_to_bool(value)
    if value:
      # Debug implies no openflow and no CLI and verbose
      #TODO: Is this really an option we need/want?
      self.verbose = True
      self.enable_openflow = False
#      self.cli = False


_options = POXOptions()


def _pre_startup ():
  """
  This function is called after all the POX options have been read in
  but before any components are loaded.  This gives a chance to do
  early setup (e.g., configure logging before a component has a chance
  to try to log something!).
  """

  _setup_logging()

  if _options.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

  if _options.enable_openflow:
    pox.openflow._launch() # Default OpenFlow launch


def _post_startup ():
  if _options.enable_openflow:
    if core._openflow_wanted:
      if not core.hasComponent("of_01"):
        # Launch a default of_01
        import pox.openflow.of_01
        pox.openflow.of_01.launch()
    else:
      logging.getLogger("boot").debug("Not launching of_01")



def _setup_logging ():
  # First do some basic log config...

  # This is kind of a hack, but we need to keep track of the handler we
  # install so that we can, for example, uninstall it later.  This code
  # originally lived in pox.core, so we explicitly reference it here.
  pox.core._default_log_handler = logging.StreamHandler()
  formatter = logging.Formatter(logging.BASIC_FORMAT)
  pox.core._default_log_handler.setFormatter(formatter)
  logging.getLogger().addHandler(pox.core._default_log_handler)
  logging.getLogger().setLevel(logging.INFO)


  # Now set up from config file if specified...
  #TODO:
  #  I think we could move most of the special log stuff into
  #  the log module.  You'd just have to make a point to put the log
  #  module first on the commandline if you wanted later component
  #  initializations to honor it.  Or it could be special-cased?

  if _options.log_config is not None:
    if not os.path.exists(_options.log_config):
      print("Could not find logging config file:", _options.log_config)
      sys.exit(2)
    logging.config.fileConfig(_options.log_config,
                              disable_existing_loggers=True)


def set_main_function (f):
  global _main_thread_function
  if _main_thread_function == f: return True
  if _main_thread_function is not None:
    import logging
    lg = logging.getLogger("boot")
    lg.error("Could not set main thread function to: " + str(f))
    lg.error("The main thread function is already "
        + "taken by: " + str(_main_thread_function))
    return False
  _main_thread_function = f
  return True


def boot (argv = None):
  """
  Start up POX.
  """

  # Add pox directory to path
  base = sys.path[0]
  sys.path.insert(0, os.path.abspath(os.path.join(base, 'pox')))
  sys.path.insert(0, os.path.abspath(os.path.join(base, 'ext')))

  thread_count = threading.active_count()

  quiet = False

  try:
    if argv is None:
      argv = sys.argv[1:]

    # Always load cli (first!)
    #TODO: Can we just get rid of the normal options yet?
    pre = []
    while len(argv):
      if argv[0].startswith("-"):
        pre.append(argv.pop(0))
      else:
        break
    argv = pre + "py --disable".split() + argv

    if _do_launch(argv):
      _post_startup()
      core.goUp()
    else:
      #return
      quiet = True
      raise RuntimeError()

  except SystemExit:
    return
  except:
    if not quiet:
      traceback.print_exc()

    # Try to exit normally, but do a hard exit if we don't.
    # This is sort of a hack.  What's the better option?  Raise
    # the going down event on core even though we never went up?

    try:
      for _ in range(4):
        if threading.active_count() <= thread_count:
          # Normal exit
          return
        time.sleep(0.25)
    except:
      pass

    os._exit(1)
    return

  if _main_thread_function:
    _main_thread_function()
  else:
    #core.acquire()
    try:
      while True:
        if core.quit_condition.acquire(False):
          core.quit_condition.wait(10)
          core.quit_condition.release()
        if not core.running: break
    except:
      pass
    #core.scheduler._thread.join() # Sleazy

  try:
    pox.core.core.quit()
  except:
    pass
