# Copyright 2011-2020 James McCauley
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

"""
Some of POX's core API and functionality is here, largely in the POXCore
class (an instance of which is available as pox.core.core).

This includes things like component rendezvous, logging, system status
(up and down events), etc.
"""

from __future__ import print_function

# Set up initial log state
import logging

import inspect
import time
import os
import signal

_path = inspect.stack()[0][1]
_ext_path = _path[0:_path.rindex(os.sep)]
_ext_path = os.path.dirname(_ext_path) + os.sep
_path = os.path.dirname(_path) + os.sep

SQUELCH_TIME = 5

_squelch = ''
_squelchTime = 0
_squelchCount = 0

def getLogger (name=None, moreFrames=0):
  """
  In general, you don't need to call this directly, and will use
  core.getLogger() instead.
  """
  if name is None:
    s = inspect.stack()[1+moreFrames]
    # Should we always use __name__ instead?
    fname = s[0].f_globals.get('__file__')
    matching = False
    name = s[1]
    if name.endswith('.py'):
      matching = name == fname
      name = name[0:-3]
    elif name.endswith('.pyo'):
      matching = name == (fname + "o")
      name = name[0:-4]
    elif name.endswith('.pyc'):
      matching = name == (fname + "c")
      name = name[0:-4]
    if name.startswith(_path):
      name = name[len(_path):]
    elif name.startswith(_ext_path):
      name = name[len(_ext_path):]
    elif not matching:
      # This may not work right across platforms, so be cautious.
      n = s[0].f_globals.get('__name__')
      if n:
        if n.startswith("pox."): n = n[4:]
        if n.startswith("ext."): n = n[4:]
      else:
        try:
          n = os.path.basename(name)
        except Exception:
          n = ""
        n = n.replace('\\','/').replace(os.path.sep,'/')
      if n: name = n

    name = name.replace('/', '.').replace('\\', '.') #FIXME: use os.path or whatever

    # Remove double names ("topology.topology" -> "topology")
    if name.find('.') != -1:
      n = name.split('.')
      if len(n) >= 2:
        if n[-1] == n[-2]:
          del n[-1]
          name = '.'.join(n)

    if name.startswith("ext."):
      name = name.split("ext.",1)[1]

    if name.endswith(".__init__"):
      name = name.rsplit(".__init__",1)[0]

  l = logging.getLogger(name)
  g=globals()
  if not hasattr(l, "print"):
    def printmsg (*args, **kw):
      #squelch = kw.get('squelch', True)
      msg = ' '.join((str(s) for s in args))
      s = inspect.stack()[1]
      o = '['
      if 'self' in s[0].f_locals:
        o += s[0].f_locals['self'].__class__.__name__ + '.'
      o += s[3] + ':' + str(s[2]) + '] '
      o += msg
      if o == _squelch:
        if time.time() >= _squelchTime:
          l.debug("[Previous message repeated %i more times]" % (g['_squelchCount']+1,))
          g['_squelchCount'] = 0
          g['_squelchTime'] = time.time() + SQUELCH_TIME
        else:
          g['_squelchCount'] += 1
      else:
        g['_squelch'] = o
        if g['_squelchCount'] > 0:
          l.debug("[Previous message repeated %i more times]" % (g['_squelchCount'],))
        g['_squelchCount'] = 0
        g['_squelchTime'] = time.time() + SQUELCH_TIME
        l.debug(o)

    setattr(l, "print", printmsg)
    setattr(l, "msg", printmsg)

  return l


# Working around something (don't remember what)
log = (lambda : getLogger())()

from pox.lib.revent import *

# Now use revent's exception hook to put exceptions in event handlers into
# the log...
def _revent_exception_hook (source, event, args, kw, exc_info):
  try:
    c = source
    t = event
    if hasattr(c, "__class__"): c = c.__class__.__name__
    if isinstance(t, Event): t = t.__class__.__name__
    elif issubclass(t, Event): t = t.__name__
  except:
    pass
  log.exception("Exception while handling %s!%s...\n" % (c,t))
import pox.lib.revent.revent
pox.lib.revent.revent.handleEventException = _revent_exception_hook

class GoingUpEvent (Event):
  """ Fired when system is going up. """
  def get_deferral (self):
    return self.source._get_go_up_deferral()

class GoingDownEvent (Event):
  """ Fired when system is going down. """
  pass

class UpEvent (Event):
  """ Fired when system is up. """
  pass

class DownEvent (Event):
  """ Fired when system is down. """
  pass

class ComponentRegistered (Event):
  """
  This is raised by core whenever a new component is registered.
  By watching this, a component can monitor whether other components it
  depends on are available.
  """
  def __init__ (self, name, component):
    self.name = name
    self.component = component

class RereadConfiguration (Event):
  """ Fired when modules should reread their configuration files. """
  pass

import pox.lib.recoco as recoco

class POXCore (EventMixin):
  """
  A nexus of of the POX API.

  pox.core.core is a reference to an instance of this class.  This class
  serves a number of functions.

  An important one is that it can serve as a rendezvous point for
  components.  A component can register objects on core, and they can
  then be accessed on the core object (e.g., if you register foo, then
  there will then be a pox.core.core.foo).  In many cases, this means you
  won't need to import a module.

  Another purpose to the central registration is that it decouples
  functionality from a specific module.  If myL2Switch and yourL2Switch
  both register as "switch" and both provide the same API, then it doesn't
  matter.  Doing this with imports is a pain.

  Additionally, a number of commmon API functions are vailable here.
  """
  _eventMixin_events = set([
    UpEvent,
    DownEvent,
    GoingUpEvent,
    GoingDownEvent,
    ComponentRegistered,
    RereadConfiguration,
  ])

  version = (0,7,0)
  version_name = "gar"

  def __init__ (self, threaded_selecthub=True, epoll_selecthub=False,
                handle_signals=True):
    self.debug = False
    self.running = True
    self.starting_up = True
    self.components = {'core':self}

    self._go_up_deferrals = set()

    self._openflow_wanted = False
    self._handle_signals = handle_signals

    import threading
    self.quit_condition = threading.Condition()

    print(self.banner)

    self.scheduler = recoco.Scheduler(daemon=True,
                                      threaded_selecthub=threaded_selecthub,
                                      use_epoll=epoll_selecthub)

    self._waiters = [] # List of waiting components

  @property
  def banner (self):
    return "{0} / Copyright 2011-2020 James McCauley, et al.".format(
     self.version_string)

  @property
  def version_string (self):
    return "POX %s (%s)" % ('.'.join(map(str,self.version)),self.version_name)

  def callDelayed (_self, _seconds, _func, *args, **kw):
    """ Deprecated """
    return _self.call_delayed(_seconds, _func, *args, **kw)

  def call_delayed (_self, _seconds, _func, *args, **kw):
    """
    Calls the function at a later time.
    This is just a wrapper around a recoco timer.
    """
    t = recoco.Timer(_seconds, _func, args=args, kw=kw,
                     scheduler = _self.scheduler)
    return t

  def callLater (_self, _func, *args, **kw):
    """ Deprecated """
    return _self.call_later(_func, *args, **kw)

  def call_later (_self, _func, *args, **kw):
    # first arg is `_self` rather than `self` in case the user wants
    # to specify self as a keyword argument
    """
    Call the given function with the given arguments within the context
    of the co-operative threading environment.
    It actually calls it sooner rather than later. ;)
    Much of POX is written without locks because it's all thread-safe
    with respect to itself, as it's written using the recoco co-operative
    threading library.  If you have a real thread outside of the
    co-operative thread context, you need to be careful about calling
    things within it.  This function provides a rather simple way that
    works for most situations: you give it a callable (like a method)
    and some arguments, and it will call that callable with those
    arguments from within the co-operative threader, taking care of
    synchronization for you.
    """
    _self.scheduler.callLater(_func, *args, **kw)

  def raiseLater (_self, _obj, *args, **kw):
    # first arg is `_self` rather than `self` in case the user wants
    # to specify self as a keyword argument
    """
    This is similar to callLater(), but provides an easy way to raise a
    revent event from outide the co-operative context.
    Rather than foo.raiseEvent(BarEvent, baz, spam), you just do
    core.raiseLater(foo, BarEvent, baz, spam).
    """
    _self.scheduler.callLater(_obj.raiseEvent, *args, **kw)

  def getLogger (self, *args, **kw):
    """
    Returns a logger.  Pass it the name you want if you'd like to specify
    one (e.g., core.getLogger("foo")).  If you don't specify a name, it
    will make one up based on the module name it is called from.
    """
    return getLogger(moreFrames=1,*args, **kw)

  def quit (self):
    """
    Shut down POX.
    """
    import threading
    if (self.starting_up or
        threading.current_thread() is self.scheduler._thread):
      t = threading.Thread(target=self._quit)
      t.daemon = True
      t.start()
    else:
      self._quit()

  def _quit (self):
    # Should probably do locking here
    if not self.running:
      return
    if self.starting_up:
      # Try again later
      self.quit()
      return

    self.running = False
    log.info("Going down...")
    import gc
    gc.collect()
    try:
      self.raiseEvent(GoingDownEvent())
    except:
      log.exception("While running GoingDownEvent")
    self.callLater(self.scheduler.quit)
    for i in range(50):
      if self.scheduler._hasQuit: break
      gc.collect()
      time.sleep(.1)
    if not self.scheduler._allDone:
      log.warning("Scheduler didn't quit in time")
    self.raiseEvent(DownEvent())
    log.info("Down.")
    #logging.shutdown()
    self.quit_condition.acquire()
    self.quit_condition.notifyAll()
    core.quit_condition.release()

  def _get_python_version (self):
    try:
      import platform
      return "{impl} ({vers}/{build})".format(
       impl=platform.python_implementation(),
       vers=platform.python_version(),
       build=platform.python_build()[1].replace("  "," "))
    except:
      return "Unknown Python"

  def _get_platform_info (self):
    try:
      import platform
      return platform.platform().split("\n")[0]
    except:
      return "Unknown Platform"

  def _add_signal_handlers (self):
    if not self._handle_signals:
      return

    import threading
    # Note, python 3.4 will have threading.main_thread()
    # http://bugs.python.org/issue18882
    if not isinstance(threading.current_thread(), threading._MainThread):
      raise RuntimeError("add_signal_handers must be called from MainThread")

    try:
      previous = signal.getsignal(signal.SIGHUP)
      signal.signal(signal.SIGHUP, self._signal_handler_SIGHUP)
      if previous != signal.SIG_DFL:
        log.warn('Redefined signal handler for SIGHUP')
    except (AttributeError, ValueError):
      # SIGHUP is not supported on some systems (e.g., Windows)
      log.debug("Didn't install handler for SIGHUP")

  def _signal_handler_SIGHUP (self, signal, frame):
    self.raiseLater(core, RereadConfiguration)

  def goUp (self):
    log.debug(self.version_string + " going up...")

    log.debug("Running on " + self._get_python_version())
    log.debug("Platform is " + self._get_platform_info())
    try:
      import platform
      vers = '.'.join(platform.python_version().split(".")[:2])
    except:
      vers = 'an unknown version'
    def vwarn (*args):
      l = logging.getLogger("version")
      if not l.isEnabledFor(logging.WARNING):
        l.setLevel(logging.WARNING)
      l.warn(*args)
    good_versions = ("3.6", "3.7", "3.8", "3.9")
    if vers not in good_versions:
      vwarn("POX requires one of the following versions of Python: %s",
             " ".join(good_versions))
      vwarn("You're running Python %s.", vers)
      vwarn("If you run into problems, try using a supported version.")
    else:
      vwarn("Support for Python 3 is experimental.")

    self.starting_up = False
    self.raiseEvent(GoingUpEvent())

    self._add_signal_handlers()

    if not self._go_up_deferrals:
      self._goUp_stage2()

  def _get_go_up_deferral (self):
    """
    Get a GoingUp deferral

    By doing this, we are deferring progress starting at the GoingUp stage.
    The return value should be called to allow progress again.
    """
    o = object()
    self._go_up_deferrals.add(o)
    def deferral ():
      if o not in self._go_up_deferrals:
        raise RuntimeError("This deferral has already been executed")
      self._go_up_deferrals.remove(o)
      if not self._go_up_deferrals:
        log.debug("Continuing to go up")
        self._goUp_stage2()

    return deferral

  def _goUp_stage2 (self):

    self.raiseEvent(UpEvent())

    self._waiter_notify()

    if self.running:
      log.info(self.version_string + " is up.")

  def _waiter_notify (self):
    if len(self._waiters):
      waiting_for = set()
      for entry in self._waiters:
        _, name, components, _, _ = entry
        components = [c for c in components if not self.hasComponent(c)]
        waiting_for.update(components)
        log.debug("%s still waiting for: %s"
                  % (name, " ".join(components)))
      names = set([n for _,n,_,_,_ in self._waiters])

      #log.info("%i things still waiting on %i components"
      #         % (names, waiting_for))
      log.warn("Still waiting on %i component(s)" % (len(waiting_for),))

  def hasComponent (self, name):
    """
    Returns True if a component with the given name has been registered.
    """
    if name in ('openflow', 'OpenFlowConnectionArbiter'):
      self._openflow_wanted = True
    return name in self.components

  def registerNew (self, __componentClass, *args, **kw):
    """
    Give it a class (and optional __init__ arguments), and it will
    create an instance and register it using the class name.  If the
    instance has a _core_name property, it will use that instead.
    It returns the new instance.
    core.registerNew(FooClass, arg) is roughly equivalent to
    core.register("FooClass", FooClass(arg)).
    """
    name = __componentClass.__name__
    obj = __componentClass(*args, **kw)
    if hasattr(obj, '_core_name'):
      # Default overridden
      name = obj._core_name
    self.register(name, obj)
    return obj

  def register (self, name, component=None):
    """
    Makes the object "component" available as pox.core.core.name.

    If only one argument is specified, the given argument is registered
    using its class name as the name.
    """
    #TODO: weak references?
    if component is None:
      component = name
      name = component.__class__.__name__
      if hasattr(component, '_core_name'):
        # Default overridden
        name = component._core_name

    if name in self.components:
      log.warn("Warning: Registered '%s' multipled times" % (name,))
    self.components[name] = component
    self.raiseEventNoErrors(ComponentRegistered, name, component)
    self._try_waiters()

  def call_when_ready (self, callback, components=[], name=None, args=(),
                       kw={}):
    """
    Calls a callback when components are ready.
    """
    if callback is None:
      callback = lambda:None
      callback.__name__ = "<None>"
    if isinstance(components, str):
      components = [components]
    elif isinstance(components, set):
      components = list(components)
    else:
      try:
        _ = components[0]
        components = list(components)
      except:
        components = [components]
    if name is None:
      #TODO: Use inspect here instead
      name = getattr(callback, '__name__')
      if name is None:
        name = str(callback)
      else:
        name += "()"
        if hasattr(callback, '__self__'):
          name = getattr(callback.__self__.__class__,'__name__','')+'.'+name
      if hasattr(callback, '__module__'):
        # Is this a good idea?  If not here, we should do it in the
        # exception printing in try_waiter().
        name += " in " + callback.__module__
    entry = (callback, name, components, args, kw)
    self._waiters.append(entry)
    self._try_waiter(entry)

  def _try_waiter (self, entry):
    """
    Tries a waiting callback.

    Calls the callback, removes from _waiters, and returns True if
    all are satisfied.
    """
    if entry not in self._waiters:
      # Already handled
      return
    callback, name, components, args_, kw_ = entry
    for c in components:
      if not self.hasComponent(c):
        return False
    self._waiters.remove(entry)
    try:
      if callback is not None:
        callback(*args_,**kw_)
    except:
      import traceback
      msg = "Exception while trying to notify " + name
      import inspect
      try:
        msg += " at " + inspect.getfile(callback)
        msg += ":" + str(inspect.getsourcelines(callback)[1])
      except:
        pass
      log.exception(msg)
    return True

  def _try_waiters (self):
    """
    Tries to satisfy all component-waiting callbacks
    """
    changed = True

    while changed:
      changed = False
      for entry in list(self._waiters):
        if self._try_waiter(entry):
          changed = True

  def listen_to_dependencies (self, sink, components=None, attrs=True,
                              short_attrs=False, listen_args={}):
    """
    Look through *sink* for handlers named like _handle_component_event.
    Use that to build a list of components, and append any components
    explicitly specified by *components*.

    listen_args is a dict of "component_name"={"arg_name":"arg_value",...},
    allowing you to specify additional arguments to addListeners().

    When all the referenced components are registered, do the following:
    1) Set up all the event listeners
    2) Call "_all_dependencies_met" on *sink* if it exists
    3) If attrs=True, set attributes on *sink* for each component
       (e.g, sink._openflow_ would be set to core.openflow)

    For example, if topology is a dependency, a handler for topology's
    SwitchJoin event must be defined as so:
       def _handle_topology_SwitchJoin (self, ...):

    *NOTE*: The semantics of this function changed somewhat in the
            Summer 2012 milestone, though its intention remains the same.
    """
    if components is None:
      components = set()
    elif isinstance(components, str):
      components = set([components])
    else:
      components = set(components)

    for c in dir(sink):
      if not c.startswith("_handle_"): continue
      if c.count("_") < 3: continue
      c = '_'.join(c.split("_")[2:-1])
      components.add(c)

    if None in listen_args:
      # This means add it to all...
      args = listen_args.pop(None)
      for k,v in args.items():
        for c in components:
          if c not in listen_args:
            listen_args[c] = {}
          if k not in listen_args[c]:
            listen_args[c][k] = v

    if set(listen_args).difference(components):
      log.error("Specified listen_args for missing component(s): %s" %
                (" ".join(set(listen_args).difference(components)),))

    def done (sink, components, attrs, short_attrs):
      if attrs or short_attrs:
        for c in components:
          if short_attrs:
            attrname = c
          else:
            attrname = '_%s_' % (c,)
          setattr(sink, attrname, getattr(self, c))
      for c in components:
        if hasattr(getattr(self, c), "_eventMixin_events"):
          kwargs = {"prefix":c}
          kwargs.update(listen_args.get(c, {}))
          getattr(self, c).addListeners(sink, **kwargs)
      getattr(sink, "_all_dependencies_met", lambda : None)()


    self.call_when_ready(done, components, name=sink.__class__.__name__,
                         args=(sink,components,attrs,short_attrs))

    if not self.starting_up:
      self._waiter_notify()

  def __getattr__ (self, name):
    if name in ('openflow', 'OpenFlowConnectionArbiter'):
      self._openflow_wanted = True
    c = self.components.get(name)
    if c is not None: return c
    raise AttributeError("'%s' not registered" % (name,))


core = None

def initialize (threaded_selecthub=True, epoll_selecthub=False,
                handle_signals=True):
  global core
  core = POXCore(threaded_selecthub=threaded_selecthub,
                 epoll_selecthub=epoll_selecthub,
                 handle_signals=handle_signals)
  return core

# The below is a big hack to make tests and doc tools work.
# We should do something better.
def _maybe_initialize ():
  import sys
  if 'unittest' in sys.modules or 'nose' in sys.modules:
    initialize()
    return
  import __main__
  mod = getattr(__main__, '__file__', '')
  if 'pydoc' in mod or 'pdoc' in mod:
    initialize()
    return
_maybe_initialize()
