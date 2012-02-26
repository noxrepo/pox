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

"""
Some of POX's core API and functionality is here, largely in the POXCore
class (an instance of which is available as pox.core.core).

This includes things like component rendezvous, logging, system status
(up and down events), etc.
"""

# Set up initial log state
import logging

import inspect
import time
import os

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
    name = s[1]
    if name.endswith('.py'):
      name = name[0:-3]
    elif name.endswith('.pyc'):
      name = name[0:-4]
    if name.startswith(_path):
      name = name[len(_path):]
    elif name.startswith(_ext_path):
      name = name[len(_ext_path):]
    name = name.replace('/', '.').replace('\\', '.') #FIXME: use os.path or whatever

    # Remove double names ("topology.topology" -> "topology")
    if name.find('.') != -1:
      n = name.split('.')
      if len(n) >= 2:
        if n[-1] == n[-2]:
          del n[-1]
          name = '.'.join(n)

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
  pass

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
    Event.__init__(self)
    self.name = name
    self.component = component

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
    ComponentRegistered
  ])

  def __init__ (self):
    self.debug = False
    self.running = True
    self.components = {}

    self.version = (0,0,0)
    print "{0} / Copyright 2011 James McCauley".format(self.version_string)

    self.scheduler = recoco.Scheduler(daemon=True)

  @property
  def version_string (self):
    return "POX " + '.'.join(map(str, self.version))

  def callDelayed (_self, _seconds, _func, *args, **kw):
    """
    Calls the function at a later time.
    This is just a wrapper around a recoco timer.
    """
    t = recoco.Timer(_seconds, _func, args=args, kw=kw,
                     scheduler = _self.scheduler)
    return t

  def callLater (_self, _func, *args, **kw):
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
    if self.running:
      self.running = False
      log.info("Going down...")
      import gc
      gc.collect()
      self.raiseEvent(GoingDownEvent())
      self.callLater(self.scheduler.quit)
      for i in range(50):
        if self.scheduler._hasQuit: break
        gc.collect()
        time.sleep(.1)
      if not self.scheduler._allDone:
        log.warning("Scheduler didn't quit in time")
      self.raiseEvent(DownEvent())
      log.info("Down.")

  def goUp (self):
    log.debug(self.version_string + " going up...")

    import platform
    py = "{impl} ({vers}/{build})".format(
     impl=platform.python_implementation(),
     vers=platform.python_version(),
     build=platform.python_build()[1].replace("  "," "))
    log.debug("Running on " + py)

    self.raiseEvent(GoingUpEvent())
    log.info(self.version_string + " is up.")
    self.raiseEvent(UpEvent())

  def hasComponent (self, name):
    """
    Returns True if a component with the given name has been registered.
    """
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

  def register (self, name, component):
    """
    Makes the object "component" available as pox.core.core.name.
    """
    #TODO: weak references?
    if name in self.components:
      log.warn("Warning: Registered '%s' multipled times" % (name,))
    self.components[name] = component
    self.raiseEventNoErrors(ComponentRegistered, name, component)
    
  def listenToDependencies(self, sink, components):
    """
    If a component depends on having other components
    registered with core before it can boot, it can use this method to 
    check for registration, and listen to events on those dependencies.
    
    Note that event handlers named with the _handle* pattern in the sink must
    include the name of the desired source as a prefix. For example, if topology is a
    dependency, a handler for topology's SwitchJoin event must be labeled:
       def _handle_topology_SwitchJoin(...)
    
    sink - the component waiting on dependencies
    components - a list of dependent component names
    
    Returns whether all of the desired components are registered.
    """
    if components == None or len(components) == 0:
      return True
  
    got = set()
    for c in components:
      if self.hasComponent(c):
        setattr(sink, c, getattr(self, c))
        sink.listenTo(getattr(self, c), prefix=c)
        got.add(c)
      else:
        setattr(sink, c, None)
    for c in got:
      components.remove(c)
    if len(components) == 0:
      log.debug(sink.__class__.__name__ + " ready")
      return True
    return False

  def __getattr__ (self, name):
    if name not in self.components:
      raise AttributeError("'%s' not registered" % (name,))
    return self.components[name]

core = POXCore()
