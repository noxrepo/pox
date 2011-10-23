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
_default_log_handler = logging.StreamHandler()
_default_log_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
logging.getLogger().addHandler(_default_log_handler)
logging.getLogger().setLevel(logging.DEBUG)

import inspect
import time
import os

_path = inspect.stack()[0][1]
_ext_path = _path[0:_path.rindex('/')]
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

from pox.lib.revent.revent import *

class GoingUpEvent (Event):
  """ Fired when system is going up. """
  pass

class GoingDownEvent (Event):
  """ Fired when system is going down. """
  pass

class UpEvent (Event):
  """ Fired when system is up. """
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

import pox.lib.recoco.recoco as recoco

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
    GoingUpEvent,
    GoingDownEvent,
    ComponentRegistered
  ])

  def __init__ (self):
    self.running = True
    self.components = {}

    self.version = (0,0,0)
    print "{0} / Copyright 2011 James McCauley".format(self.version_string)

    self.scheduler = recoco.Scheduler(daemon=True)

  @property
  def version_string (self):
    return "POX " + '.'.join(map(str, self.version))

  def callLater (_self, _func, *args, **kw):
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
      log.info("Quitting...")
      self.raiseEvent(GoingDownEvent())
      self.callLater(self.scheduler.quit)
      for i in range(50):
        if self.scheduler._hasQuit: break
        time.sleep(.1)
      if not self.scheduler._allDone:
        log.warning("Scheduler didn't quit in time")

  def goUp (self):
    log.debug(self.version_string + " going up...")

    import platform
    py = "{impl} ({vers}/{build})".format(
     impl=platform.python_implementation(),
     vers=platform.python_version(),
     build=platform.python_build()[1].replace("  "," "))
    log.debug("Running on " + py)

    self.raiseEvent(GoingUpEvent())
    log.info("Up...")
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

  def __getattr__ (self, name):
    if name not in self.components:
      raise AttributeError("'%s' not registered" % (name,))
    return self.components[name]

core = POXCore()
