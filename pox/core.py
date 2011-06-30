

import inspect
import logging
import time

_path = inspect.stack()[0][1]
#_path = _path[0:_path.rindex('/')] # Uncomment if you want "pox."
_path = _path[0:_path.rindex('/')+1]

SQUELCH_TIME = 5

_squelch = ''
_squelchTime = 0
_squelchCount = 0

def getLogger (name=None):
  if name is None:
    s = inspect.stack()[2]
    name = s[1]
    if name.endswith('.py'):
      name = name[0:-3]    
    if name.startswith(_path):
      name = name[len(_path):]    
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

import pox.lib.recoco.recoco as recoco

class POXCore (EventMixin):
  _eventMixin_events = set([UpEvent, GoingUpEvent, GoingDownEvent])
  
  def __init__ (self):
    self.running = True
    self.components = {}
    
    print "POX v0.0"
    self.scheduler = recoco.Scheduler(daemon=True)

  def getLogger (self, *args, **kw):
    return getLogger(*args, **kw)
    
  def quit (self):
    if self.running:
      print "Quitting..."
      self.raiseEvent(GoingDownEvent())
    self.running = False

  def goUp (self):
    log.debug("Going up...")
    self.raiseEvent(GoingUpEvent())
    log.info("Up...")
    self.raiseEvent(UpEvent())
    
  def register (self, name, component):
    #TODO: weak references?
    if name in self.components:
      log.warn("Warning: Registered '%s' multipled times" % (name,))
    self.components[name] = component

  def __getattr__ (self, name):
    if name not in self.components:
      raise AttributeError("'%s' not registered" % (name,))
    return self.components[name]
    
core = POXCore()

"""
import pox_hub


if __name__ == '__main__':
  hub = pox_hub.ComponentHub()

  hub.launch_component("pox_hub.TimerComponent")
"""
