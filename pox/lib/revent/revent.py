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

import operator
import weakref

showEventExceptions = False

nextEventID = 0
def generateEventID ():
  global nextEventID
  nextEventID += 1
  return nextEventID

def EventReturn (halt = False, remove = False):
  return (halt, remove)

EventHalt = EventReturn(halt=True)

EventRemove = EventReturn(remove=True)

EventHaltAndRemove = EventReturn(remove=True, halt=True)

class Event (object):
  def __init__ (self):
    self.halt = False
    self.source = None

  def _invoke (self, handler, *args, **kw):
    return handler(self, *args, **kw)

class EventMixin (object):
  _eventMixin_events = set()

  def _eventMixin_addEvent (self, eventType):
    self._eventMixin_init()
    if self._eventMixin_events == True:
      # Do nothing, all events already accepted!
      # print warning?
      return
    elif self._eventMixin_events == None:
      self._eventMixin_events = set()
    self._eventMixin_events.add(eventType)

  def __init__ (self):
    self._eventMixin_init()

  def _eventMixin_init (self):
    if not hasattr(self, "_eventMixin_events"):
      setattr(self, "_eventMixin_events", True)
    if not hasattr(self, "_eventMixin_handlers"):
      setattr(self, "_eventMixin_handlers", {})

  def raiseEventNoErrors (self, event, *args, **kw):
    #TODO: this should really keep subsequent events executing and print the
    #      specific handler that failed...
    try:
      return self.raiseEvent(event, *args, **kw)
    except:
      print "Event handler raised exception"
      if showEventExceptions:
        import traceback
        traceback.print_exc()
    return None

  def raiseEvent (self, event, *args, **kw):
    """
    Raises an event.
    If "event" is an event type, it will be initialized with args and kw, but only
    if there are actually listeners.
    Returns the event object, unless it was never created (because there were no
    listeners) in which case returns None.
    """
    self._eventMixin_init()

    classCall = False
    if isinstance(event, Event):
      eventType = event.__class__
      classCall = True
      if event.source is None: event.source = self
    elif issubclass(event, Event):
      # Check for early-out
      if event not in self._eventMixin_handlers:
        return None
      if len(self._eventMixin_handlers[event]) == 0:
        return None

      classCall = True
      eventType = event
      event = eventType(*args, **kw)
      args = ()
      kw = {}
      if event.source is None: event.source = self
    #print "raise",event,eventType
    if self._eventMixin_events != True and eventType not in self._eventMixin_events:
      raise RuntimeError("Event " + str(eventType) + " not defined on object of type " + str(type(self)))

    # Create a copy so that it can be modified freely during event processing.
    # It might make sense to change this.
    handlers = self._eventMixin_handlers.get(eventType, [])
    for (priority, handler, once, eid) in handlers:
      if classCall:
        rv = event._invoke(handler, *args, **kw)
      else:
        rv = handler(event, *args, **kw)
      if once: self.removeListener(eid)
      if rv is None: continue
      if rv is False:
        self.removeListener(eid)
      if rv is True:
        break
      if type(rv) == tuple:
        if len(rv) >= 2 and rv[1] == True:
          self.removeListener(eid)
        if len(rv) >= 1 and rv[0]:
          break
        if len(rv) == 0:
          break
      #if classCall and hasattr(event, "halt") and event.halt:
      if classCall and event.halt:
        break
    return event

  def removeListeners (self, listeners):
    altered = False
    for l in listeners:
      altered = altered or self.removeListener(l)
    return altered

  def removeListener (self, handlerOrEID, eventType=None):
    #print "Remove listener", handlerOrEID
    self._eventMixin_init()
    handler = handlerOrEID

    altered = False
    if type(handler) == tuple:
      # It's a type/eid pair
      if eventType == None: eventType = handler[0]
      handlers = self._eventMixin_handlers[eventType]
      l = len(handlers)
      self._eventMixin_handlers[eventType] = [x for x in handlers if x[3] != handler[1]]
      altered = altered or l != len(self._eventMixin_handlers[eventType])
    elif type(handler) == int:
      # It's an EID
      if eventType == None:
        for event in self._eventMixin_handlers:
          handlers = self._eventMixin_handlers[event]
          l = len(handlers)
          self._eventMixin_handlers[event] = [x for x in handlers if x[3] != handler]
          altered = altered or l != len(self._eventMixin_handlers[event])
      else:
        l = len(handlers)
        handlers = self._eventMixin_handlers[eventType]
        self._eventMixin_handlers[eventtype] = [x for x in handlers if x[3] != handler]
        altered = altered or l != len(self._eventMixin_handlers[event])
    else:
      if eventType == none:
        for event in self._eventMixin_handlers:
          handlers = self._eventMixin_handlers[event]
          l = len(handlers)
          self._eventMixin_handlers[event] = [x for x in handlers if x[1] != handler]
          altered = altered or l != len(self._eventMixin_handlers[event])
      else:
        handlers = self._eventMixin_handlers[eventType]
        l = len(handlers)
        self._eventMixin_handlers[eventtype] = [x for x in handlers if x[1] != handler]
        altered = altered or l != len(self._eventMixin_handlers[eventType])

    return altered

  def addListenerByName (self, *args, **kw):
    kw['byName'] = True
    return self.addListener(*args,**kw)

  def addListener (self, eventType, handler, once=False, weak=False, priority=None, byName=False):
    self._eventMixin_init()
    if self._eventMixin_events != True and eventType not in self._eventMixin_events:
      fail = True
      if byName:
        for e in self._eventMixin_events:
          if issubclass(e, Event):
            if e.__name__ == eventType:
              eventType = e
              fail = False
              break
      if fail:
        raise RuntimeError("Event " + str(eventType) + " not defined on object of type " + str(type(self)))
    if eventType not in self._eventMixin_handlers:
      l = self._eventMixin_handlers[eventType] = []
      self._eventMixin_handlers[eventType] = l
    else:
      l = self._eventMixin_handlers[eventType]

    eid = generateEventID()

    if weak: handler = CallProxy(self, handler, (eventType, eid))

    entry = (priority, handler, once, eid)
    assert entry not in l
    l.append(entry)
    if l[0][0] != None:
      l.sort(reverse = True, key = operator.itemgetter(0), cmp =
             lambda a,b: (0 if a is None else a) - (0 if b is None else b) )

    return (eventType,eid)

  def listenTo (self, *args, **kv):
    return autoBindEvents(self, *args, **kv)

  def addListeners (self, sink, prefix='', weak=False):
    return autoBindEvents(sink, self, prefix, weak)

def autoBindEvents (sink, source, prefix='', weak=False):
  if len(prefix) > 0 and prefix[0] != '_': prefix = '_' + prefix
  if hasattr(source, '_eventMixin_events') == False:
    return []

  events = {}
  for e in source._eventMixin_events:
    if type(e) == str:
      events[e] = e
    else:
      events[e.__name__] = e

  listeners = []
  for m in dir(sink):
    a = getattr(sink, m)
    if callable(a):
      if m.startswith("_handle" + prefix):
        m = m[8+len(prefix):]
        if m in events:
          listeners.append(source.addListener(events[m], a, weak))
          #print "autoBind: ",source,m,"to",sink

  return listeners


class CallProxy (object):
  def __init__ (self, source, handler, removeData):
    self.source = weakref.ref(source, self.forgetMe)
    self.obj = weakref.ref(handler.im_self, self.forgetMe)
    self.method = handler.im_func
    self.removeData = removeData
    self.name = str(handler)
  def forgetMe (self, o):
    #print "Forgetting",self.removeData,self.method
    source = self.source()
    if source is not None:
      source.removeListener(self.removeData)
    self.obj = None
  def __call__ (self, *args, **kw):
    #print "weak call"
    if self.obj is None: return
    o = self.obj()
    if o is not None:
      return self.method(o, *args, **kw)
    print "callProxy object is gone!"
    raise RuntimeException("callProxy object is gone!")
  def __str__ (self):
    return "<CallProxy for " + self.name + ">"

"""
TODO
----
decorator for adding event classes to a class?
make mixin-able to existing classes
make mixin-able to existing objects
"""
