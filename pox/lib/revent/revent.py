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
  
  def _eventMixin_init (self):
    if not hasattr(self, "_eventMixin_events"):
      setattr(self, "_eventMixin_events", True)
    if not hasattr(self, "_eventMixin_handlers"):
      setattr(self, "_eventMixin_handlers", {})

  def raiseEventNoErrors (self, event, *args, **kw):
    try:
      self.raiseEvent(event, *args, **kw)
    except:
      print "Event handler raised exception"
      if showEventExceptions:
        import traceback
        traceback.print_exc()
      
  def raiseEvent (self, event, *args, **kw):
    self._eventMixin_init()

    classCall = False
    if isinstance(event, Event):
      eventType = event.__class__
      classCall = True
    elif issubclass(event, Event):
      classCall = True
      eventType = event
      event = eventType(*args, **kw)
      args = ()
      kw = {}
    #print "raise",event,eventType
    if self._eventMixin_events != True and eventType not in self._eventMixin_events:
      raise RuntimeError("Event " + str(eventType) + " not defined on this object")

    # Create a copy so that it can be modified freely during event processing.
    # It might make sense to change this.
    handlers = self._eventMixin_handlers.get(eventType, [])
    for (priority, handler, once, eid) in handlers:
      if type(handler) == weakref.ref:
        handler = handler()
        if handler == None:
          self.removeListener(eid)
          continue
        
      if classCall:
        rv = event._invoke(handler, *args, **kw) 
      else:
        rv = handler(event, *args, **kw)
      if once: self.removeListener(eid)
      if rv == None: continue
      if rv == False:
        self.removeListener(eid) 
      if type(rv) == type(tuple):
        if rv[1] == True:
          self.removeListener(eid) 
        if rv[0]:
          break
      if classCall and hasattr(event, "halt") and event.halt:
        break

  def removeListener (self, handlerOrEID, eventType=None):
    self._eventMixin_init()
    handler = handlerOrEID
    
    altered = False
    if type(handler) == tuple:
      # It's a type/eid pair
      if eventType == None: eventType = handler[0]
      handlers = self._eventMixin_handlers[eventType]
      l = len(handlers)
      self._eventMixin_handlers[eventType] = (x for x in handlers if x(3) != handler[1])
      altered = altered or l != len(self._eventMixin_handlers[eventType])
    elif type(handler) == int:
      # It's an EID
      if eventType == None:
        for event in self._eventmixin_handlers:
          handlers = self._eventmixin_handlers[event]
          l = len(handlers)
          self._eventmixin_handlers[event] = (x for x in handlers if x(3) != handler)
          altered = altered or l != len(self._eventmixin_handlers[event])
      else:
        l = len(handlers)
        handlers = self._eventmixin_handlers[eventType]
        self._eventmixin_handlers[eventtype] = (x for x in handlers if x(3) != handler)
        altered = altered or l != len(self._eventmixin_handlers[event])
    else:
      if eventType == none:
        for event in self._eventmixin_handlers:
          handlers = self._eventmixin_handlers[event]
          l = len(handlers)
          self._eventmixin_handlers[event] = (x for x in handlers if x(1) != handler)
          altered = altered or l != len(self._eventmixin_handlers[event])
      else:
        handlers = self._eventmixin_handlers[eventType]
        l = len(handlers)
        self._eventmixin_handlers[eventtype] = (x for x in handlers if x(1) != handler)
        altered = altered or l != len(self._eventmixin_handlers[eventType])

    return altered
 
  def addListener (self, eventType, handler, once=False, weak=False, priority=None):
    self._eventMixin_init()
    if self._eventMixin_events != True and eventType not in self._eventMixin_events:
      raise RuntimeError("Event " + str(eventType) + " not defined on this object") 
    if eventType not in self._eventMixin_handlers:
      l = self._eventMixin_handlers[eventType] = set()
      self._eventMixin_handlers[eventType] = l
    else:
      l = self._eventMixin_handlers[eventType]
    
    eid = generateEventID()

    if weak: handler = weakref.ref(handler, lambda o: self.removeListener((eventType, eid)))
    
    doSort = priority != None
    if priority == None: priority = 0
    l.add((priority, handler, once, eid))
    if doSort: l.sort(reverse = True, key = operator.itemgetter(0))
      
    return (eventType,eid)

  def listenTo (self, *args, **kv):
    return autoBindEvents(self, *args, **kv)

  def addListeners (self, sink, prefix='', weak=False):
    return autoBindEvents(sink, self, prefix, weak)

def autoBindEvents (sink, source, prefix='', weak=False):
  if len(prefix) > 0 and prefix[0] != '_': prefix = '_' + prefix
  if hasattr(source, '_eventMixin_events') == False:
    return False
    
  events = {}
  for e in source._eventMixin_events:
    if type(e) == str:
      events[e] = e
    else:
      events[e.__name__] = e
      
  for m in dir(sink):
    a = getattr(sink, m)
    if callable(a):
      if m.startswith("_handle" + prefix):
        m = m[8+len(prefix):]
        if m in events:
          source.addListener(events[m], a, weak)

  return True
  
"""
TODO
----
decorator for adding event classes to a class?
make mixin-able to existing classes
make mixin-able to existing objects
"""
