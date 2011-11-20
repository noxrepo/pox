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
Revent is a custom event library for POX. 

The most common use case of revent is to inherit from EventMixin.

For example:

class Foo (EventMixin):
  def __init__(self):
   # This tells revent that we want to listen to events triggered by pox.core
   self.listenTo(pox.core)
  
  
  def _handle_ComponentRegistered(self, event):
    # The name of this method has a special meaning. Any method with a prefix
    # of '_handle_', and a suffix naming an EventType will automatically
    # be registered as an event handler.
    #  
    # This method will now be called whenever pox.core triggers a 
    # ComponentRegistered event.
    
    # All event handlers are passed an event object as a second parameter. 
    component = event.component
    name = event.name
    print "I see you,", name, "!"

  # A second way to register handlers is to explicitly call self.addListener()
  # For example:
  def bar_handler(self, event):
    print "bar!", event
  
  # This has the same effect as defining a method called "_handle_UpEvent"
  self.addListener(UpEvent, bar_handler)
"""
import operator
# weakrefs are used for some event handlers. 
#
# See: http://docs.python.org/library/weakref.html:
# "A weak reference to an object is not enough to keep the object alive: when the
# only remaining references to a referent are weak references, garbage collection
# is free to destroy the referent"
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
  """
  Mixin to be inherited from if the subclass is interested in handling events
  """
  # What does (_eventMixin_events == True) signify?
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
    """
    Raise an event, but squelch all exception thrown by handler.
    Also see raiseEvent()
    """
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
      if not hasattr(event, 'source') or event.source is None: event.source = self
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
    """
    handlerOrEID : either a reference to a handler object, an integer (EID) 
                  identifying the event type, or (eventType, EID) pair
    eventType : the type of event to remove the listener(s?) for
    """
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
        self._eventMixin_handlers[eventType] = [x for x in handlers if x[3] != handler]
        altered = altered or l != len(self._eventMixin_handlers[event])
    else:
      if eventType == None:
        for event in self._eventMixin_handlers:
          handlers = self._eventMixin_handlers[event]
          l = len(handlers)
          self._eventMixin_handlers[event] = [x for x in handlers if x[1] != handler]
          altered = altered or l != len(self._eventMixin_handlers[event])
      else:
        handlers = self._eventMixin_handlers[eventType]
        l = len(handlers)
        self._eventMixin_handlers[eventType] = [x for x in handlers if x[1] != handler]
        altered = altered or l != len(self._eventMixin_handlers[eventType])

    return altered

  def addListenerByName (self, *args, **kw):
    """
    Add a listener by name. An eventType argument must be present, which is used 
    as the name. A handler argument must also be present.
    
    Also see addListener().
    """
    kw['byName'] = True
    return self.addListener(*args,**kw)

  def addListener (self, eventType, handler, once=False, weak=False, priority=None, byName=False):
    """
    Add an event handler for an event triggered by this object. 
    
    eventType : event class object (e.g. ConnectionUp). If byName is True, should
                be a string (e.g. "ConnectionUp") 
    handler : method object to be invoked on event triggers
    once : whether to stop invoking the handler after the first trigger
    weak : whether to allow the garbage collector to clean up handlers and sources
    priority : the order in which to call event handlers if there are multiple
               for an event type. TODO: priority value may be one of X, Y, or Z
    byName : whether eventType is an event Class or a string name
    
    Raises an exception if eventType is not in the source's _eventMixin_events list
    """
    self._eventMixin_init()
    if self._eventMixin_events != True and eventType not in self._eventMixin_events:
      # eventType wasn't found
      fail = True
      if byName:
        # if we were supposed to find the event by name, see if one of the event
        # names matches
        for e in self._eventMixin_events:
          if issubclass(e, Event):
            if e.__name__ == eventType:
              eventType = e
              fail = False
              break
      if fail:
        raise RuntimeError("Event " + str(eventType) + " not defined on object of type " + str(type(self)))
    if eventType not in self._eventMixin_handlers:
      # if no handler is already registered, initialize handler_list to []
      handler_list = self._eventMixin_handlers[eventType] = []
      self._eventMixin_handlers[eventType] = handler_list
    else:
      handler_list = self._eventMixin_handlers[eventType]

    eid = generateEventID()

    if weak: handler = CallProxy(self, handler, (eventType, eid))

    entry = (priority, handler, once, eid)
    assert entry not in handler_list # what might cause this to happen?
    handler_list.append(entry)
    if handler_list[0][0] != None: # what if a later element in the tuple has a priority?
      # If priority is specified, sort the event handlers
      handler_list.sort(reverse = True, key = operator.itemgetter(0), cmp =
             lambda a,b: (0 if a is None else a) - (0 if b is None else b) )

    return (eventType,eid)

  def listenTo (self, *args, **kv):
    """
    source argument must be present
    
    sink is set to self
    """
    return autoBindEvents(self, *args, **kv)

  def addListeners (self, sink, prefix='', weak=False):
    """
    Reflection foo: pick up all _handle methods defined by sink, and make sure
    they are executed when this object triggers the corresponding events.
    
    sink - the object to trigger listeners for
    
    source is set to self
    """
    return autoBindEvents(sink, self, prefix, weak)


# Not part of the EventMixin class
# (My mental model of Python scoping is thoroughly broken)
def autoBindEvents (sink, source, prefix='', weak=False):
  """
  sink : the class listening to events (EventMixin)
  source : the class triggering events
  prefix : the prefix for the _handle methods. e.g., to listen to
           pox.topology, prefix would be '_pox_core'
  weak : whether 
  """
  if len(prefix) > 0 and prefix[0] != '_': prefix = '_' + prefix
  # ignore source if it does not declare that it raises any the revent events
  if hasattr(source, '_eventMixin_events') == False:
    return []

  events = {}
  for e in source._eventMixin_events:
    if type(e) == str:
      events[e] = e
    else:
      events[e.__name__] = e

  listeners = []
  # for each method in sink
  for m in dir(sink):
    # get the method object
    a = getattr(sink, m)
    if callable(a):
      # if it has the revent prefix signature, 
      if m.startswith("_handle" + prefix):
        m = m[8+len(prefix):]
        # and it is one of the events our source triggers
        if m in events:
          # append the listener
          listeners.append(source.addListener(events[m], a, weak))
          #print "autoBind: ",source,m,"to",sink

  return listeners


class CallProxy (object):
  """
  Custom proxy wrapper for /weak reference/ event handlers.
  Allows garbage collector to remove this handler, and the source
  object?
  """
  def __init__ (self, source, handler, removeData):
    """
    source :  object raising events
    handler : method to be called upon 
    removeData : whether to remove data XXX
    """
    self.source = weakref.ref(source, self.forgetMe)
    self.obj = weakref.ref(handler.im_self, self.forgetMe)
    self.method = handler.im_func
    self.removeData = removeData
    self.name = str(handler)
  def forgetMe (self, o):
    """
    What is the `o` variable used for?
    """
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
    raise RuntimeError("callProxy object is gone!")
  def __str__ (self):
    return "<CallProxy for " + self.name + ">"

"""
TODO
----
decorator for adding event classes to a class?
make mixin-able to existing classes
make mixin-able to existing objects
"""
