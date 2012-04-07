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

#TODO:
#-----
# decorator for adding event classes to a class?
# make mixin-able to existing classes
# make mixin-able to existing objects

"""
Revent is an event system wherein objects become a composition of data,
methods, and now events.  It fits with the publish/subscribe communication
pattern.

Events themselves are generally instances of some subclass of the Event class.
In fact, they can be arbitrary values of any sort, though subclasses of
Event get special handling (and support for values of other sorts may
eventually be removed).

To subscribe to an event, you create a callback function and register it with
the source.  For example:

def bar_handler(self, event):
  print "bar!", event

pox.core.addListener(UpEvent, bar_handler)


Often (especially if you are going to listen to multiple events from a single
source), it is easier to inherit from EventMixin just so that you can use the
listenTo() method.  For example:

class Sink (EventMixin):
  def __init__(self):
   # This tells revent that we want to listen to events triggered by pox.core
   self.listenTo(pox.core)

  def _handle_ComponentRegistered (self, event):
    # The name of this method has a special meaning. Any method with a prefix
    # of '_handle_', and a suffix naming an EventType that the source
    # publishes will automatically be registered as an event handler.
    #  
    # This method will now be called whenever pox.core triggers a 
    # ComponentRegistered event.

    # Most event handlers are passed an event object as a parameter (though
    # individual Event classes can override this behavior by altering their
    # _invoke() method).
    component = event.component
    name = event.name
    print "I see you,", name, "!"


Event sources can also use the EventMixin library:

class Source (EventMixin):
  # Defining this variable tells the revent library what kind of events this
  # source can raise.
  _eventMixin_events = set([ComponentRegistered])

  def __init__ (self):
    foo()

  def foo (self):
    # We can raise events as follows:
    component = "fake_pox_component"
    self.raiseEvent(ComponentRegistered(component))

    # In the above invocation, the argument is an instance of
    # ComponentRegistered (which is a subclass of Event).  The following is
    # functionally equivalent, but has the nice property that 
    # ComponentRegistered is never instantiated if there are no listeners.
    #self.raiseEvent(ComponentRegistered, component)
    # In both cases, "component" is passed to the __init__ method for the
    # ComponentRegistered class.

    # The above method invocation will raise an exception if an event
    # handler rauses an exception.  To project yourself from exceptions in
    # handlers, see raiseEventNoErrors().
"""
import operator

# weakrefs are used for some event handlers. 
#
# See: http://docs.python.org/library/weakref.html:
# "A weak reference to an object is not enough to keep the object alive: when
# the only remaining references to a referent are weak references, garbage
# collection is free to destroy the referent"
import weakref


_nextEventID = 0
def _generateEventID ():
  """
  Generates an event ID
  This is (at present) mostly so that an event can later be removed.
  Note that this function is not threadsafe.
  """
  global _nextEventID
  _nextEventID += 1
  return _nextEventID


def EventReturn (halt = False, remove = False):
  """
  Event handlers can return special values.  You can craft these with this
  function.

  If halt is True, further handlers will not be called for this particular
  event.

  If remove is True, the handler will be removed (i.e. unsubscribed) and will
  not be called anymore.

  Shortcut names are also available.  You can also simply do:
  return EventHalt
  return EventRemove
  return HaltAndRemove
  """
  return (halt, remove)

EventContinue = EventReturn(halt=False, remove=False)

# Event handlers can return this to stop further handling of this event
EventHalt = EventReturn(halt=True)

# A handler can return this if it wants to remove itself (unsubscribe)
EventRemove = EventReturn(remove=True)

# A handler can return this if it wants to both stop further processing
# and unsubscribe
EventHaltAndRemove = EventReturn(remove=True, halt=True)


class Event (object):
  """
  Superclass for events
  """
  def __init__ (self):
    self.halt = False
    self.source = None

  def _invoke (self, handler, *args, **kw):
    return handler(self, *args, **kw)

def handleEventException (source, event, args, kw, exc_info):
  """
  Called when an exception is raised by an event handler when the event
  was raised by raiseEventNoErrors().

  You can replace this method if you'd like to replace the default handling
  (printing an error message an a traceback) with your own (for example if
  you are using a logging system and would like to use that).  You can also
  replace it with None to have events fail silently.

  "source" is the object sourcing the event.  "event" is the event that was
  being raised when the exception occurred.  "args" and "kw" were the args
  and kwargs passed to raiseEventNoErrors.  "exc_info" is the exception info
  as returned by sys.exc_info()).
  """
  try:
    c = source
    t = event
    if hasattr(c, "__class__"): c = c.__class__.__name__
    if isinstance(t, Event): t = t.__class__.__name__
    elif issubclass(t, Event): t = t.__name__
  except:
    pass
  import sys
  sys.stderr.write("Exception while handling %s!%s...\n" % (c,t))
  import traceback
  traceback.print_exception(*exc_info)


class EventMixin (object):
  """
  Mixin to be inherited from if the subclass is interested in handling events
  """
  # _eventMixin_events contains the set of events that the subclassing object
  # will raise.
  # You can't raise events that aren't in this set.  However, if you set this
  # to True, all events are acceptable.
  _eventMixin_events = set()

  def _eventMixin_addEvents (self, events):
    for e in events:
      self._eventMixin_addEvent(e)
  def _eventMixin_addEvent (self, eventType):
    self._eventMixin_init()
    assert self._eventMixin_events is not True
    if False:
      pass
    #if self._eventMixin_events == True:
    #  # Do nothing, all events already accepted!
    #  # print warning?
    #  return
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
    Raise an event, catching exceptions thrown by the handler.
    If exceptions are caught, the global handleEventExceptions() is called.
    Also see raiseEvent()
    """
    #TODO: this should really keep subsequent events executing and print the
    #      specific handler that failed...
    try:
      return self.raiseEvent(event, *args, **kw)
    except:
      if handleEventException is not None:
        import sys
        handleEventException(self, event, args, kw, sys.exc_info())
    return None

  def raiseEvent (self, event, *args, **kw):
    """
    Raises an event.
    If "event" is an Event type, it will be initialized with args and kw, but
    only if there are actually listeners.
    Returns the event object, unless it was never created (because there were
    no listeners) in which case returns None.
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
      if event.source is None:
        event.source = self
    #print "raise",event,eventType
    if (self._eventMixin_events is not True
        and eventType not in self._eventMixin_events):
      raise RuntimeError("Event " + str(eventType) +
                         " not defined on object of type " + str(type(self)))

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
      if self.removeListener(l): altered = True
    return altered

  def _eventMixin_get_listener_count (self):
    """
    Returns the number of listeners.
    """
    return sum((len(x) for x in self._eventMixin_handlers.itervalues()))

  def removeListener (self, handlerOrEID, eventType=None):
    """
    handlerOrEID : either a reference to a handler object, an event ID (EID) 
                  identifying the event type, or (eventType, EID) pair
    eventType : the type of event to remove the listener(s) for
    """
    #TODO: This method could use an elegant refactoring.

    #print "Remove listener", handlerOrEID
    self._eventMixin_init()
    handler = handlerOrEID

    altered = False
    if type(handler) == tuple:
      # It's a type/eid pair
      if eventType == None: eventType = handler[0]
      handlers = self._eventMixin_handlers[eventType]
      l = len(handlers)
      self._eventMixin_handlers[eventType] = [x for x in handlers
                                              if x[3] != handler[1]]
      altered = altered or l != len(self._eventMixin_handlers[eventType])
    elif type(handler) == int:
      # It's an EID
      if eventType == None:
        for event in self._eventMixin_handlers:
          handlers = self._eventMixin_handlers[event]
          l = len(handlers)
          self._eventMixin_handlers[event] = [x for x in handlers
                                              if x[3] != handler]
          altered = altered or l != len(self._eventMixin_handlers[event])
      else:
        l = len(handlers)
        handlers = self._eventMixin_handlers[eventType]
        self._eventMixin_handlers[eventType] = [x for x in handlers
                                                if x[3] != handler]
        altered = altered or l != len(self._eventMixin_handlers[event])
    else:
      if eventType == None:
        for event in self._eventMixin_handlers:
          handlers = self._eventMixin_handlers[event]
          l = len(handlers)
          self._eventMixin_handlers[event] = [x for x in handlers
                                              if x[1] != handler]
          altered = altered or l != len(self._eventMixin_handlers[event])
      else:
        handlers = self._eventMixin_handlers[eventType]
        l = len(handlers)
        self._eventMixin_handlers[eventType] = [x for x in handlers
                                                if x[1] != handler]
        altered = altered or l != len(self._eventMixin_handlers[eventType])

    return altered

  def addListenerByName (self, *args, **kw):
    """
    Add a listener by name. An eventType argument must be present, which is
    used as the name. A handler argument must also be present.

    Also see addListener().
    """
    kw['byName'] = True
    return self.addListener(*args,**kw)

  def addListener (self, eventType, handler, once=False, weak=False,
                   priority=None, byName=False):
    """
    Add an event handler for an event triggered by this object (subscribe).

    eventType : event class object (e.g. ConnectionUp). If byName is True,
                should be a string (e.g. "ConnectionUp") 
    handler : function/method to be invoked when event is raised 
    once : if True, this handler is removed after the first time it is fired
    weak : If handler is a method on object A, then listening to an event on
           object B will normally make B have a reference to A, so A can not
           be released until after B is released or the listener is removed.
           If weak is True, there is no relationship between the lifetimes of
           the publisher and subscriber.
    priority : The order in which to call event handlers if there are multiple
               for an event type.  Should probably be an integer, where higher
               means to call it earlier.  Do not specify if you don't care.
    byName : True if eventType is a string name, else it's an Event subclass

    Raises an exception unless eventType is in the source's _eventMixin_events
    set (or, alternately, _eventMixin_events must be True).

    The return value can be used for removing the listener.
    """
    self._eventMixin_init()
    if (self._eventMixin_events is not True
        and eventType not in self._eventMixin_events):
      # eventType wasn't found
      fail = True
      if byName:
        # if we were supposed to find the event by name, see if one of the
        # event names matches
        for e in self._eventMixin_events:
          if issubclass(e, Event):
            if e.__name__ == eventType:
              eventType = e
              fail = False
              break
      if fail:
        raise RuntimeError("Event " + str(eventType) +
                           " not defined on object of type " + str(type(self)))
    if eventType not in self._eventMixin_handlers:
      # if no handlers are already registered, initialize
      handlers = self._eventMixin_handlers[eventType] = []
      self._eventMixin_handlers[eventType] = handlers
    else:
      handlers = self._eventMixin_handlers[eventType]

    eid = _generateEventID()

    if weak: handler = CallProxy(self, handler, (eventType, eid))

    entry = (priority, handler, once, eid)

    handlers.append(entry)
    if priority is not None:
      # If priority is specified, sort the event handlers
      handlers.sort(reverse = True, key = operator.itemgetter(0))

    return (eventType,eid)

  def listenTo (self, source, *args, **kv):
    """
    Automatically subscribe to events on source.

    This method tries to bind all _handle_ methods on self to events
    on source.  Kind of the opposite of addListeners().

    See also: addListeners(), autoBindEvents()
    """
    return autoBindEvents(self, source, *args, **kv)

  def addListeners (self, sink, prefix='', weak=False, priority=None):
    """
    Automatically subscribe sink to our events.

    Tries to bind all _handle_ methods on sink to events that this object
    raises.  Kind of the opposite of listenTo().

    See also: listenTo(), autoBindEvents()
    """
    return autoBindEvents(sink, self, prefix, weak, priority)
  
  def clearHandlers(self):
    """
    Remove all handlers from this object
    """
    self._eventMixin_handlers = {}


def autoBindEvents (sink, source, prefix='', weak=False, priority=None):
  """
  Automatically set up listeners on sink for events raised by source.

  Often you have a "sink" object that is interested in multiple events raised
  by some other "source" object.  This method makes setting that up easy.
  You name handler methods on the sink object in a special way.  For example,
  lets say you have an object mySource which raises events of types
  FooEvent and BarEvent.  You have an object mySink which wants to listen
  to these events.  To do so, it names its handler methods "_handle_FooEvent"
  and "_handle_BarEvent".  It can then simply call
  autoBindEvents(mySink, mySource), and the handlers are set up.

  You can also set a prefix which changes how the handlers are to be named.
  For example, autoBindEvents(mySink, mySource, "source1") would use a
  handler named "_handle_source1_FooEvent".

  "weak" has the same meaning as with addListener().

  Returns the added listener IDs (so that you can remove them later).
  """
  if len(prefix) > 0 and prefix[0] != '_': prefix = '_' + prefix
  if hasattr(source, '_eventMixin_events') is False:
    # If source does not declare that it raises any events, do nothing
    print "Warning: source class %s doesn't specify any events!" % (
     source.__class__.__name__,)
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
      if m.startswith("_handle" + prefix + "_"):
        event = m[8+len(prefix):]
        # and it is one of the events our source triggers
        if event in events:
          # append the listener
          listeners.append(source.addListener(events[event], a, weak=weak,
                                              priority=priority))
          #print "autoBind: ",source,m,"to",sink
        elif len(prefix) > 0 and "_" not in event:
          print("Warning: %s found in %s, but %s not raised by %s" %
                (m, sink.__class__.__name__, event, source.__class__.__name__))



  return listeners


class CallProxy (object):
  """
  Internal use.

  Custom proxy wrapper for /weak reference/ event handlers.  When the
  publisher or subscriber objects are lost, this cleans up by removing
  the listener entry in the publisher object.
  """
  def __init__ (self, source, handler, removeData):
    """
    source : Event source (publisher)
    handler : A "weak handler" callback
    removeData :  The identifier used for removal of the handler
    """
    self.source = weakref.ref(source, self._forgetMe)
    self.obj = weakref.ref(handler.im_self, self._forgetMe)
    self.method = handler.im_func
    self.removeData = removeData
    self.name = str(handler)

  def _forgetMe (self, o):
    # o is the weak reference object; we don't use it
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

