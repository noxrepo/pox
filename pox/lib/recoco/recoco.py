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

from __future__ import print_function
from collections import deque
from Queue import PriorityQueue
from Queue import Queue
import time
import threading
from threading import Thread
import select
import traceback
import os
import socket
import pox.lib.util

CYCLE_MAXIMUM = 2

# A ReturnFunction can return this to skip a scheduled slice at the last
# moment.
ABORT = object()

defaultScheduler = None

nextTaskID = 0
def generateTaskID ():
  global nextTaskID
  nextTaskID += 1
  return nextTaskID

class BaseTask  (object):
  id = None
  #running = False
  priority = 1

  def __init__ (self, *args, **kw):
    #NOTE: keep in sync with Task.__init__ !
    #      (better yet, refactor)
    self.id = generateTaskID()
    self.gen = self.run(*args, **kw)
    self.rv = None
    self.rf = None # ReturnFunc

  def start (self, scheduler = None, priority = None):
    if scheduler is None: scheduler = defaultScheduler
    if priority != None: self.priority = priority
    scheduler.schedule(self)

  def execute (self):
    if self.rf is not None:
      v = self.rf(self)
      self.rf = None
      self.rv = None
      if v == ABORT:
        return False
    else:
      v = self.rv
      self.rv = None
    return self.gen.send(v)

  def run (self):
    print("Dummy task")
    yield 0


class Task (BaseTask):
  """
  Provides an interface close to threading.Thread
  """

  def __init__ (self, group=None, target=None, name=None, args=(), kwargs={}):
    #NOTE: keep in sync with BaseTask.__init__ !
    #      (better yet, refactor)
    assert(group == None) # Not supported
    self.id = generateTaskID()
    self.rv = None

    self.name = name
    if name == None: self.name = str(self.id)

    self.target = target
    self.args = args
    self.kwargs = kwargs

    self.gen = self.run(*args, **kwargs)

    BaseTask.__init__(self)


  def run (self):
    return self.target(*self.args, **self.kwargs)

  def __str__ (self):
    return "<" + self.__class__.__name__ + "/tid" + str(self.name) + ">"


class Scheduler (object):
  """ Scheduler for Tasks """
  def __init__ (self, isDefaultScheduler = None, startInThread = True, daemon = False):
    self._ready = deque()
    self._hasQuit = False
    self._selectHub = SelectHub(self)
    self._thread = None
    self._event = threading.Event()

    self._lock = threading.Lock()
    self._callLaterTask = None
    self._allDone = False

    global defaultScheduler
    if isDefaultScheduler or (isDefaultScheduler is None and defaultScheduler is None):
      defaultScheduler = self

    if startInThread:
      self.runThreaded(daemon)

  def __del__ (self):
    self._hasQuit = True
    super(Scheduler, self).__del__()

  def callLater (self, func, *args, **kw):
    """
    Calls func with the given arguments at some later point, within this
    scheduler.  This is a good way for another thread to call something in
    a co-op-thread-safe manner.
    """

    with self._lock:
      if self._callLaterTask is None:
        self._callLaterTask = CallLaterTask()
        self._callLaterTask.start()

    self._callLaterTask.callLater(func, *args, **kw)

  def runThreaded (self, daemon = False):
    self._thread = Thread(target = self.run)
    self._thread.daemon = daemon
    self._thread.start()

  def synchronized (self):
    return Synchronizer(self)

  def schedule (self, task, first = False):
    # The following line is not really guaranteed to catch multiple schedulings
    # of the same task.  So you really should implement your own logic to keep
    # that from happening.

    """
    print("schedule", task, " (",len(self._ready), "already running)")
    import traceback
    traceback.print_stack()
    print("---")
    """

    if task in self._ready:
      raise RuntimeError("Task " + str(task) + " scheduled multiple times")
      #return

    if first:
      self._ready.appendleft(task)
    else:
      self._ready.append(task)

    self._event.set()

  def quit (self):
    self._hasQuit = True

  def run (self):
    try:
      while self._hasQuit == False:
        if len(self._ready) == 0:
          self._event.wait(CYCLE_MAXIMUM) # Wait for a while
          self._event.clear()
          if self._hasQuit: break
        r = self.cycle()
    finally:
      #print("Scheduler done")
      self._hasQuit = True
      self._selectHub._cycle()
      self._allDone = True

  def cycle (self):
    #if len(self._ready) == 0: return False

    # Patented hilarious priority system
    t = None
    try:
      while True:
        t = self._ready.popleft()
        if t >= 1: break
        if random.random() >= t.priority: break
        if len(self._ready) == 1: break
        self._ready.append(t)
    except IndexError:
      return False

    #print(len(self._ready), "tasks")

    try:
      rv = t.execute()
    except StopIteration:
      return True
    except:
      try:
        print("Task", t, "caused exception and was de-scheduled")
        traceback.print_exc()
      except:
        pass
      return True

    if isinstance(rv, BlockingOperation):
      try:
        rv.execute(t, self)
      except:
        print("Task", t, "caused exception during a blocking operation and was de-scheduled")
        traceback.print_exc()
    elif rv is False:
      # Just unschedule/sleep
      #print "Unschedule", t, rv
      pass
    elif type(rv) == int or type(rv) == long or type(rv) == float:
      # Sleep time
      if rv == 0:
        #print "sleep 0"
        self._ready.append(t)
      else:
        self._selectHub.registerTimer(t, rv)
    elif rv == None:
      raise RuntimeError("Must yield a value!")

    return True


#TODO: Read() and Write() BlockingOperations that use nonblocking sockets with
#      SelectHub and do post-processing of the return value.

class BlockingOperation (object):
  """
  A base class for what can be thought of as syscalls for Tasks.
  The separation between __init__ and execute may seem sort of artificial, but
  it serves an actual purpose, which is that it makes it impossible for a task
  to accidentally start to make a syscall (by instantiating a BlockingOperation)
  without actually yielding.
  """
  def __init__ (self):
    """ When the syscall is made by a task, this is executed """
    pass

  def execute (self, task, scheduler):
    """ Scheduler calls this to actually execute the syscall """
    pass


class Exit (BlockingOperation):
  """
  Syscall that kills the scheduler
  """
  def __init__ (self):
    pass

  def execute (self, task, scheduler):
    scheduler.quit()


class Sleep (BlockingOperation):
  """
  Sleep for specified amount of time (seconds)
  None means unscheduler (i.e., sleep until an outside force wakes it)
  0 means reschedule for later (no additional time)
  """
  def __init__ (self, timeToWake = None, absoluteTime = False):
    if absoluteTime == False and timeToWake != None: timeToWake += time.time()
    self._t = timeToWake

  def execute (self, task, scheduler):
    if self._t is None:
      # Just unschedule
      return
    if self._t is 0 or self._t < time.time():
      # Just reschedule
      scheduler.schedule(task)
      return
    scheduler._selectHub.registerTimer(task, self._t, True) # A bit ugly


class Select (BlockingOperation):
  """
  Should be very similar to Python select.select()
  """
  def __init__ (self, *args, **kw):
    self._args = args
    self._kw = kw

  def execute (self, task, scheduler):
    scheduler._selectHub.registerSelect(task, *self._args, **self._kw)


defaultRecvFlags = 0
try:
  defaultRecvFlags = socket.MSG_DONTWAIT
except:
  pass

class Recv (BlockingOperation):
  def __init__ (self, fd, bufsize = 1024*8, flags = defaultRecvFlags, timeout = None):
    """
    Recv call on fd.
    """
    self._fd = fd
    self._length = bufsize
    self._timeout = timeout
    self._flags = flags

  def _recvReturnFunc (self, task):
    # Select() will have placed file descriptors in rv
    if len(task.rv[2]) != 0 or len(task.rv[0]) == 0:
      # Socket error
      task.rv = None
      return None
    sock = task.rv[0][0]
    task.rv = None
    try:
      return sock.recv(self._length, self._flags)
    except:
      traceback.print_exc()
      return None #

  def execute (self, task, scheduler):
    task.rf = self._recvReturnFunc
    scheduler._selectHub.registerSelect(task, [self._fd], None, [self._fd], timeout=self._timeout)


class Send (BlockingOperation):
  def __init__ (self, fd, data):
    self._fd = fd
    self._data = data
    self._sent = 0
    self._scheduler = None

  def _sendReturnFunc (self, task):
    # Select() will have placed file descriptors in rv
    sock = task.rv[1]
    if len(task.rv[2]) != 0:
      # Socket error
      task.rv = None
      return self._sent
    task.rv = None
    try:
      if len(self._data) > 1024:
        data = self._data[:1024]
        self._data = self._data[1024:]
      l = sock.send(data, flags = socket.MSG_DONTWAIT)
      self._sent += l
      if l == len(data) and len(self._data) == 0:
        return self._sent
      self._data = data[l:] + self._data
    except:
      pass

    # Still have data to send...
    self.execute(task, self._scheduler)
    return ABORT

  def execute (self, task, scheduler):
    self._scheduler = scheduler
    task.rf = self._sendReturnFunc
    scheduler._selectHub.registerSelect(task, None, [self._fd], [self._fd])


#TODO: just merge this in with Scheduler?
class SelectHub (object):
  """
  This class is a single select() loop that handles all Select() requests for
  a scheduler as well as timed wakes (i.e., Sleep()).
  """
  def __init__ (self, scheduler):
    # We store tuples of (elapse-time, task)
    self._sleepers = [] # Sleeping items stored as a heap
    self._incoming = Queue() # Threadsafe queue for new items

    self._scheduler = scheduler
    self._pinger = pox.lib.util.makePinger()

    self._ready = False

    self._thread = Thread(target = self._threadProc)
    self._thread.daemon = True
    self._thread.start()

    # Ugly busy wait for initialization
    #while self._ready == False:
    #  time.sleep(0.2)

  def _threadProc (self):
    tasks = {}
    timeouts = []
    expired = []

    while self._scheduler._hasQuit == False:
      #print("SelectHub cycle")

      if len(timeouts) == 0:
        timeout = None
      else:
        timeout = self._sleepers[0][0] - time.time()
        if timeout < 0: timeout = 0

      #NOTE: Everything you select on eventually boils down to file descriptors,
      #      which are unique, obviously.  It might be possible to leverage this
      #      to reduce hashing cost (i.e. by picking a really good hashing
      #      function), though this is complicated by wrappers, etc...
      rl = {}
      wl = {}
      xl = {}

      timeout = None
      timeoutTask = None

      now = time.time()

      expired = None

      for t,trl,twl,txl,tto in tasks.itervalues():
        if tto != None:
          if tto <= now:
            # Already expired
            if expired is None: expired = []
            expired.append(t)
            if tto-now > 0.1: print("preexpired",tto,now,tto-now)
            continue
          tt = tto - now
          if tt < timeout or timeout is None:
            timeout = tt
            timeoutTask = t

        if trl:
          for i in trl: rl[i] = t
        if twl:
          for i in twl: wl[i] = t
        if txl:
          for i in txl: xl[i] = t

      if expired:
        for t in expired:
          del tasks[t]
          self._return(t, ([],[],[]))

      if timeout is None: timeout = CYCLE_MAXIMUM
      ro, wo, xo = select.select(rl.keys() + [self._pinger], wl.keys(), xl.keys(), timeout)

      if len(ro) == 0 and len(wo) == 0 and len(xo) == 0 and timeoutTask != None:
        # IO is idle - dispatch timers / release timeouts
        del tasks[timeoutTask]
        self._return(timeoutTask, ([],[],[]))
      else:
        # We have IO events
        if self._pinger in ro:
          self._pinger.pongAll()
          while not self._incoming.empty():
            stuff = self._incoming.get(True)
            task = stuff[0]
            assert task not in tasks
            tasks[task] = stuff
          if len(ro) == 1 and len(wo) == 0 and len(xo) == 0:
            # Just recycle
            continue
          ro.remove(self._pinger)

        # At least one thread is going to be resumed
        rets = {}
        for i in ro:
          task = rl[i]
          if task not in rets: rets[task] = ([],[],[])
          rets[task][0].append(i)
        for i in wo:
          task = wl[i]
          if task not in rets: rets[task] = ([],[],[])
          rets[task][1].append(i)
        for i in xo:
          task = xl[i]
          if task not in rets: rets[task] = ([],[],[])
          rets[task][2].append(i)

        for t,v in rets.iteritems():
          del tasks[t]
          self._return(t, v)

  def registerSelect (self, task, rlist = None, wlist = None, xlist = None, timeout = None, timeIsAbsolute = False):
    if not timeIsAbsolute:
      if timeout != None:
        timeout += time.time()

    self._incoming.put((task, rlist, wlist, xlist, timeout))
    self._cycle()

  def _cycle (self):
    """
    Cycle the wait thread so that new timers or FDs can be picked up
    """
    self._pinger.ping()

  def registerTimer (self, task, timeToWake, timeIsAbsolute = False):
    """
    Register a task to be wakened up interval units in the future.
    It means timeToWake seconds in the future if absoluteTime is False.
    """
    return self.registerSelect(task, None, None, None, timeToWake, timeIsAbsolute)

  def _return (self, sleepingTask, returnVal):
    #print("reschedule", sleepingTask)
    sleepingTask.rv = returnVal
    self._scheduler.schedule(sleepingTask)


class SyncTask (BaseTask):
  def __init__ (self, *args, **kw):
    BaseTask.__init__(self)
    self.inlock = threading.Lock()
    self.outlock = threading.Lock()
    self.inlock.acquire()
    self.outlock.acquire()

  def run (self):
    self.inlock.release()
    self.outlock.acquire()


class Synchronizer (object):
  def __init__ (self, scheduler = None):
    if scheduler is None:
      scheduler = defaultScheduler
    self.scheduler = scheduler
    self.syncer = None
    self.enter = 0

  def __enter__ (self):
    self.enter += 1
    if self.enter == 1:
      self.syncer = SyncTask()
      self.syncer.start(self.scheduler) #NOTE: maybe add it to head of list?
      self.syncer.inlock.acquire()
    return this.syncer

  def __exit__ (self, type_, value, traceback):
    self.enter -= 1
    if self.enter == 0:
      self.syncer.outlock.release()


class Timer (Task):
  def __init__ (self, timeToWake, callback, absoluteTime = False, recurring = False, args = (), kw = {}, scheduler = None, started = True):
    if absoluteTime and recurring:
      raise RuntimeError("Can't have a recurring timer for an absolute time!")
    Task.__init__(self)
    self._next = timeToWake
    self._interval = timeToWake if recurring else 0
    if not absoluteTime:
      self._next += time.time()

    self._cancelled = False

    self._recurring = recurring
    self._callback = callback
    self._args = args
    self._kw = kw

    if started: self.start(scheduler)

  def cancel (self):
    self._cancelled = True

  def run (self):
    while not self._cancelled:
      yield Sleep(timeToWake=self._next, absoluteTime=True)
      if self._cancelled: break
      self._next = time.time() + self._interval
      self._callback(*self._args,**self._kw)
      if not self._recurring: break
    yield False # Quit


class CallLaterTask (BaseTask):
  def __init__ (self):
    BaseTask.__init__(self)
    self._pinger = pox.lib.util.makePinger()
    from collections import deque
    self._calls = deque()

  def callLater (self, func, *args, **kw):
    self._calls.append((func,args,kw))
    self._pinger.ping()

  def run (self):
    while True:
      yield Select([self._pinger], None, None)
      self._pinger.pongAll()
      try:
        while True:
          e = self._calls.popleft()
          try:
            e[0](*e[1], **e[2])
          except:
            import logging
            logging.getLogger("recoco").exception("Exception calling %s", e[0])
      except:
        pass


# Sanity tests
if __name__ == "__main__":
  class TestTask (BaseTask):
    def __init__ (self, *args, **kw):
      BaseTask.__init__(self, *args, **kw)

    def run (self, a, b, inc = 1, sleep = 0):
      n = a
      while n <= b:
        print(n)
        n+=inc
        yield sleep

  s = Scheduler(daemon=True)

  t = TestTask(5,10,sleep=10)
  t.start()

  t = TestTask(100,110,sleep=20)
  t.start()

  #TestTask(1000,1010,sleep=1).start()

  import code
  code.interact(local=locals())

  s.quit()


