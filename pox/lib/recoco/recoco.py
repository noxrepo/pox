# Copyright 2011-2013 James McCauley
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

from __future__ import print_function
from collections import deque
from queue import PriorityQueue
from queue import Queue
import time
import threading
from threading import Thread
import select
import traceback
import sys
import os
import socket
import pox.lib.util
import random
from types import GeneratorType
import inspect
from pox.lib.epoll_select import EpollSelect
from pox.lib.util import aslist

#TODO: Need a way to redirect the prints in here to something else (the log).

CYCLE_MAXIMUM = 2

# A ReturnFunction can return this to skip a scheduled slice at the last
# moment.  Whatever the task's current .rf is set to whill be executed
# on the next slice (so by default, this means the same ReturnFunction will
# be executed again).
ABORT = object()

# A ReturnFunction can notify that it has set .re.
EXCEPTION = object()

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

  @classmethod
  def new (cls, *args, **kw):
    """
    Creates a task and starts it on the default scheduler with the
    default priority.
    """
    o = cls(*args, **kw)
    o.start(fast=True)
    return o

  def __init__ (self, *args, **kw):
    #NOTE: keep in sync with Task.__init__ !
    #      (better yet, refactor)
    self.id = generateTaskID()
    self.gen = self.run(*args, **kw)
    assert isinstance(self.gen, GeneratorType), "run() method has no yield"
    self.rv = None
    self.rf = None # ReturnFunc
    self.re = None # ReturnException

  def start (self, scheduler = None, priority = None, fast = False):
    """
    Schedules this task.

    See Scheduler.schedule() and Scheduler.fast_schedule() for the meaning
    of the 'fast' argument.
    """
    if scheduler is None: scheduler = defaultScheduler
    if priority != None: self.priority = priority
    if fast:
      scheduler.fast_schedule(self)
    else:
      scheduler.schedule(self)

  def execute (self):
    if self.rf is not None:
      v = self.rf(self)
      if v is ABORT: return False
      self.rf = None
      self.rv = None
      e = self.re
      self.re = None
      if v == EXCEPTION:
        return self.gen.throw(e)
    elif self.re:
      e = self.re
      self.re = None
      return self.gen.throw(*e)
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

    if self.target:
      self.gen = self.run()
    else:
      self.gen = self.run(*args, **kwargs)
    assert isinstance(self.gen, GeneratorType), "run() method has no yield"

    BaseTask.__init__(self)

  def run (self):
    g = self.target(*self.args, **self.kwargs)
    x = g.send(None)
    while True:
      x = g.send((yield x))

  def __str__ (self):
    return "<%s %s tid:%s>" % (type(self).__name__,
                               getattr(self,'name',object.__str__(self)),
                               getattr(self,'id',None))


class Scheduler (object):
  """ Scheduler for Tasks """

  def __init__ (self, isDefaultScheduler = None, startInThread = True,
                daemon = False, use_epoll=False, threaded_selecthub = True):

    self._ready = deque()
    self._hasQuit = False

    self._selectHub = SelectHub(self, use_epoll=use_epoll,
                                threaded=threaded_selecthub)
    self._thread = None

    self._lock = threading.Lock()
    self._callLaterTask = None
    self._allDone = False

    self._random = random.random

    self._threadlocal = threading.local()

    global defaultScheduler
    if isDefaultScheduler or (isDefaultScheduler is None and
                              defaultScheduler is None):
      defaultScheduler = self

    if startInThread:
      self.runThreaded(daemon)

  def __del__ (self):
    self._hasQuit = True

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
    """
    Returns a Python context manager which blocks the scheduler

    With this, you can write code which runs in another thread like:
      with scheduler.synchronized():
        # Do stuff which assumes co-op tasks aren't running
      # Co-op tasks will resume here
    """
    s = getattr(self._threadlocal, "synchronizer", None)
    if s is None:
      s = Synchronizer(self)
      self._threadlocal.synchronizer = s
    return s

  def schedule (self, task, first = False):
    """
    Schedule the given task to run later.
    If first is True, the task will be the next to run.

    Unlike fast_schedule(), this method will not schedule a task to run
    multiple times.  The one exception is if a Task actually schedules
    itself.  The easiest way to avoid this is simply not to do it.
    See fast_schedule() and ScheduleTask for more info.
    """
    if threading.current_thread() is self._thread:
      # We're know we're good.
      #TODO: Refactor the following with ScheduleTask
      if task in self._ready:
        # It might make sense to keep a flag on the task, since checking
        # if it's in the ready list is not very efficient.
        # Not sure if it makes sense to print out a message here or not.
        import logging
        logging.getLogger("recoco").info("Task %s scheduled multiple " +
                                         "times", task)
        return False
      self.fast_schedule(task, first)
      return True

    st = ScheduleTask(self, task)
    st.start(fast=True)

  def fast_schedule (self, task, first = False):
    """
    Schedule the given task to run later.
    If first is True, the task will be the next to run.

    This method does not protect you from scheduling the same Task more
    than once, which you probably really don't want to do.

    If you are scheduling an existing Task (waking it) from another Task,
    you should either implement your own logic to ensure that you don't
    schedule it multiple times, or you should just use schedule().

    If you are scheduling an existing Task (waking it) from any thread
    besides the one the scheduler is running on, there's a race condition
    which makes it nontrivial to ensure that multiple schedulings never
    happen, and you should just use schedule() for such Tasks.

    If you are scheduling a new Task that you just created, this method
    is always safe.
    """

    # Sanity check.  Won't catch all cases.
    assert task not in self._ready

    if first:
      self._ready.appendleft(task)
    else:
      self._ready.append(task)

    self._selectHub.break_idle()

  def quit (self):
    self._hasQuit = True

  def run (self):
    try:
      while self._hasQuit == False:
        if len(self._ready) == 0:
          self._selectHub.idle()
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
    #TODO: Replace it with something better
    t = None
    try:
      while True:
        t = self._ready.popleft()
        if t.priority >= 1: break
        if len(self._ready) == 0: break
        if t.priority >= self._random(): break
        self._ready.append(t)
    except IndexError:
      return False

    #print(len(self._ready), "tasks")

    while True:
      try:
        rv = t.execute()
      except StopIteration:
        return True
      except:
        try:
          print("Task", t, "caused an exception and was de-scheduled")
          traceback.print_exc()
        except:
          pass
        return True

      if isinstance(rv, BlockingOperation):
        try:
          if rv.execute(t, self) is True:
            continue
        except:
          print("Task", t, "caused an exception during a blocking operation "
                + "and was de-scheduled")
          traceback.print_exc()
      elif rv is False:
        # Just unschedule/sleep
        #print "Unschedule", t, rv
        pass
      elif type(rv) == int or type(rv) == float:
        # Sleep time
        if rv == 0:
          #print "sleep 0"
          self._ready.append(t)
        else:
          self._selectHub.registerTimer(t, rv)
      elif rv == None:
        raise RuntimeError("Must yield a value!")

      break

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


class DummyOp (BlockingOperation):
  """
  A BlockingOperation which just returns a value immediately
  """
  def __init__ (self, rv):
    self.rv = rv
    assert rv is not None

  def execute (self, task, scheduler):
    scheduler.fast_schedule(task)
    task.rv = self.rv

  def __repr__ (self):
    return "%s(%s)" % (type(self).__name__, self.rv)


class CallBlocking (BlockingOperation):
  """
  Syscall that calls an actual blocking operation (like a real .recv()).
  In order to keep from blocking, it calls it on another thread.
  The return value is (ret_val, exc_info), one of which is always None.
  """
  @classmethod
  def new (_cls, _func, *_args, **_kw):
    return _cls(_func, *_args, **_kw)

  def __init__ (self, func, args=(), kw={}):
    self.t = None
    self.scheduler = None
    self.task = None

    self.func = func
    self.args = args
    self.kw = kw

  def _proc (self):
    try:
      self.task.rv = (self.func(*self.args, **self.kw), None)
    except:
      import sys
      self.task.rv = (None, sys.exc_info())

    self.scheduler.fast_schedule(self.task)

  def execute (self, task, scheduler):
    self.task = task
    self.scheduler = scheduler

    #NOTE: It might be nice to use a pool here
    self.t = threading.Thread(target=self._proc)
    #pool.add(self._proc)

    self.t.daemon = True
    self.t.start()


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
    if self._t == 0 or self._t < time.time():
      # Just reschedule
      scheduler.fast_schedule(task)
      return
    scheduler._selectHub.registerTimer(task, self._t, True) # A bit ugly


class _LockAcquire (BlockingOperation):
  """
  Internal use by Lock
  """
  __slots__ = ['_parent', '_blocking']

  def __init__ (self, parent, blocking):
    self._parent = parent
    self._blocking = blocking

  def execute (self, task, scheduler):
    return self._parent._do_acquire(task, scheduler, self._blocking)


class _LockRelease (BlockingOperation):
  """
  Internal use by Lock
  """
  __slots__ = ['_parent']

  def __init__ (self, parent):
    self._parent = parent

  def execute (self, task, scheduler):
    return self._parent._do_release(task, scheduler)


class Lock (object):
  """
  A lock object with similar semantics to the Python Lock.

  Note that it is only safe across Tasks, not Threads.

  Note that as with all recoco "sycalls", you must...
   yield lock.release()
   yield lock.acquire()
  """
  __slots__ = ['_waiting', '_locked']

  def __init__ (self, locked = False):
    self._locked = locked
    self._waiting = set()

  def release (self):
    """
    Release the lock

    Note that this doesn't give up control, so any tasks waiting on the lock
    won't actually run until you do so.
    """
    return _LockRelease(self)

  def acquire (self, blocking = True):
    return _LockAcquire(self, blocking)

  def _do_release (self, task, scheduler):
    if not self._locked:
      raise RuntimeError("You haven't locked this lock")

    self._locked = None

    if self._waiting:
      t = self._waiting.pop()
      self._locked = t
      t.rv = True
      scheduler.fast_schedule(t)

    return True

  def _do_acquire (self, task, scheduler, blocking):
    if not self._locked:
      self._locked = task
      task.rv = True
      return True # Reclaim running state

    if not blocking:
      task.rv = False
      return True # Reclaim running state

    self._waiting.add(task)


class Select (BlockingOperation):
  """
  Should be very similar to Python select.select()
  """
  def __init__ (self, *args, **kw):
    if ( (not isinstance(args[0], (type(None),list)))
      or (not isinstance(args[1], (type(None),list)))
      or (not isinstance(args[2], (type(None),list))) ):
      args = list(args)
      for i in range(3):
        args[i] = None if args[i] is None else aslist(args[i])

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
  def __init__ (self, fd, bufsize = 1024*8, flags = defaultRecvFlags,
                timeout = None):
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
      #traceback.print_exc()
      return None #

  def execute (self, task, scheduler):
    task.rf = self._recvReturnFunc
    scheduler._selectHub.registerSelect(task, [self._fd], None, [self._fd],
                                        timeout=self._timeout)

class RecvFrom (Recv):
  def _recvReturnFunc (self, task):
    # Select() will have placed file descriptors in rv
    if len(task.rv[2]) != 0 or len(task.rv[0]) == 0:
      # Socket error
      task.rv = None
      return None
    sock = task.rv[0][0]
    task.rv = None
    try:
      return sock.recvfrom(self._length, self._flags)
    except:
      #traceback.print_exc()
      return None #

class Send (BlockingOperation):
  def __init__ (self, fd, data, timeout = None, block_size=1024*8):
    # timeout is the amount of time between progress being made, not a total
    # (it's possible this should change)
    self._fd = fd
    self._data = data
    self._sent = 0
    self._scheduler = None
    self._timeout = timeout
    self._block_size = block_size

  def _sendReturnFunc (self, task):
    # Select() will have placed file descriptors in rv
    if len(task.rv[2]) != 0 or len(task.rv[1]) == 0:
      # Socket error
      task.rv = None
      return self._sent
    sock = task.rv[1][0]

    bs = self._block_size
    data = self._data
    if len(data) > bs: data = data[:bs]
    try:
      l = sock.send(data, socket.MSG_DONTWAIT)
    except socket.error:
      # Just try again?
      l = 0

    if l == 0:
      # Select and try again later
      scheduler._selectHub.registerSelect(task, None, [self._fd], [self._fd],
                                          timeout=self._timeout)
      return ABORT

    self._sent += l
    self._data = self._data[l:]
    if not self._data:
      # Done!
      self.rv = None
      return self._sent

    # Still have data to send...
    self.execute(task, self._scheduler)
    return ABORT

  def execute (self, task, scheduler):
    self._scheduler = scheduler
    task.rf = self._sendReturnFunc
    scheduler._selectHub.registerSelect(task, None, [self._fd], [self._fd],
                                        timeout=self._timeout)


class AgainTask (Task):
  def run_again (self):
    parent = self.parent
    g = parent.subtask_func
    parent.task.rv = None

    try:
      nxt = g.send(None)
    except Exception:
      parent.task.re = sys.exc_info()
    else:
      while True:
        if isinstance(nxt, BlockingOperation):
          try:
            v = yield nxt
            do_next = lambda: g.send(v)
          except Exception as e:
            exc_info = sys.exc_info()
            do_next = lambda: g.throw(*exc_info)
          try:
            nxt = do_next()
          except StopIteration:
            # Iterator just ran out, so...
            break
          except Exception:
            parent.task.re = sys.exc_info()
            break
        else:
          # "yield" used like return
          parent.task.rv = nxt
          break
    #print("reschedule",parent.task)
    # Schedule the parent to run next, which maintains the illusion of a
    # function return without the parent have given up its time.
    parent.scheduler.fast_schedule(parent.task, first=True)
  run = run_again

class Again (BlockingOperation):
  """
  A syscall that runs a subtask

  Very useful in task_function decorator form (see its documentation)
  """
  name = "?"

  def __init__ (self, subtask_func):
    self.subtask_func = subtask_func
    self.retval = None

  def execute (self, task, scheduler):
    fn = getattr(self.subtask_func, "__name__", "?")
    n = "%s() from %s" % (fn, task)
    self.name = n
    self.subtask = AgainTask(name=n)
    self.subtask.parent = self
    self.subtask.priority = task.priority
    self.task = task
    self.scheduler = scheduler

    # Instead of using self.subtask.start(scheduler=scheduler), we schedule
    # the subtask by hand using fast_schedule().  This is safe because 1) we
    # can't be racing with the scheduler (we're running under it!), and
    # 2) subtask can't already be scheduled, since it's brand new.  The
    # reason we want to do fast_schedule() is so that we can use first to
    # make it so that the subtask runs next -- this maintains the illusion
    # of a function call which doesn't yield its time.
    scheduler.fast_schedule(self.subtask, first=True)
    #self.subtask.start(scheduler=scheduler)

  def __repr__ (self):
    return "<%s %s>" % (type(self).__name__, self.name)

def task_function (f):
  """
  A decorator for Again()

  An issue with tasks is that they can't just call another function which
  makes its own BlockingOperation syscalls.  With Python 3's yield from,
  it's easy enough (you just need to make the sub-calls with "yield from"!),
  but that doesn't work in Python 2.

  The thing to note about such functions which make their own blocking calls
  is that they are themselves just like a normal top-level task!  Thus, we
  can "call" them by making a new task which runs the sub-function while
  the caller task blocks.  When the sub-function returns, the calling task
  unblocks.  The Again BlockingOperation does exactly this.  Additionally,
  if the sub-function yields a value (instead of a BlockingOperation), then
  the sub-function will stop being scheduled and that value will be Again()'s
  return value.

  The only annoying bit left is that every calling function would need to
  call all its sub-functions with "yield Again(f(...))".  This decorator
  just wraps its function in an Again() call for you, so when you write a
  sub-function, put the decorator on it and it can then just be called
  simply with "yield f(...)".

  TLDR:
   * Put this decorator on a function f()
   * Use "yield" in f() where you would normally use "return"
   * Have f() make calls to other Recoco blocking ops with yield (as usual)
   * You can now call f() from a Recoco task using yield f().
  """
  if not inspect.isgeneratorfunction(f):
    # Well, let's just make it one...
    real_f = f
    def gen_f (*args, **kw):
      yield real_f(*args, **kw)
    f = gen_f
  def run (*args, **kw):
    return Again(f(*args,**kw))
  return run


#TODO: just merge this in with Scheduler?
class SelectHub (object):
  """
  This class is a single select() loop that handles all Select() requests for
  a scheduler as well as timed wakes (i.e., Sleep()).
  """
  def __init__ (self, scheduler, use_epoll=False, threaded=True):
    # We store tuples of (elapse-time, task)
    self._incoming = Queue() # Threadsafe queue for new items

    self._scheduler = scheduler
    self._pinger = pox.lib.util.makePinger()
    if use_epoll:
      self._select_func = EpollSelect().select
    else:
      self._select_func = select.select

    self._tasks = {}

    self._thread = None
    if threaded:
      self._thread = Thread(target = self._threadProc)
      self._thread.daemon = True
      self._thread.start()
      self._event = threading.Event()

  def idle (self):
    """
    Called by the scheduler when the scheduler has nothing to do

    This should block until there's IO or until break_idle().
    (Or at least should block up to CYCLE_MAXIMUM)
    """
    if self._thread:
      # We're running select on another thread

      self._event.wait(CYCLE_MAXIMUM) # Wait for a while
      self._event.clear()
    else:
      # We're running select on the same thread as scheduler
      self._select(self._tasks, {})

  def break_idle (self):
    """
    Break a call to idle()
    """
    if self._thread:
      self._event.set()
    else:
      self._cycle()

  def _threadProc (self):
    tasks = self._tasks
    rets = {}
    _select = self._select
    _scheduler = self._scheduler

    while not _scheduler._hasQuit:
      _select(tasks, rets)

  def _select (self, tasks, rets):
    #print("SelectHub cycle")

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

    #TODO: Fix this.  It's pretty expensive.  There had been some code which
    #      priority heaped this, but I don't think a fully working version
    #      ever quite made it.
    for t,trl,twl,txl,tto in tasks.values():
      if tto != None:
        if tto <= now:
          # Already expired
          if expired is None: expired = []
          expired.append(t)
          if tto-now > 0.1: print("preexpired",tto,now,tto-now)
          continue
        tt = tto - now
        if timeout is None or tt < timeout:
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
    ro, wo, xo = self._select_func( list(rl.keys()) + [self._pinger],
                                    wl.keys(),
                                    xl.keys(), timeout )

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
          self._incoming.task_done()
        if len(ro) == 1 and len(wo) == 0 and len(xo) == 0:
          # Just recycle
          return
        ro.remove(self._pinger)

      # At least one thread is going to be resumed
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

      for t,v in rets.items():
        del tasks[t]
        self._return(t, v)
      rets.clear()

  def registerSelect (self, task, rlist = None, wlist = None, xlist = None,
                      timeout = None, timeIsAbsolute = False):
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
    return self.registerSelect(task, None, None, None, timeToWake,
                               timeIsAbsolute)

  def _return (self, sleepingTask, returnVal):
    #print("reschedule", sleepingTask)
    sleepingTask.rv = returnVal
    self._scheduler.fast_schedule(sleepingTask)


class ScheduleTask (BaseTask):
  """
  If multiple real threads (such as a recoco scheduler thread and any
  other thread, or any two other threads) try to schedule ("wake") the
  same Task with Scheduler.fast_schedule(), there is a race condition where
  the Task may get scheduled multiple times, which is probably quite bad.

  Scheduler.schedule() fixes this by creating one of these ScheduleTasks,
  and it's this ScheduleTask that actually calls fast_schedule().  This
  way, the Task is only ever *really* scheduled from the scheduler thread
  and the race condition doesn't exist.
  """
  def __init__ (self, scheduler, task):
    BaseTask.__init__(self)
    self._scheduler = scheduler
    self._task = task

  def __repr__ (self):
    return "<%s %s>" % (type(self).__name__, self._task)

  def run (self):
    #TODO: Refactor the following, since it is copy/pasted from schedule().
    if self._task in self._scheduler._ready:
      # It might make sense to keep a flag on the task, since checking
      # if it's in the ready list is not very efficient.
      # Not sure if it makes sense to print out a message here or not.
      import logging
      logging.getLogger("recoco").info("Task %s scheduled multiple " +
                                       "times", self._task)
    else:
      self._scheduler.fast_schedule(self._task, True)
    yield False


class SyncTask (BaseTask):
  def __init__ (self, *args, **kw):
    BaseTask.__init__(self)
    self.inlock = threading.Lock()
    self.outlock = threading.Lock()
    self.inlock.acquire()
    self.outlock.acquire()

  def run (self):
    yield 0 # Give away early first slice
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
    return self.syncer

  def __exit__ (self, type_, value, traceback):
    self.enter -= 1
    if self.enter == 0:
      self.syncer.outlock.release()


class Timer (Task):
  """
  A simple timer.

  timeToWake     Amount of time to wait before calling callback (seconds)
  callback       Some callable to be called when the timer expires
  absoluteTime   A specific time to fire (as from time.time())
  recurring      Whether to call repeatedly or just once
  args, kw       Args and keyword args for the callback
  scheduler      The recoco scheduler to use (None means default scheduler)
  started        If False, requires you to call .start() to begin timer
  selfStoppable  If True, the callback can return False to cancel the timer
  """
  def __init__ (self, timeToWake, callback, absoluteTime = False,
                recurring = False, args = (), kw = {}, scheduler = None,
                started = True, selfStoppable = True):
    if absoluteTime and recurring:
      raise RuntimeError("Can't have a recurring timer for an absolute time!")
    Task.__init__(self)
    self._self_stoppable = selfStoppable
    self._cancelled = False

    self._recurring = recurring
    self._callback = callback
    self._args = args
    self._kw = kw

    self._next = timeToWake
    self._interval = timeToWake if recurring else 0
    self._absolute_time = absoluteTime

    self._started = False

    if started: self.start(scheduler)

  def start (self, *args, **kw):
    assert not self._started
    if not self._absolute_time:
      self._next += time.time()
    self._started = True
    return super(Timer,self).start(*args, **kw)

  def cancel (self):
    self._cancelled = True

  def run (self):
    while not self._cancelled:
      yield Sleep(timeToWake=self._next, absoluteTime=True)
      if self._cancelled: break
      self._next = time.time() + self._interval
      rv = self._callback(*self._args,**self._kw)
      if self._self_stoppable and (rv is False): break
      if not self._recurring: break
    yield False # Quit


class CallLaterTask (BaseTask):
  def __init__ (self):
    BaseTask.__init__(self)
    self._pinger = pox.lib.util.makePinger()
    from collections import deque
    self._calls = deque()

  def callLater (self, func, *args, **kw):
    assert callable(func)
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


class BlockingTask (BaseTask):
  @classmethod
  def new (_cls, _func, _cb=None, *_args, **_kw):
    return _cls(_func, _cb, *_args, **_kw)

  def __init__ (self, func, callback=None, args=(), kw={}):
    """
    callback takes two parameters: rv and exc. One is always None.
    if callback is actually a tuple, the first one is called with
    the return value on normal exit, the second is called with
    exc_info on an exception.
    """
    BaseTask.__init__(self)
    self.func = func
    self.callback = callback
    self.args = args
    self.kw = kw

  def run (self):
    rv,exc = (yield CallBlocking(self.func, args=self.args, kw=self.kw))
    if self.callback is None:
      pass
    elif isinstance(self.callback, tuple):
      if exc is not None:
        if self.callback[1] is not None:
          self.callback[1](exc)
      else:
        if self.callback[0] is not None:
          self.callback[0](rv)
    else:
      self.callback(rv,exc)


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
        yield Select([],[],[],sleep)

  s = Scheduler(daemon=True)

  t = TestTask(5,10,sleep=10)
  t.start()

  t = TestTask(100,110,sleep=20)
  t.start()

  #TestTask(1000,1010,sleep=1).start()

  import code
  code.interact(local=locals())

  s.quit()
