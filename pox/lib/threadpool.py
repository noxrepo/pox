# Copyright 2012 James McCauley
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
Totally untested thread pool class.
Tries to not get more than "maximum" (but this is not a hard limit).
Kills off up to around half of its workers when more than half are idle.
"""

from __future__ import with_statement
from threading import Thread, RLock
from Queue import Queue


CYCLE_TIME = 3


class WorkerThread (Thread):
  def __init__ (self, pool):
    Thread.__init__(self)
    self._pool = pool
    self.daemon = True
    self.start()

  def run (self):
    with self._pool._lock:
      self._pool._total += 1

    while self._pool.running:
      with self._pool._lock:
        self._pool._available += 1
      try:
        func, args, kw = self._pool._tasks.get(True, CYCLE_TIME)
        if func is None: return
      except:
        continue
      finally:
        with self._pool._lock:
          self._pool._available -= 1
          assert self._pool._available >= 0

      try:
        func(*args, **kw)
      except Exception as e:
        print "Worker thread exception", e
      self._pool._tasks.task_done()

    with self._pool._lock:
      self._pool._total -= 1
      assert self._pool._total >= 0


class ThreadPool (object):
  #NOTE: Assumes only one thread manipulates the pool
  #      (Add some locks to fix)
  def __init__ (self, initial = 0, maximum = None):
    self._available = 0
    self._total = 0
    self._tasks = Queue()
    self.maximum = maximum
    self._lock = RLock()
    for i in xrange(initial):
      self._new_worker

  def _new_worker (self):
    with self._lock:
      if self.maximum is not None:
        if self._total >= self.maximum:
          # Too many!
          return False
    WorkerThread(self)
    return True

  def add (_self, _func, *_args, **_kwargs):
    self.add_task(_func, args=_args, kwargs=_kwargs)

  def add_task (self, func, args=(), kwargs={}):
    while True:
      self._lock.acquire()
      if self._available == 0:
         self._lock.release()
         self._new_worker()
      else:
        break

    self._tasks.put((func, args, kwargs))

    if self.available > self._total / 2 and self.total > 8:
      for i in xrange(self._total / 2 - 1):
        self._tasks.put((None,None,None))

    self._lock.release()

  def join (self):
    self._tasks.join()
