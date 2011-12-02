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

import pox.lib.recoco as recoco
import pox.lib.revent as revent
import threading

class ReventWaiter (revent.EventMixin):
  def __init__ (self):
    self.waitEvents = set()
    revent.EventMixin.__init__(self)
    self._events = recoco.deque()
    self._task = None
    self._scheduler = None
    self._wakeLock = threading.Lock()
    self._wakeable = False

  def registerForEvent (self, eventType, once=False, weak=False, priority=None):
    return self.addListener(eventType, self._eventHandler, once, weak, priority)

  def _eventHandler (self, *args, **kw):
    self._events.append((args, kw))
    self._check()

  def _check (self):
    if len(self._events) > 0:
      if self._task != None and self._scheduler != None:
        self._wakeLock.acquire()
        if self._wakeable:
          self._wakeable = False
          self._wakeLock.release()
          self._scheduler.schedule(self._task)
        else:
          self._wakeLock.release()

  def _reset (self):
    self._wakeLock.acquire()
    self._wakeable = True
    self._wakeLock.release()

  def getEvent (self):
    try:
      return self._events.popleft()
    except:
      return None

class WaitOnEvents (recoco.BlockingOperation):
  def __init__ (self, eventWaiter):
    self._waiter = eventWaiter

  def execute (self, task, scheduler):
    #Next two should go into reset()?
    task.rv = self._waiter
    self._waiter._task = task
    self._waiter._scheduler = scheduler
    self._waiter._reset()
    self._waiter._check()
