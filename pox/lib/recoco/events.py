# Copyright 2011 James McCauley
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
