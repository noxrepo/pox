# Copyright 2013 James McCauley
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
Stuff for implementing simple producer/consumer work queues with recoco.
"""

from pox.core import core
from pox.lib.recoco import Task

from collections import deque

log = core.getLogger()

class BaseConsumer (Task):
  """
  A basic consumer for overriding.

  add_work() adds work (whatever that is)
  _do_work is given work and should do something with it
  _on_exception is called if _do_work() raises an exception
  """
  def __init__ (self, batch_size = 1, priority = 1, start = True):
    """
    batch_size is the maximum number of work items per scheduling
    priority is the Task priority
    """
    self.queue = deque() # work items
    self.running = True # Set to false to stop
    self.log = log

    super(BaseConsumer,self).__init__()
    self.priority = priority
    self.batch_size = batch_size
    if start:
      self.start()

  def add_work (self, work):
    """
    Add a work item
    """
    self.queue.appendleft(work)

    # Since we have work, make sure we're scheduled
    core.scheduler.schedule(self)

  def _on_exception (self, exception, work):
    """
    Override to handle cases where a work item causes an exception

    work is the problematic work item

    return True to keep going
    """
    self.log.error("While executing %s...", work)
    self.log.exception(exception)

    return True

  def _do_work (self, work):
    """
    Do work.

    Override me.
    """
    self.log.error("Don't know how to do work for %s!", work)

  def run (self):
    while core.running and self.running:
      for _ in xrange(min(self.batch_size, len(self.queue))):
        work = self.queue.pop()
        try:
          self._do_work(work)
        except Exception as e:
          if self._on_exception(e, work) is not True:
            self.log.debug("Quitting")
            self.running = False
            break

      if len(self.queue) == 0:
        yield False # Don't reschedule
      else:
        yield 0 # Reschedule ASAP (sleep 0)


class FlexConsumer (BaseConsumer):
  """
  A consumer where work items are callables and their parameters
  """
  def add_work (__self, __callable, *__args, **__kw):
    """
    Add a work item

    A work item is a callable with associated args/kwargs.
    """
    super(FlexConsumer, __self).add_work(__callable, __args, __kw)

  def _do_work (self, work):
    f, args, kw = work
    f(*args, **kw)
