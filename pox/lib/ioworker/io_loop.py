# Copyright 2017 James McCauley
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

"""
Generic IO loop stuff

Not technically IOWorkers, but might be useful for implementing
IOWorkers.
"""

from pox.lib.recoco import Task, Select
from pox.core import core



class ReadLoop (object):
  """
  Singleton IO Loop

  Serves "clients", which are objects with fileno() and _do_rx() methods.
  You add clients with add() and remove them with remove().
  This class runs a Task which selects on the clients.  When one becomes
  readable, its _do_rx() is called.

  It is intended to be run as a singleton.  A single instance is available
  as ReadLoop.singleton.
  """
  IO_TIMEOUT = 2

  def __init__ (self):
    self._clients = []
    self._started = False
    self._task = None
    core.add_listener(self._handle_GoingDownEvent, weak=True)
    self.running = True

  class _singleton_property (object):
    def __get__ (self, instance, owner):
      if owner._singleton is None:
        owner._singleton = owner()
      return owner._singleton
  _singleton = None
  singleton = _singleton_property()

  def _handle_GoingDownEvent (self, event):
    self.running = False

  def add (self, client):
    #TODO: Should these be weak refs?
    self._clients.append(client)
    self._start()

  def remove (self, client):
    self._clients.remove(client)

  def _start (self):
    if not self._started:
      self._task = Task(target=self._task_proc)
      self._task.start()
      self._started = True

  def _task_proc (self):
    #log.info("%s task starting", type(self).__name__)
    while core.running and self.running:
      rr,ww,xx = yield Select(self._clients, [], [], self.IO_TIMEOUT)
      for client in rr:
        client._do_rx()
    #log.info("%s task quit", type(self).__name__)
