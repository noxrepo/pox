# Copyright 2011 Colin Scott
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

"""
These are example uses of the recoco cooperative threading library. Hopefully
they will save time for developers getting used to the POX environment.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import *

class EventLoopExample (Task):
   """
   Suppose we have a component of our application that uses it's own event
   loop. recoco allows us to "add" our select loop to the other event
   loops running within pox.

   First note that we inherit from Task. The Task class is recoco's equivalent
   of python's threading.thread interface.
   """
   def __init__(self):
     Task.__init__(self)  # call our superconstructor

     self.sockets = self.get_sockets() # ... the sockets to listen to events on

     # Note! We can't start our event loop until the core is up. Therefore,
     # we'll add an event handler.
     core.addListener(pox.core.GoingUpEvent, self.start_event_loop)

   def start_event_loop(self, event):
     """
     Takes a second parameter: the GoingUpEvent object (which we ignore)
     """
     # This causes us to be added to the scheduler's recurring Task queue
     Task.start(self)

   def get_sockets(self):
     return []

   def handle_read_events(self):
      pass

   def run(self):
     """
     run() is the method that gets called by the scheduler to execute this task
      """
     while core.running:
       """
       This looks almost exactly like python's select.select, except that it's
       it's handled cooperatively by recoco

       The only difference in Syntax is the "yield" statement, and the
       capital S on "Select"
       """
       rlist,wlist,elist = yield Select(self.sockets, [], [], 3)
       events = []
       for read_sock in rlist:
         if read_sock in self.sockets:
           events.append(read_sock)

         if events:
           self.handle_read_events() # ...


"""
And that's it!

TODO: write example usages of the other recoco BlockingTasks, e.g. recoco.Sleep
"""
