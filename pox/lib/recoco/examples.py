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
These are example uses of the recoco cooperative threading library. Hopefully
they will save time for developers getting used to the POX environment.

I can't seem to find any documentation on recoco on the web. Maybe
Murphy rolled recoco himself?
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
