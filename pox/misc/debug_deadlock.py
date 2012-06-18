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
Primitive help for debugging deadlocks.
Prints stack info for all threads.
(Might be more useful if it only printed stack frames that
were not changing, sort of like recoco_spy.)

This was initially factored out from a pox.py modification by
Colin or Andi.
"""

import sys
import time
import inspect
import traceback
import threading
from pox.core import core

def _trace_thread_proc ():
  try:
    while core.running:
      frames = sys._current_frames()
      for key in frames:
        frame = frames[key]
        print inspect.getframeinfo(frame)
        outer_frames = inspect.getouterframes(frame)
        for i in range(0, len(outer_frames)): 
          print "     " + str(inspect.getframeinfo(outer_frames[i][0]))

      time.sleep(5)
  except:
    traceback.print_exc()


def launch ():

  _trace_thread = threading.Thread(target=_trace_thread_proc)
  _trace_thread.daemon = True

  # Start it up a bit in the future so that it doesn't print all over
  # init messages.
  core.callDelayed(3, _trace_thread.start)
