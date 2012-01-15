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
This is an extremely primitive start at some debugging.
At the moment, it is really just for recoco (maybe it belongs in there?).
"""

from pox.core import core
log = core.getLogger()
import time
import traceback
import pox.lib.recoco

_frames = []

def _tf (frame, event, arg):
  if _frames is None: return _tf
  #print " " * len(_frames) + event
  if event == 'call':
    _frames.append(frame)
    return _tf
  elif event == 'line':
    return _tf
  elif event == 'exception':
    #_frames.pop()
    return _tf
  elif event == 'return':
    _frames.pop()
  elif event == 'c_call':
    print "c_call"
    _frames.append((frame,arg))
  elif event == 'c_exception':
    _frames.pop()
  elif event == 'c_return':
    _frames.pop()


def _trace_thread_proc ():
  last = None
  last_time = None
  warned = None
  while True:
    try:
      time.sleep(1)
      c = len(_frames)
      if c == 0: continue
      f = _frames[-1]
      stopAt = None
      count = 0
      sf = f
      while sf is not None:
        if sf.f_code == pox.lib.recoco.Scheduler.cycle.im_func.func_code:
          stopAt = sf
          break
        count += 1
        sf = sf.f_back
      #if stopAt == None: continue

      f = "\n".join([s.strip() for s in
                      traceback.format_stack(f,count)])
      #f = " / ".join([s.strip() for s in
      #                traceback.format_stack(f,1)[0].strip().split("\n")])
      #f = "\n".join([s.strip() for s in
      #                traceback.format_stack(f)])

      if f != last:
        if warned:
          log.warning("Running again")
        warned = None
        last = f
        last_time = time.time()
      elif f != warned:
        if time.time() - last_time > 3:
          if stopAt is not None:
            warned = f
            log.warning("Stuck at:\n" + f)

      #from pox.core import core
      #core.f = f

    except:
      traceback.print_exc()
      pass



def launch ():
  def f ():
    import sys
    sys.settrace(_tf)
  core.callLater(f)

  import threading
  _trace_thread = threading.Thread(target=_trace_thread_proc)
  _trace_thread.daemon = True
  _trace_thread.start()
