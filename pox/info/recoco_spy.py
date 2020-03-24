# Copyright 2012 James McCauley
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
    print("c_call")
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
        if sf.f_code == pox.lib.recoco.Scheduler.cycle.__func__.__code__:
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
