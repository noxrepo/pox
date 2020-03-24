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
import os
base_path = __file__
base_path = os.path.split(base_path)[0]
base_path = os.path.split(base_path)[0]
base_path += os.path.sep

def fmt_tb (tb):
  f = tb.filename
  if f.startswith(base_path):
    f = f[len(base_path):]
  l = "%s:%i" % (f, tb.lineno)
  code = tb.code_context
  if code: code = code[0].strip()
  if not code: code = "<Unknown>"
  return "%20s: %s" % (l,code)

def _trace_thread_proc ():
  try:
    while core.running:
      frames = sys._current_frames()
      for key in frames:
        frame = frames[key]
        print(fmt_tb(inspect.getframeinfo(frame)))
        outer_frames = inspect.getouterframes(frame)
        for i in range(0, len(outer_frames)):
          print("  " + fmt_tb(inspect.getframeinfo(outer_frames[i][0])))

      time.sleep(5)
  except:
    traceback.print_exc()


def launch ():

  _trace_thread = threading.Thread(target=_trace_thread_proc)
  _trace_thread.daemon = True

  # Start it up a bit in the future so that it doesn't print all over
  # init messages.
  core.callDelayed(3, _trace_thread.start)
