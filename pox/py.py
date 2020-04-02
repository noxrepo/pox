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
Provides a Python interpreter while running POX
"""

from __future__ import print_function

from pox.core import core
from pox.lib.util import str_to_bool
from pox.lib.revent import EventMixin, Event
import time

def _monkeypatch_console ():
  """
  The readline in pypy (which is the readline from pyrepl) turns off output
  postprocessing, which disables normal NL->CRLF translation.  An effect of
  this is that output *from other threads* (like log messages) which try to
  print newlines end up just getting linefeeds and the output is all stair-
  stepped.  We monkeypatch the function in pyrepl which disables OPOST to
  turn OPOST back on again.  This doesn't immediately seem to break
  anything in the simple cases, and makes the console reasonable to use
  in pypy.
  """
  try:
    import termios
    import sys
    import pyrepl.unix_console
    uc = pyrepl.unix_console.UnixConsole
    old = uc.prepare
    def prep (self):
      old(self)
      f = sys.stdin.fileno()
      a = termios.tcgetattr(f)
      a[1] |= 1 # Turn on postprocessing (OPOST)
      termios.tcsetattr(f, termios.TCSANOW, a)
    uc.prepare = prep
  except:
    pass



class SourceEntered (Event):
  """
  Event raised for each "line" of console input

  If .source is set to None, the code won't be run.
  """
  def __init__ (self, source):
    self.source = source



class Interactive (EventMixin):
  """
  This is how other applications can interact with the interpreter.

  At the moment, it's really limited.
  """
  _eventMixin_events = set([SourceEntered])

  def __init__ (self):
    core.register("Interactive", self)
    self.enabled = False
    self.completion = False
    self.history = False

    #import pox.license
    import sys
    self.variables = dict(locals())
    self.variables['core'] = core

    self.variables['sync'] = False

    class pox_exit (object):
      def __call__ (self, code = 0):
        core.quit()
        sys.exit(code)
      def __repr__ (self):
        return "Use exit() or Ctrl-D (i.e. EOF) to exit POX"
    self.variables['exit'] = pox_exit()

    self.running = False

#    def start (event):
#      if core.Interactive.enabled is not True: return
#      import threading
#      t = threading.Thread(target=self.interact)
#      t.start()
#    core.addListenerByName("UpEvent", start)


  def interact (self):
    """ Begin user interaction """

    import os
    history = self.history
    if history is True:
      history = ".pox_history"
    elif history:
      history = os.path.expanduser(history)
    if history:
      history = os.path.abspath(history)
      import readline, atexit
      _log = core.getLogger("py")
      try:
        readline.read_history_file(history)
        readline.set_history_length(10000)
        _log.debug("Read console history")
      except Exception:
        pass
      def save_history ():
        readline.write_history_file(history)
        _log.debug("Saved console history")
      atexit.register(save_history)

    if self.completion:
      import readline, rlcompleter
      ns = globals().copy()
      ns.update(self.variables)
      # Note that things added to self.variables later won't be available.
      # To fix this, make a dict proxy that actually reads from self.variables
      # *and* globals().
      readline.set_completer(rlcompleter.Completer(ns).complete)
      readline.parse_and_bind("tab: complete")

    _monkeypatch_console()

    #print("This program comes with ABSOLUTELY NO WARRANTY.  This program " \
    #      "is free software,")
    #print("and you are welcome to redistribute it under certain conditions.")
    #print("Type 'help(pox.license)' for details.")

    # Ridiculously gross code to wait for a while before showing the console
    is_up = [False]
    def notify_up ():
      is_up[0] = True
    core.call_later(notify_up)
    while not is_up[0]:
      time.sleep(0.2)
    if core._openflow_wanted: # Hacky
      time.sleep(0.6) # Long enough?
    else:
      time.sleep(0.2)

    if not core.running: return # A race condition, but probably okay

    import code
    import sys
    sys.ps1 = "POX> "
    sys.ps2 = " ... "
    self.running = True

    console = code.InteractiveConsole(self.variables)

    # Patch in the synchronized feature
    real_runcode = console.runcode
    def runcode (code):
      if self.variables['sync'] and core.running:
        with core.scheduler.synchronized():
          return real_runcode(code)
      return real_runcode(code)
    console.runcode = runcode

    # Patch in the event hook; why don't we just subclass InteractiveConsole?!
    real_runsource = console.runsource
    def runsource(source, *args, **kw):
      e = SourceEntered(source)
      self.raiseEvent(e)
      source = e.source
      if source is None: return
      return real_runsource(source, *args, **kw)
    console.runsource = runsource

    try:
      import readline
    except ImportError:
      pass
    console.interact('Ready.', exitmsg='')

    self.running = False
    core.quit()


def launch (disable = False, completion = None, history = False,
            sync = False, __INSTANCE__ = None):
  if not core.hasComponent("Interactive"):
    Interactive()

  from . import boot
  if not disable:
    boot.set_main_function(core.Interactive.interact)
  else:
    boot.set_main_function(None)
  core.Interactive.enabled = not disable
  if completion is not None:
    core.Interactive.completion = str_to_bool(completion)
  if history:
    core.Interactive.history = history
  core.Interactive.variables['sync'] = sync
