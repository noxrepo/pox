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
Provides a Python interpreter while running POX
"""

from __future__ import print_function

from pox.core import core
from pox.lib.util import str_to_bool
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


class Interactive (object):
  """
  This is how other applications can interact with the interpreter.

  At the moment, it's really limited.
  """
  def __init__ (self):
    core.register("Interactive", self)
    self.enabled = False
    self.completion = False

    import pox.license
    import sys
    self.variables = dict(locals())
    self.variables['core'] = core

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

    print("This program comes with ABSOLUTELY NO WARRANTY.  This program " \
          "is free software,")
    print("and you are welcome to redistribute it under certain conditions.")
    print("Type 'help(pox.license)' for details.")
    time.sleep(1)

    import code
    import sys
    sys.ps1 = "POX> "
    sys.ps2 = " ... "
    self.running = True
    code.interact('Ready.', local=self.variables)
    self.running = False
    core.quit()


def launch (disable = False, completion = None, __INSTANCE__ = None):
  if not core.hasComponent("Interactive"):
    Interactive()

  import boot
  if not disable:
    boot.set_main_function(core.Interactive.interact)
  else:
    boot.set_main_function(None)
  core.Interactive.enabled = not disable
  if completion is not None:
    core.Interactive.completion = str_to_bool(completion)
