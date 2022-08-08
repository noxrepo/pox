# Copyright 2011,2022 James McCauley
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

# NOTE: Not platform independent -- uses VT escape codes

# Magic sequence used to introduce a command or color
MAGIC = "@@@"

# Colors for log levels
LEVEL_COLORS = {
  'DEBUG': 'CYAN',
  'INFO': 'GREEN',
  'WARNING': 'YELLOW',
  'ERROR': 'RED',
  'CRITICAL': 'blink@@@RED',
}

# Will get set to True if module is initialized
enabled = False

# Gets set to True if we should strip special sequences but
# not actually try to colorize
_strip_only = False

import logging
import sys

# Name to (intensity, base_value) (more colors added later)
COLORS = {
 'black' : (0,0),
 'red' : (0,1),
 'green' : (0,2),
 'yellow' : (0,3),
 'blue' : (0,4),
 'magenta' : (0,5),
 'cyan' : (0,6),
 'gray' : (0,7),
 'darkgray' : (1,0),
 'pink' : (1,1),
 'white' : (1,7),
}

# Add intense/bold colors (names it capitals)
for _c in [_n for _n,_v in list(COLORS.items()) if _v[0] == 0]:
  COLORS[_c.upper()] = (1,COLORS[_c][1])

COMMANDS = {
  'reset' : 0,
  'bold' : 1,
  'dim' : 2,
  'bright' : 1,
  'dull' : 2,
  'bright:' : 1,
  'dull:' : 2,
  'blink' : 5,
  'noblink' : 25,
  'BLINK' : 6,
  'NOBLINK' : 26,
  'invert' : 7,
  'noinvert' : 27,
  'bg:' : -1, # Special
  'level' : -2, # Special -- color of current level
  'normal' : 22,
  'underline' : 4,
  'nounderline' : 24,
}


# Control Sequence Introducer
CSI = "\033["

def _color (color, msg):
  """ Colorizes the given text """
  return _proc(MAGIC + color) + msg + _proc(MAGIC + 'reset').lower()

def _proc (msg, level_color = "DEBUG"):
  """
  Do some replacements on the text
  """
  msg = msg.split(MAGIC)
  #print "proc:",msg
  r = ''
  i = 0
  cmd = False
  while i < len(msg):
    m = msg[i]
    #print i,m
    i += 1
    if cmd:
      best = None
      bestlen = 0
      for k,v in COMMANDS.items():
        if len(k) > bestlen:
          if m.startswith(k):
            best = (k,v)
            bestlen = len(k)
      special = None
      if best is not None and best[0].endswith(':'):
        special = best
        m = m[bestlen:]
        best = None
        bestlen = 0
      for k,v in COLORS.items():
        if len(k) > bestlen:
          if m.startswith(k):
            best = (k,v)
            bestlen = len(k)
      if best is not None:
        #print "COMMAND", best
        m = m[bestlen:]
        if type(best[1]) is tuple:
          # Color
          brightness,color = best[1]
          if special is not None:
            if special[1] == -1:
              brightness = None
              color += 10
            elif special[1] in (1,2):
              brightness = special[1]
          color += 30
          if not _strip_only:
            r += CSI
            if brightness is not None:
              r += str(brightness) + ";"
            r += str(color) + "m"
        elif not _strip_only:
          # Command
          if best[1] == -2:
            r += _proc(MAGIC + LEVEL_COLORS.get(level_color, ""), level_color)
          else:
            r += CSI + str(best[1]) + "m"
    cmd = True
    r += m
  return r


def launch (entire=False, autolevels=True):
  """
  Enables color logging.

  This does two things.  First, it enables the interpretation of some special
  color-related sequences in the log format string.  Secondly, it applies
  some default colorization to log formats.

  Starting with the second aspect, this can be controlled a bit.  By default,
  the log level name is colorized (entire=False, autolevels=True), and the
  rest of the log message is unaltered (though note that this will require you
  to adjust padding on the %(levelname) part of the log if you use it).
  Setting entire=True will colorize the entire log message based on the log
  level color.  To turn off all auto colorization and just enable the special
  color sequences, set entire=False and autolevels=False.

  The special log sequences all start with "@@@".  The most basic ones are
  just some colors:
    black, red, green, yellow, blue, magenta, cyan, gray, darkgray
    pink, white

  There is also a special "color":
    level - A color based on the log level (e.g., red for errors)

  There are modifier prefixes that you can use with colors.  "bg" and
  "bright" probably almost always work.  "dull" is a maybe.  Examples:
    bg:red
    bright:green
    dull:blue

  You can make text more or less intense.  Depending on the terminal, this
  might either change the boldness of the text or the brightness (or both!):
    bright/bold - Make text brighter or bolder
    dim/dull    - Make text dimmer or duller
    normal      - Make text normal brightness/boldness

  There are some modifiers you can switch on or off:
    blink/noblink
    invert/noinvert
    underline/nounderline

  To get things entirely back to normal in one step (and this may be the
  only way to restore brightness/dullness):
    reset

  For example, try:
   log --format="%(levelname)s: @@@bold%(message)s@@@normal" log.color
  """

  global enabled
  if enabled: return

  from pox.core import core
  log = core.getLogger()

  from pox.lib.util import str_to_bool
  autolevels = str_to_bool(autolevels)

  windows_hack = False

  # Try to work on Windows
  if sys.platform == "win32":
    try:
      from colorama import init
      windows_hack = True
      init()
    except:
      log.info("You need colorama if you want color logging on Windows")
      global _strip_only
      _strip_only = True

  from pox.core import _default_log_handler as dlf
  if not dlf:
    log.warning("Color logging disabled -- no default logger found")
    return
  #if not hasattr(dlf, 'formatter'):
  #  log.warning("Color logging disabled -- no formatter found")
  #  return
  #if not hasattr(dlf.formatter, '_fmt'):
  #  log.warning("Color logging disabled -- formatter unrecognized")
  #  return

  # Monkeypatch in a new format function...
  old_format = dlf.format
  global _old_format
  _old_format = old_format
  if entire:
    def new_format (record):
      msg = _proc(old_format(record), record.levelname)
      color = LEVEL_COLORS.get(record.levelname)
      if color is None:
        return msg
      return _color(color, msg)
  else:
    def new_format (record):
      color = LEVEL_COLORS.get(record.levelname)
      oldlevelname = record.levelname
      if (color is not None) and autolevels:
        record.levelname = "@@@level" + record.levelname + "@@@reset"
      r = _proc(old_format(record), oldlevelname)
      record.levelname = oldlevelname
      return r
  dlf.format = new_format

  if windows_hack:
    if hasattr(dlf, "stream"):
      if dlf.stream is sys.__stderr__:
        dlf.stream = sys.stderr
        enabled = True
  else:
    enabled = True


def disable ():
  global enabled
  if not enabled: return

  import pox.core as core
  core._default_log_handler.format = _old_format
  enabled = False
