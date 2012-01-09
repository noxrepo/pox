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

# NOTE: Not platform independent -- uses VT escape codes

import logging

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
for _c in [_n for _n,_v in COLORS.items() if _v[0] == 0]:
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
  'BLINK' : 6,
  'invert' : 7,
  'bg:' : -1, # Special
  'normal' : 22,
  'underline' : 4,
  'nounderline' : 24,
}


# Control Sequence Introducer
CSI = "\033["

# Magic sequence used for our special escape sequences
MAGIC = "@@@"

# Colors for log levels
LEVEL_COLORS = {
  'DEBUG': 'CYAN',
  'INFO': 'GREEN',
  'WARNING': 'YELLOW',
  'ERROR': 'red',
  'CRITICAL': 'blink@@@RED',
}

def _color (color, msg):
  """ Colorizes the given text """
  return _proc(MAGIC + color) + msg + _proc(MAGIC + 'reset').lower()

def _proc (msg):
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
      for k,v in COMMANDS.iteritems():
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
      for k,v in COLORS.iteritems():
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
          color += 30
          r += CSI
          if brightness is not None:
            r += str(brightness) + ";"
          r += str(color) + "m"
        else:
          # Command
          r += CSI + str(best[1]) + "m"
    cmd = True
    r += m
  return r


def launch (entire=False):
  """
  If --entire then the whole message is color-coded, otherwise just the
  log level.

  Also turns on interpretation of some special sequences in the log
  format string.  For example, try:
   log --format="%(levelname)s: @@@bold%(message)s@@@normal" log.color
  """

  from pox.core import core
  log = core.getLogger()
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
  if entire:
    def new_format (record):
      msg = _proc(old_format(record))
      color = LEVEL_COLORS.get(record.levelname)
      if color is None:
        return msg
      return _color(color, msg)
  else:
    def new_format (record):
      color = LEVEL_COLORS.get(record.levelname)
      if color is not None:
        record.levelname = _color(color, record.levelname)
      return _proc(old_format(record))
  dlf.format = new_format
