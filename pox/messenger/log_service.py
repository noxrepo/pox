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

from pox.core import core
from pox.messenger.messenger import *
from pox.lib.revent import autoBindEvents
import logging
import traceback

log = core.getLogger()

# These attributes are copied verbatim from the log record
_attributes = [
  'created','filename','funcName','levelname','levelno','lineno',
  'module','msecs','name','pathname','process','processName',
  'relativeCreated','thread','threadName','args',
]

class LogMessenger (logging.Handler):
  """
  A Python logging.Handler that is a messenger service

  Accepts dictionaries with configuration info:
  KEY         VALUE
  level       Minimum log level to output (probably one of CRITICAL, ERROR,
              WARNING, INFO or DEBUG)
  format      fmt argument to logging.Formatter
  dateFormat  datefmt argument to logging.Formatter
  json        true if you want a bunch of attributes from the LogRecord to be
              included.  In some cases, these are stringized versions since the
              originals are objects and we don't pickle/jsonpickle them.
  """
  def __init__ (self, connection, params):
    logging.Handler.__init__(self)
    self.connection = connection
    connection._newlines = params.get("newlines", True) == True #HACK
    self._json = False
    self._format = False # Not valid, should never be set
    self._dateFormat = None
    if "format" not in params:
      params["format"] = None # Force update
    self._processParameters(params)
    if "opaque" in params:
      self._opaque = params["opaque"]
    else:
      self._opaque = None
    logging.getLogger().addHandler(self)
    self._listeners = autoBindEvents(self, connection) #GC?  Weak?

  def _processParameters (self, params):
    if "level" in params:
      self.setLevel(params["level"])
    if "json" in params:
      self._json = params['json']

    doFormat = False
    if "format" in params:
      fmt = params['format']
      if fmt is not self._format:
        self._format = fmt
        doFormat = True
    if "dateFormat" in params:
      dateFormat = params['dateFormat']
      if dateFormat is not self._dateFormat:
        self._dateFormat = dateFormat
        doFormat = True

    if doFormat:
      self.setFormatter(logging.Formatter(self._format, self._dateFormat))

  def _handle_MessageReceived (self, event, msg):
    if event.con.isReadable():
      r = event.con.read()
      if type(r) is dict:
        self._processParameters(r)
        if "bye" in r:
          event.con.close()

  def _handle_ConnectionClosed (self, event):
    logging.getLogger().removeHandler(self)

  def emit (self, record):
    o = {'message' : self.format(record)}
    if self._opaque is not None:
      o.update(self._opaque)
    #o['message'] = record.getMessage()
    if self._json:
      for attr in _attributes:
        o[attr] = getattr(record, attr)
      o['asctime'] = self.formatter.formatTime(record, self._dateFormat)
      if record.exc_info:
        o['exc_info'] = [str(record.exc_info[0]),
                         str(record.exc_info[1]),
                         traceback.format_tb(record.exc_info[2],1)]
        o['exc'] = traceback.format_exception(*record.exc_info)
    o['type'] = 'log'
    self.connection.send(o, default=str)

class LogMessengerListener (object):
  """
  Takes care of spawning individual LogMessengers

  Hello message is like:
  {"hello":"log"}
  You can also include any of the config parameters for LogMessenger
  (like "level").
  """
  def __init__ (self):
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived)

  def _handle_global_MessageReceived (self, event, msg):
    try:
      json = False
      if msg['hello'] == 'log':
        # It's for me!
        try:
          LogMessenger(event.con, msg)
          event.claim()
          return True # Stop processing this message
        except:
          traceback.print_exc()
    except:
      pass


def launch ():
  def realStart (event=None):
    if not core.hasComponent("messenger"):
      if event is None:
        # Only do this the first time
        log.warning("Deferring firing up LogMessengerListener because Messenger isn't up yet")
      core.addListenerByName("ComponentRegistered", realStart, once=True)
      return
    if not core.hasComponent(LogMessengerListener.__name__):
      core.registerNew(LogMessengerListener)
      log.info("Up...")

  realStart()
