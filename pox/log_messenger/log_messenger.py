from pox.core import core
from pox.messenger.messenger import *
from pox.lib.revent.revent import autoBindEvents
import logging
import traceback

log = core.getLogger()

# These attributes are copied verbatim from the log record
_attributes = [
  'created','filename','funcName','levelname','levelno','lineno',
  'module','msecs','name','pathname','process','processName',
  'relativeCreated','thread','threadName',
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
    connection._newlines = True #HACK
    self._json = False
    self._format = False # Not valid, should never be set
    self._dateFormat = None
    if "format" not in params:
      params["format"] = None # Force update
    self._processParameters(params)

    logging.getLogger().addHandler(self)
    autoBindEvents(self, connection) #GC?  Weak?

  def _processParameters (self, params):
    if "level" in params:
      print "set level"
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

  def _handle_MessageRecieved (self, event):
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
    #o['message'] = record.getMessage()
    if self._json:
      for attr in _attributes:
        o[attr] = getattr(record, attr)
      o['args'] = [str(x) for x in record.args]
      o['asctime'] = self.formatter.formatTime(record, self._dateFormat)
      if record.exc_info:
        o['exc_info'] = [str(record.exc_info[0]),
                         str(record.exc_info[1]),
                         traceback.format_tb(record.exc_info[2],1)]
        o['exc'] = traceback.format_exception(*record.exc_info)
    self.connection.send(o)


class LogMessengerListener (object):
  """
  Takes care of spawning individual LogMessengers

  Hello message is like:
  {"hello":"logger"}
  You can also include any of the config parameters for LogMessenger
  (like "level").
  """
  def __init__ (self):
    core.messenger.addListener(MessageRecieved, self._handle_global_MessageRecieved)

  def _handle_global_MessageRecieved (self, event):
    try:
      n = event.con.read()
      json = False
      if n['hello'] == 'logger':
        # It's for me!
        try:
          LogMessenger(event.con, n)
          event.claim()
        except:
          traceback.print_exc()
    except:
      pass


def start ():
  def realStart (event=None):
    if not core.hasComponent("messenger"):
      if event is None:
        # Onyl do this the first time
        log.warning("Deferring firing up LogMessenger because Messenger isn't up yet")
      core.addListenerByName("ComponentRegistered", realStart, once=True)
      return
    global logMessengerListener
    logMessengerListener = LogMessengerListener()
    log.info("Up...")

  realStart()