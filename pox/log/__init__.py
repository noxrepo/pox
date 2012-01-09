import logging
from logging.handlers import *

_formatter = logging.Formatter(logging.BASIC_FORMAT)

def _parse (s):
  if s.lower() == "none": return None
  if s.lower() == "false": return False
  if s.lower() == "true": return True
  if s.startswith("0x"): return int(s[2:], 16)
  try:
    return int(s)
  except:
    pass
  try:
    return float(s)
  except:
    pass
  if s.startswith('"') and s.endswith('"') and len(s) >= 2:
    return s[1:-1]
  return s


#NOTE: Arguments are not parsed super-intelligently.  The result is that some
#      cases will be wrong (i.e., filenames that are only numbers or strings
#      with commas).  But I think this should be usable for most common cases.
#      You're welcome to improve it.

def launch (__INSTANCE__ = None, **kw):
  """
  Allows you to configure log handlers from the commandline.

  Examples:
   ./pox.py log --file=pox.log,w --syslog --no-default
   ./pox.py log --*TimedRotatingFile=filename=foo.log,when=D,backupCount=5

  The handlers are most of the ones described in Python's logging.handlers,
  and the special one --no-default, which turns off the default logging to
  stderr.

  Arguments are passed positionally by default.  A leading * makes them pass
  by keyword.

  If a --format="<str>" is specified, it is used as a format string for a
  logging.Formatter instance for all loggers created with that invocation
  of the log module.  If no loggers are created with this instantiation,
  it is used for the default logger.
  """

  if 'format' in kw:
    formatter = logging.Formatter(kw['format'])
    del kw['format']
    if len(kw) == 0:
      # Use for the default logger...
      import pox.core
      pox.core._default_log_handler.setFormatter(formatter)
  else:
    formatter = _formatter

  def standard (use_kw, v, C):
    # Should use a better function than split, which understands
    # quotes and the like.
    if v is True:
      h = C()
    else:
      v = [_parse(p) for p in v.split(',')]
      if use_kw:
        v = dict([x.split('=',1) for x in v])
        h = C(**v)
      else:
        h = C(*v)
    h.setFormatter(formatter)
    logging.getLogger().addHandler(h)

  for _k,v in kw.iteritems():
    k = _k
    use_kw = k.startswith("*")
    if use_kw: k = k[1:]
    k = k.lower()
    if k == "no-default" and v:
      import pox.core
      logging.getLogger().removeHandler(pox.core._default_log_handler)
      logging.getLogger().addHandler(logging.NullHandler())
    elif k == "stderr":
      standard(use_kw, v, lambda : logging.StreamHandler())
    elif k == "stdout":
      import sys
      standard(use_kw, v, lambda : logging.StreamHandler(sys.stdout))
    elif k == "file":
      standard(use_kw, v, logging.FileHandler)
    elif k == "watchedfile":
      standard(use_kw, v, WatchedFileHandler)
    elif k == "rotatingfile":
      standard(use_kw, v, RotatingFileHandler)
    elif k == "timedrotatingfile":
      standard(use_kw, v, TimedRotatingFileHandler)
    elif k == "socket":
      standard(use_kw, v, SocketHandler)
    elif k == "datagram":
      standard(use_kw, v, DatagramHandler)
    elif k == "syslog":
      if v is True:
        v = []
        use_kw = False
      else:
        v = [_parse(p) for p in v.split(',')]
      if use_kw:
        v = dict([x.split('=',1) for x in v])
        if 'address' in v or 'port' in v:
          address = ('localhost', SYSLOG_UDP_PORT)
          v['address'] = (v.get('address', 'localhost'),
                          v.get('port', SYSLOG_UDP_PORT))
          if 'port' in v: del v['port']
        elif 'address' == '' or 'address' == '*':
          v['address'] = '/dev/log'
        h = SysLogHandler(**v)
      else:
        if len(v) > 1:
          v[0] = (v[0], v[1])
          del v[1]
        elif len(v) > 0:
          if v[0] == '' or v[0] == '*':
            v[0] = '/dev/log'
          else:
            v[0] = (v[0], SYSLOG_UDP_PORT)
        h = SysLogHandler(*v)
      logging.getLogger().addHandler(h)
    elif k == "http":
      standard(use_kw, v, HTTPHandler)
    else:
      raise TypeError("Invalid argument: " + _k)
