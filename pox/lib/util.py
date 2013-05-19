# Copyright 2011,2012 James McCauley
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
Various utility functions
"""

from __future__ import print_function

import traceback
import struct
import sys
import os
import time
import socket

#FIXME: ugh, why can't I make importing pox.core work here?
import logging
log = logging.getLogger("util")


class DirtyList (list):
  #TODO: right now the callback may be called more often than needed
  #      and it may not be called with good names/parameters.
  #      All you can really rely on is that it will be called in
  #      some way if something may have changed.
  def __init__ (self, *args, **kw):
    list.__init__(self, *args, **kw)
    self.dirty = False
    self.callback = None

  def __setslice__ (self, k, v):
    #TODO: actually check for change
    self._smudge('__setslice__', k, v)
    list.__setslice__(self, k, v)

  def __delslice__ (self, k):
    #TODO: actually check for change
    self._smudge('__delslice__', k, None)
    list.__delslice__(self, k)

  def append (self, v):
    self._smudge('append', None, v)
    list.append(self, v)

  def extend (self, v):
    self._smudge('extend', None, v)
    list.extend(self, v)

  def insert (self, i, v):
    self._smudge('insert', k, v)
    list.extend(self, v)

  def pop (self, i=-1):
    self._smudge('pop', i, None)
    list.pop(self, i)

  def remove (self, v):
    if v in self:
      self._smudge('remove', None, v)
    list.remove(self, v)

  def reverse (self):
    if len(self):
      self._smudge('reverse', None, None)
    list.reverse(self)

  def sort (self, *arg, **kw):
    #TODO: check for changes?
    self._smudge('sort', None, None)
    list.sort(self, *arg, **kw)

  def __setitem__ (self, k, v):
    if isinstance(k, slice):
      #TODO: actually check for change
      self._smudge('__setitem__slice',k,v)
    elif self[k] != v:
      self._smudge('__setitem__',k,v)
    list.__setitem__(self, k, v)
    assert good

  def __delitem__ (self, k):
    list.__delitem__(self, k)
    if isinstance(k, slice):
      #TODO: actually check for change
      self._smudge('__delitem__slice',k,v)
    else:
      self._smudge('__delitem__', k, None)

  def _smudge (self, reason, k, v):
    if self.callback:
      if self.callback(reason, k, v) is not True:
        self.dirty = True
    else:
      self.dirty = True


class DirtyDict (dict):
  """
  A dict that tracks whether values have been changed shallowly.
  If you set a callback, it will be called when the value changes, and
  passed three values: "add"/"modify"/"delete", key, value
  """
  def __init__ (self, *args, **kw):
    dict.__init__(self, *args, **kw)
    self.dirty = False
    self.callback = None

  def _smudge (self, reason, k, v):
    if self.callback:
      if self.callback(reason, k, v) is not True:
        self.dirty = True
    else:
      self.dirty = True

  def __setitem__ (self, k, v):
    if k not in self:
      self._smudge('__setitem__add',k,v)
    elif self[k] != v:
      self._smudge('__setitem__modify',k,v)
    dict.__setitem__(self, k, v)

  def __delitem__ (self, k):
    self._smudge('__delitem__', k, None)
    dict.__delitem__(self, k)


def set_extend (l, index, item, emptyValue = None):
  """
  Adds item to the list l at position index.  If index is beyond the end
  of the list, it will pad the list out until it's large enough, using
  emptyValue for the new entries.
  """
  if index >= len(l):
    l += ([emptyValue] * (index - len(self) + 1))
  l[index] = item


def str_to_dpid (s):
  """
  Convert a DPID in the canonical string form into a long int.
  """
  if s.lower().startswith("0x"):
    s = s[2:]
  s = s.replace("-", "").split("|", 2)
  a = int(s[0], 16)
  if a > 0xffFFffFFffFF:
    b = a >> 48
    a &= 0xffFFffFFffFF
  else:
    b = 0
  if len(s) == 2:
    b = int(s[1])
  return a | (b << 48)
strToDPID = str_to_dpid


def dpid_to_str (dpid, alwaysLong = False):
  """
  Convert a DPID from a long into into the canonical string form.
  """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = '-'.join(['%02x' % (ord(x),) for x in dpid[2:]])

  if alwaysLong or dpid[0:2] != (b'\x00'*2):
    r += '|' + str(struct.unpack('!H', dpid[0:2])[0])

  return r
dpidToStr = dpid_to_str # Deprecated


def assert_type(name, obj, types, none_ok=True):
  """
  Assert that a parameter is of a given type.
  Raise an Assertion Error with a descriptive error msg if not.

  name: name of the parameter for error messages
  obj: parameter value to be checked
  types: type or list or tuple of types that is acceptable
  none_ok: whether 'None' is an ok value
  """
  if obj is None:
    if none_ok:
      return True
    else:
      raise AssertionError("%s may not be None" % name)

  if not isinstance(types, (tuple, list)):
    types = [ types ]

  for cls in types:
    if isinstance(obj, cls):
      return True
  allowed_types = "|".join(map(lambda x: str(x), types))
  stack = traceback.extract_stack()
  stack_msg = "Function call %s() in %s:%d" % (stack[-2][2],
                                               stack[-3][0], stack[-3][1])
  type_msg = ("%s must be instance of %s (but is %s)"
              % (name, allowed_types , str(type(obj))))

  raise AssertionError(stack_msg + ": " + type_msg)


def init_helper (obj, kw):
  """
  Inside a class's __init__, this will copy keyword arguments to fields
  of the same name.  See libopenflow for an example.
  """
  for k,v in kw.iteritems():
    if not hasattr(obj, k):
      raise TypeError(obj.__class__.__name__ + " constructor got "
      + "unexpected keyword argument '" + k + "'")
    setattr(obj, k, v)
initHelper = init_helper # Deprecated


def make_pinger ():
  """
  A pinger is basically a thing to let you wake a select().
  On Unix systems, this makes a pipe pair.  But on Windows, select() only
  works with sockets, so it makes a pair of connected sockets.
  """

  class PipePinger (object):
    def __init__ (self, pair):
      self._w = pair[1]
      self._r = pair[0]
      assert os is not None

    def ping (self):
      if os is None: return #TODO: Is there a better fix for this?
      os.write(self._w, ' ')

    def fileno (self):
      return self._r

    def pongAll (self):
      #TODO: make this actually read all
      os.read(self._r, 1024)

    def pong (self):
      os.read(self._r, 1)

    def __del__ (self):
      try:
        os.close(self._w)
      except:
        pass
      try:
        os.close(self._r)
      except:
        pass

    def __repr__ (self):
      return "<%s %i/%i>" % (self.__class__.__name__, self._w, self._r)

  class SocketPinger (object):
    def __init__ (self, pair):
      self._w = pair[1]
      self._r = pair[0]
    def ping (self):
      self._w.send(' ')
    def pong (self):
      self._r.recv(1)
    def pongAll (self):
      #TODO: make this actually read all
      self._r.recv(1024)
    def fileno (self):
      return self._r.fileno()
    def __repr__ (self):
      return "<%s %s/%s>" % (self.__class__.__name__, self._w, self._r)

  #return PipePinger((os.pipe()[0],os.pipe()[1]))  # To test failure case

  if os.name == "posix":
    return PipePinger(os.pipe())

  #TODO: clean up sockets?
  localaddress = '127.127.127.127'
  startPort = 10000

  import socket
  import select

  def tryConnect ():
    l = socket.socket()
    l.setblocking(0)

    port = startPort
    while True:
      try:
        l.bind( (localaddress, port) )
        break
      except:
        port += 1
        if port - startPort > 1000:
          raise RuntimeError("Could not find a free socket")
    l.listen(0)

    r = socket.socket()

    try:
      r.connect((localaddress, port))
    except:
      import traceback
      ei = sys.exc_info()
      ei = traceback.format_exception_only(ei[0], ei[1])
      ei = ''.join(ei).strip()
      log.warning("makePinger: connect exception:\n" + ei)
      return False

    rlist, wlist,elist = select.select([l], [], [l], 2)
    if len(elist):
      log.warning("makePinger: socket error in select()")
      return False
    if len(rlist) == 0:
      log.warning("makePinger: socket didn't connect")
      return False

    try:
      w, addr = l.accept()
    except:
      return False

    #w.setblocking(0)
    if addr != r.getsockname():
      log.info("makePinger: pair didn't connect to each other!")
      return False

    r.setblocking(1)

    # Turn off Nagle
    r.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    w.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    return (r, w)

  # Try a few times
  for i in range(0, 3):
    result = tryConnect()
    if result is not False:
      return SocketPinger(result)

  raise RuntimeError("Could not allocate a local socket pair")
makePinger = make_pinger # Deprecated


def is_subclass (cls, classinfo):
  """
  A more sensible version of the issubclass builtin
  """
  try:
    return issubclass(cls, classinfo)
  except TypeError:
    return False


def str_to_bool (s):
  """
  Given a string, parses out whether it is meant to be True or not
  """
  s = str(s).lower() # Make sure
  if s in ['true', 't', 'yes', 'y', 'on', 'enable', 'enabled', 'ok',
           'okay', '1', 'allow', 'allowed']:
    return True
  try:
    r = 10
    if s.startswith("0x"):
      s = s[2:]
      r = 16
    i = int(s, r)
    if i != 0:
      return True
  except:
    pass
  return False


def hexdump (data):
  if isinstance(data, str):
    data = [ord(c) for c in data]
  o = ""
  def chunks (data, length):
    return (data[i:i+length] for i in xrange(0, len(data), length))
  def filt (c):
    if c >= 32 and c <= 126: return chr(c)
    return '.'

  for i,chunk in enumerate(chunks(data,16)):
    if i > 0: o += "\n"
    o += "%04x: " % (i * 16,)
    l = ' '.join("%02x" % (c,) for  c in chunk)
    l = "%-48s" % (l,)
    l = l[:3*8-1] + "  " + l[3*8:]
    t = ''.join([filt(x) for x in chunk])
    l += '  %-16s' % (t,)
    o += l
  return o


def connect_socket_with_backoff (address, port, max_backoff_seconds=32):
  '''
  Connect to the given address and port. If the connection attempt fails, 
  exponentially back off, up to the max backoff
  
  return the connected socket, or raise an exception if the connection
  was unsuccessful
  '''
  backoff_seconds = 1
  sock = None
  print("connect_socket_with_backoff(address=%s, port=%d)"
        % (address, port), file=sys.stderr)
  while True:
    try:
      sock = socket.socket()
      sock.connect( (address, port) )
      break
    except socket.error as e:
      print("%s. Backing off %d seconds ..." % (str(e), backoff_seconds),
            file=sys.stderr)
      if backoff_seconds >= max_backoff_seconds:
        raise RuntimeError("Could not connect to controller %s:%d"
                           % (address, port))
      else:
        time.sleep(backoff_seconds)
      backoff_seconds <<= 1
  return sock


_scalar_types = (int, long, basestring, float, bool)

def is_scalar (v):
 return isinstance(v, _scalar_types)


def fields_of (obj, primitives_only=False,
               primitives_and_composites_only=False, allow_caps=False):
  """
  Returns key/value pairs of things that seem like public fields of an object.
  """
  #NOTE: The above docstring isn't split into two lines on purpose.

  r = {}
  for k in dir(obj):
    if k.startswith('_'): continue
    v = getattr(obj, k)
    if hasattr(v, '__call__'): continue
    if not allow_caps and k.upper() == k: continue
    if primitives_only:
      if not isinstance(v, _scalar_types):
        continue
    elif primitives_and_composites_only:
      if not isinstance(v, (int, long, basestring, float, bool, set,
                            dict, list)):
        continue
    #r.append((k,v))
    r[k] = v
  return r


if __name__ == "__main__":
  #TODO: move to tests?
  def cb (t,k,v): print(v)
  l = DirtyList([10,20,30,40,50])
  l.callback = cb

  l.append(3)

  print(l)
