# Copyright 2011,2012,2013 James McCauley
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
Various utility functions

Some of these are POX-specific, and some aren't.
"""

#TODO: Break into multiple modules?  (data structures, POX-specific, etc.)

from __future__ import print_function

import traceback
import struct
import sys
import os
import time
import socket
import collections

from pox.lib.iter import first_of


#FIXME: ugh, why can't I make importing pox.core work here?
import logging
log = logging.getLogger("util")


class ClassicCmp (object):
  """
  Helper for porting Python2 __cmp__ functions to Python 3

  Override _classic__cmp__ to change how it behaves (really, you should
  just rename an old __cmp__ to _classic__cmp__).
  """

  def __lt__ (self, other):
    return self._classic__cmp__(other) < 0

  def __gt__ (self, other):
    return self._classic__cmp__(other) > 0

  def __le__ (self, other):
    return self._classic__cmp__(other) <= 0

  def __gt__ (self, other):
    return self._classic__cmp__(other) >= 0

  def __eq__ (self, other):
    return self._classic__cmp__(other) == 0

  def __ne__ (self, other):
    return self._classic__cmp__(other) != 0



class DirtyList (list):
  """
  A list which keeps track of changes

  When the list is altered, callback (if any) is called, and dirty is set.
  """
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


class DefaultDict (collections.defaultdict):
  """
  A dictionary that can create missing values

  This is similar to (and a subclass of) collections.defaultdict.  However, it
  calls the default factory passing it the missing key.
  """
  #TODO: Make key-passing a constructor option so that this can serve as a
  #      complete defaultdict replacement.
  def __missing__ (self, key):
    v = self.default_factory(key)
    self[key] = v
    return v


def set_extend (l, index, item, emptyValue = None):
  """
  Sets l[index] = item, padding l if needed

  Adds item to the list l at position index.  If index is beyond the end
  of the list, it will pad the list out until it's large enough, using
  emptyValue for the new entries.
  """
  #TODO: Better name?  The 'set' is a bit misleading.
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
  if type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = '-'.join(['%02x' % (x,) for x in dpid[2:]])

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
  allowed_types = "|".join(str(x) for x in types)
  stack = traceback.extract_stack()
  stack_msg = "Function call %s() in %s:%d" % (stack[-2][2],
                                               stack[-3][0], stack[-3][1])
  type_msg = ("%s must be instance of %s (but is %s)"
              % (name, allowed_types , str(type(obj))))

  raise AssertionError(stack_msg + ": " + type_msg)


def init_helper (obj, kw):
  """
  Helper for classes with attributes initialized by keyword arguments.

  Inside a class's __init__, this will copy keyword arguments to fields
  of the same name.  See libopenflow for an example.
  """
  for k,v in kw.items():
    if not hasattr(obj, k):
      raise TypeError(obj.__class__.__name__ + " constructor got "
      + "unexpected keyword argument '" + k + "'")
    setattr(obj, k, v)
initHelper = init_helper # Deprecated


class Pinger (object):
  pass

def make_pinger ():
  """
  A pinger is basically a thing to let you wake a select().

  On Unix systems, this makes a pipe pair.  But on Windows, select() only
  works with sockets, so it makes a pair of connected sockets.
  """
  class PipePinger (Pinger):
    def __init__ (self, pair):
      self._w = pair[1]
      self._r = pair[0]
      assert os is not None

    def ping (self):
      if os is None: return #TODO: Is there a better fix for this?
      os.write(self._w, b' ')

    def fileno (self):
      return self._r

    def pongAll (self): # Deprecated
      return self.pong_all()

    def pong_all (self):
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

  class SocketPinger (Pinger):
    def __init__ (self, pair):
      self._w = pair[1]
      self._r = pair[0]
    def ping (self):
      self._w.send(' ')
    #FIXME: Since the read socket is now nonblocking, there's the possibility
    #       that the recv() calls for pong will not complete.  We should
    #       deal with this.
    def pong (self):
      self._r.recv(1)
    def pongAll (self): # Deprecated
      return self.pong_all()
    def pong_all (self):
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
  #TODO: use socketpair if available?
  localaddresses = ['127.0.0.1', '127.127.127.127'] # Try oddball one first
  startPort = 10000

  import socket
  import select

  def tryConnect ():
    l = None
    localaddress = None
    port = None
    while True:
      if localaddress is None:
        if not localaddresses:
          raise RuntimeError("Could not find a free socket")
        localaddress = localaddresses.pop()
        port = startPort
      try:
        l = socket.socket()
        l.bind( (localaddress, port) )
        l.listen(0)
        break
      except:
        port += 1
        if port - startPort > 1000:
          localaddress = None
    l.setblocking(0)

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

    t = time.time() + 2
    while time.time() < t:
      rlist, wlist,elist = select.select([l], [], [l], 2)
      if len(elist):
        log.warning("makePinger: socket error in select()")
        return False
      if len(rlist) != 0:
        break
    else:
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

    r.setblocking(0)

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
  """
  Converts raw data to a hex dump
  """
  if isinstance(data, (str,bytes)):
    data = [ord(c) for c in data]
  o = ""
  def chunks (data, length):
    return (data[i:i+length] for i in range(0, len(data), length))
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
    l += '  |%-16s|' % (t,)
    o += l
  return o


def connect_socket_with_backoff (address, port, max_backoff_seconds=32):
  """
  Attempt to connect to the given address and port.

  If the connection attempt fails, exponentially back off, up to the maximum.

  return the connected socket, or raise an exception if the connection
  was unsuccessful by the time the maximum was reached.

  Note: blocks while connecting.
  """
  #TODO: Remove?  The backoff IOWorker seems like a better way to do this
  #      in general.
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


_scalar_types = (int, str, float, bool)

def is_scalar (v):
  """
  Is the given value a scalar-like object?
  """
  return isinstance(v, _scalar_types)


def is_listlike (o):
  """
  Is this a sequence that isn't like a string or bytes?
  """
  if isinstance(o, (bytes,str,bytearray)): return False
  return isinstance(o, collections.abc.Iterable)


def fields_of (obj, primitives_only=False,
               primitives_and_composites_only=False, allow_caps=False,
               ignore=set()):
  """
  Returns key/value pairs of things that seem like public fields of an object.
  """
  #NOTE: The above docstring isn't split into two lines on purpose.
  #NOTE: See Python builtin vars().

  r = {}
  for k in dir(obj):
    if k.startswith('_'): continue
    if k in ignore: continue
    v = getattr(obj, k)
    if hasattr(v, '__call__'): continue
    if not allow_caps and k.upper() == k: continue
    if primitives_only:
      if not isinstance(v, _scalar_types):
        continue
    elif primitives_and_composites_only:
      if not isinstance(v, (int, str, bytes, float, bool, set,
                            dict, list)):
        continue
    #r.append((k,v))
    r[k] = v
  return r


def del_values_where (d, f):
  """
  Deletes items from dict if f(value) is True

  This is optimized for cases with few or no removals.
  """
  dead = None
  for k,v in container.items():
    if f(v):
      if not dead: dead = [k]
      else: dead.append(k)
  if dead:
    for k in dead:
      del d[k]


def aslist (l):
  """
  Ensures l is a list without copying it
  """
  if isinstance(l, list): return l
  return list(l)


def eval_args (f):
  """
  A decorator which causes arguments to be interpreted as Python literals

  This isn't a generic decorator, but is specifically meant for POX component
  launch functions -- the actual magic is in POX's boot code.
  The intention is for launch function/commandline arguments (normally all
  strings) to easily receive other types.
  """
  f._pox_eval_args = True
  return f


if __name__ == "__main__":
  #TODO: move to tests?
  def cb (t,k,v): print(v)
  l = DirtyList([10,20,30,40,50])
  l.callback = cb

  l.append(3)

  print(l)
