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

"""
Various utility functions
"""

import struct
import sys
import os

#FIXME: ugh, why can't I make importing pox.core work here?
import logging
log = logging.getLogger("util")

class DirtyDict (dict):
  """ A dict that tracks whether values have been changed shallowly. """
  def __init__ (self, *args, **kw):
    dict.__init__(self, *args, **kw)
    self.dirty = False
  def __setitem__ (self, k, v):
    if k not in self:
      self.dirty = True
    elif self[k] != v:
      self.dirty = True
    dict.__setitem__(self, k, v)
  def __delitem__ (self, k):
    self.dirty = True
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

def strToDPID (s):
  """
  Convert a DPID in the canonical string form into a long int.
  """
  s = s.replace("-", "").split("|", 2)
  a = int(s[0], 16)
  b = 0
  if len(s) == 2:
    b = int(s[1])
  return a | (b << 48)

def dpidToStr (dpid, alwaysLong = False):
  """
  Convert a DPID from a long into into the canonical string form.
  """
  """ In flux. """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = '-'.join(['%02x' % (ord(x),) for x in dpid[2:]])

  if alwaysLong or dpid[0:2] != (b'\x00'*2):
    r += '|' + str(struct.unpack('!H', dpid[0:2])[0])

  return r

def initHelper (obj, kw):
  """
  Inside a class's __init__, this will copy keyword arguments to fields
  of the same name.  See libopenflow for an example.
  """
  for k,v in kw.iteritems():
    if not hasattr(obj, k):
      raise TypeError(obj.__class__.__name__ + " constructor got "
      + "unexpected keyword argument '" + k + "'")
    setattr(obj, k, v)

def makePinger ():
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


def str_to_bool (s):
  """
  Given a string, parses out whether it is meant to be True or not
  """
  s = str(s).lower() # Make sure
  if s in ['true', 't', 'yes', 'y', 'on', 'enable', 'enabled', 'ok', 'okay',
           '1']:
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
