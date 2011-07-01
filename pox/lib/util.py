import struct
import sys
import os

def dpidToStr (dpid):
  """ In flux. """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = '-'.join(['%02x' % (x,) for x in dpid[2:]])
  r += '/' + str(struct.unpack('!H', dpid[0:2]))

  return r

def initHelper (obj, kw):
  for k,v in kw.iteritems():
    if not hasattr(obj, k):
      raise TypeError(obj.__class__.__name__ + " constructor got "
      + "unexpected keyword argument '" + k + "'")
    setattr(obj, k, v)

def makePipe ():
  """
  On Unix systems, this makes a real pipe pair.
  But on Windows, select() doesn't work with anything but sockets,
  so this SHOULD make a pair of localhost sockets instead.
  """
  if os.name is "posix":
    return os.pipe()
  raise RuntimeError("OS not supported")