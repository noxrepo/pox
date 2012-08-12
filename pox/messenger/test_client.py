#!/usr/bin/env python

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
This is NOT a POX component.  It's a little tool to test out the messenger.
"""

import socket
import threading
import json

class JSONDestreamer (object):
  import json
  decoder = json.JSONDecoder()
  def __init__ (self, callback = None):
    self.data = ''
    self.callback = callback if callback else self.rx

  def push (self, data):
    if len(self.data) == 0:
      data = data.lstrip()
    self.data += data
    try:
      while len(self.data) > 0:
        r,off = self.decoder.raw_decode(self.data)

        self.data = self.data[off:].lstrip()
        self.callback(r)
    except ValueError:
      pass

  def rx (self, data):
    import json
    print "Recv:", json.dumps(data, indent=4)

jd = JSONDestreamer()
done = False

def reader (socket):
  global done
  while True:
    d = socket.recv(1024)
    if d == "":
      done = True
      break
    jd.push(d)

cur_chan = None
def channel (ch):
  global cur_chan
  cur_chan = ch

import readline

def main (addr = "127.0.0.1", port = 7790):
  print "Connecting to %s:%i" % (addr,port)
  port = int(port)

  sock = socket.create_connection((addr, port))

  t = threading.Thread(target=reader, args=(sock,))
  t.daemon = True
  t.start()

  while not done:
    try:
      #print ">",
      m = raw_input()
      if len(m) == 0: continue
      m = eval(m)
      if not isinstance(m, dict):
        continue
      if cur_chan is not None and 'CHANNEL' not in m:
        m['CHANNEL'] = cur_chan
      m = json.dumps(m)
      sock.send(m)
    except EOFError:
      break
    except KeyboardInterrupt:
      break
    except:
      import traceback
      traceback.print_exc()

if __name__ == "__main__":
  import sys
  main(*sys.argv[1:])
