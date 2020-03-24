#!/usr/bin/env python

# Copyright 2012 James McCauley
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
This is NOT a POX component.  It's a little tool to test out the messenger.
"""

import socket
import threading
import json

class JSONDestreamer (object):
  import json
  decoder = json.JSONDecoder()
  def __init__ (self, callback = None):
    self._buf = b''
    self.callback = callback if callback else self.rx

  def push (self, data):
    if len(self._buf) == 0:
      data = data.lstrip()
    self._buf += data
    try:
      while len(self._buf) > 0:
        r,off = self.decoder.raw_decode(self._buf.decode())

        self._buf = self._buf[off:].lstrip()
        self.callback(r)
    except ValueError:
      pass

  def rx (self, data):
    import json
    print("Recv:", json.dumps(data, indent=4))

jd = JSONDestreamer()
done = False

def reader (socket):
  global done
  while True:
    d = socket.recv(1024)
    if d == b"":
      done = True
      break
    jd.push(d)

cur_chan = None
def channel (ch):
  global cur_chan
  cur_chan = ch

import readline

def main (addr = "127.0.0.1", port = 7790):
  port = int(port)
  print("Connecting to %s:%i" % (addr,port))

  sock = socket.create_connection((addr, port))

  t = threading.Thread(target=reader, args=(sock,))
  t.daemon = True
  t.start()

  while not done:
    try:
      #print ">",
      m = input()
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
else:
  # This will get run if you try to run this as a POX component.
  def launch ():
    from pox.core import core
    log = core.getLogger()
    log.critical("This isn't a POX component.")
    log.critical("Please see the documentation.")
    raise RuntimeError("This isn't a POX component.")
