#!/usr/bin/env python

# Copyright 2011 James McCauley
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

import json
import sys
import socket

decoder = json.JSONDecoder()

host = "localhost"
port = 7790

if len(sys.argv) >= 2 : host = sys.argv[1]
if len(sys.argv) >= 3 : port = int(sys.argv[2])

while True:
  try:
    sock = socket.socket()
    sock.connect((host,port))
    print "== Connected =="
    buf = ''
    try:
      sock.send('{"hello":"logger","format":"%(levelname)-8s | %(name)-15s | %(message)s"}')
      while True:
        d = sock.recv(1024)
        if len(d) == 0: raise RuntimeError()
        if len(buf) == 0: d = d.lstrip() # protect from whitespace
        buf += d
        try:
          while len(buf) > 0:
            o = decoder.raw_decode(buf)
            buf = buf[o[1]:].lstrip() # protect from whitespace
            print o[0]['message']
        except:
          pass
    except KeyboardInterrupt:
      break
    except:
      print "== Disconnected =="
      try:
        sock.close()
      except:
        pass
  except KeyboardInterrupt:
    break
  except:
    pass
