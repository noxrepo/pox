#!/usr/bin/env python

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
