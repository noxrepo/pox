#!/usr/bin/env python
import json
import sys
import socket

decoder = json.JSONDecoder()

host = "localhost"
port = 7790

if len(sys.argv) >= 2 : host = argv[1]
if len(sys.argv) >= 3 : port = int(argv[2])

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
