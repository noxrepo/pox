#!/usr/bin/env python

# Copyright 2011,2013 James McCauley
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
Display POX logs remotely

Connects to the POX messenger bus via TCP, and listens to a log channel.

Requires the messenger, messenger.tcp_transport, and messenger.log_service
components to be running.
"""

import json
import sys
import socket
import argparse
#from pox.messenger.test_client import JSONDestreamer

import uuid
uniq = str(uuid.uuid4())
mychannel = 'log_' + str(uuid.uuid4())



parser = argparse.ArgumentParser(description='Connect to the POX log service')
parser.add_argument('loggers', metavar='loggers', nargs='*',
                   help='loggers to listen to (logger[=level])')
parser.add_argument('--level', dest='default_level', default='INFO',
                    help="Default log level")
parser.add_argument('--address', dest='address', default='127.0.0.1',
                    help="Messenger service address")
parser.add_argument('--port', dest='port', default='7790', type=int,
                    help="Messenger service port")

args = parser.parse_args()

host = args.address
port = args.port


class JSONDestreamer (object):
  import json
  decoder = json.JSONDecoder()
  def __init__ (self, callback = None):
    self._buf = ''
    self.callback = callback if callback else self.rx

  def push (self, data):
    if len(self._buf) == 0:
      data = data.lstrip()
    self._buf += data
    try:
      while len(self._buf) > 0:
        r,off = self.decoder.raw_decode(self._buf)

        self._buf = self._buf[off:].lstrip()
        self.callback(r)
    except ValueError:
      pass


class LogJSONDestreamer (JSONDestreamer):
  def rx (self, data):
    if data.get('CHANNEL') != mychannel: return

    print("%s|%s|%s" % (data['levelname'], data['name'], data['message']))


jd = LogJSONDestreamer()

while True:
  try:
    sock = socket.socket()
    sock.connect((host,port))
    print("== Connected ==", file=sys.stderr)
    msg = {
        'CHANNEL' : '',
        'cmd' : 'join_channel',
        'channel' : mychannel,
        'json' : True,
    }
    sock.send(json.dumps(msg))
    msg = {
        'CHANNEL' : mychannel,
        'setLevels' : {"":args.default_level},
    }
    for logger_name in args.loggers:
      logger_name = logger_name.split("=")
      if len(logger_name) == 1:
        logger_name = logger_name[0]
        level = args.default_level
      else:
        logger_name,level = logger_name
      level = level.upper()
      msg['setLevels'][logger_name] = level
    sock.send(json.dumps(msg))

    try:
      while True:
        d = sock.recv(1024)
        if len(d) == 0: raise RuntimeError()
        jd.push(d)
    except KeyboardInterrupt:
      break
    except RuntimeError as e:
      print("== Disconnected ==", file=sys.stderr)
      try:
        sock.close()
      except:
        pass
  except KeyboardInterrupt:
    break
  except:
    pass
