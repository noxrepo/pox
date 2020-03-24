# Copyright 2011,2012 James McCauley
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
Connects the POX messenger bus to HTTP.

Requires the "webserver" component.

NOTE: The web_transport keeps its own session IDs.  Since it was first
      written, though, sessions IDs have become part of every
      Connection, and we could (but are not) reuse those.
"""

from socketserver import ThreadingMixIn
from http.server import *
import time
import select

import random
import hashlib
import base64
import json

from pox.lib.recoco import Timer

from pox.messenger import Connection, Transport

from pox.core import core

from pox.web.webcore import *

log = core.getLogger()


class HTTPConnection (Connection):
  def __init__ (self, transport):
    Connection.__init__(self, transport)
    self._messages = []
    self._cond = threading.Condition()
    self._quitting = False

    # We're really protected from attack by the session key, we hope
    self._tx_seq = -1 #random.randint(0, 1 << 32)
    self._rx_seq = None

    #self._t = Timer(10, lambda : self.send({'hi':'again'}), recurring=True)

    self._touched = time.time()

    self._send_welcome()

  def _check_timeout (self):
    if (time.time() - self._touched) > 120:
      log.info("Session " + str(self) + " timed out")
      self._close()

  def _new_tx_seq (self):
    self._tx_seq = (self._tx_seq + 1) & 0x7fFFffFF
    return self._tx_seq

  def _check_rx_seq (self, seq):
    seq = int(seq)
    if self._rx_seq is None: self._rx_seq = seq

    if seq != self._rx_seq: return False

    self._rx_seq = (self._rx_seq + 1) & 0x7fFFffFF
    return True

  def _close (self):
    super(HTTPConnection, self)._close()
    #TODO: track request sockets and cancel them?
    self._quitting = True

  def send_raw (self, data):
    self._cond.acquire()
    self._messages.append(data)
    self._cond.notify()
    self._cond.release()

  def _do_rx_message (self, items):
    for item in items:
      self._rx_message(item)


class HTTPTransport (Transport):
  def __init__ (self, nexus = None):
    Transport.__init__(self, nexus)
    self._connections = {}
    #self._t = Timer(5, self._check_timeouts, recurring=True)
    self._t = Timer(60*2, self._check_timeouts, recurring=True)

  def _check_timeouts (self):
    for c in list(self._connections.values()):
      c._check_timeout()

  def _forget (self, connection):
    # From MessengerTransport
    if connection._session_id in self._connections:
      del self._connections[connection._session_id]
    else:
      #print "Failed to forget", connection
      pass

  def create_session (self):
    ses = HTTPConnection(self)
    self._connections[ses._session_id] = ses
    self._nexus.register_session(ses)
    return ses

  def get_session (self, key):
    return self._connections.get(key, None)



class CometRequestHandler (SplitRequestHandler):
  protocol_version = 'HTTP/1.1'

#  def __init__ (self, *args, **kw):
#    super(CometRequestHandler, self).__init__(*args, **kw)

  def _init (self):
    self.transport = self.args['transport']
    self.auth_function = self.args.get('auth', None)

  def _doAuth (self):
    if self.auth_function:
      auth = self.headers.get("Authorization", "").strip().lower()
      success = False
      if auth.startswith("basic "):
        try:
          auth = base64.decodestring(auth[6:].strip()).split(':', 1)
          success = self.auth_function(auth[0], auth[1])
        except:
          pass
      if success is not True:
        self.send_response(401, "Authorization Required")
        self.send_header("WWW-Authenticate",  'Basic realm="POX"')
        self.end_headers()
        return

  def _getSession (self):
    session_key = self.headers.get("X-POX-Messenger-Session-Key")
    if session_key is None:
      session_key = self.path.split('/')[-1]
    session_key = session_key.strip()
    if len(session_key) == 0:
      #TODO: return some bad response and log
      return None
    if session_key == "new":
      hmh = self.transport.create_session()
    else:
      hmh = self.transport.get_session(session_key)
    #print session_key, hmh.session_key
    return hmh

  def _enter (self):
    self._doAuth()
    hmh = self._getSession()
    if hmh is None:
      #TODO: return some bad response and log
      pass
    else:
      hmh._touched = time.time()
    return hmh

  def do_POST (self):
    hmh = self._enter()
    if hmh is None: return None

    l = self.headers.get("Content-Length", "")
    if l == "":
      data = json.loads(self.rfile.read())
    else:
      data = json.loads(self.rfile.read(int(l)))
    payload = data['data']
    # We send null payload for timeout poking and initial setup
    if 'seq' in data:
      if not hmh._check_rx_seq(data['seq']):
        # Bad seq!
        data = '{"seq":-1,"ses":"%s"}' % (hmh._session_id,)
        self.send_response(400, "Bad sequence number")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.send_header("X-POX-Messenger-Sequence-Number", "-1")
        if self.auth_function: self.send_header("WWW-Authenticate",
                                                'Basic realm="POX"')
        self.end_headers()
        self.wfile.write(data)
        hmh._close()
        return
      if payload is not None:
        core.callLater(hmh._do_rx_message, payload)

    try:
      data = '{"seq":-1,"ses":"%s"}' % (hmh._session_id,)
      self.send_response(200, "OK")
      self.send_header("Content-Type", "application/json")
      self.send_header("Content-Length", len(data))
      self.send_header("X-POX-Messenger-Sequence-Number", "-1")
      if self.auth_function: self.send_header("WWW-Authenticate",
                                              'Basic realm="POX"')
      self.end_headers()
      self.wfile.write(data)
    except:
      import traceback
      traceback.print_exc()
      pass
    return

  def do_GET (self):
    hmh = self._enter()
    if hmh is None: return None

    hmh._cond.acquire()
    if len(hmh._messages) == 0:
      # Wait for messages
      while True:
        # Every couple seconds check if the socket is dead
        hmh._cond.wait(2)
        if len(hmh._messages): break
        if hmh._quitting: break
        r,w,x = select.select([self.wfile],[],[self.wfile], 0)
        if len(r) or len(x):
          # Other side disconnected?
          hmh._cond.release()
          return
    # Okay...
    if hmh._quitting:
      #NOTE: we don't drain the messages first, but maybe we should?
      try:
        data = '{"seq":-1,"ses":"%s"}' % (hmh._session_id,)
        self.send_response(200, "OK")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.send_header("X-POX-Messenger-Sequence-Number", "-1")
        if self.auth_function: self.send_header("WWW-Authenticate",
                                                'Basic realm="POX"')
        self.end_headers()
        self.wfile.write(data)
      except:
        pass
      hmh._cond.release()
      return

    num_messages = min(20, len(hmh._messages))
    data = hmh._messages[:num_messages]
    old_seq = hmh._tx_seq
    seq = hmh._new_tx_seq()
    data = '{"seq":%i,"ses":"%s","data":[%s]}' % (seq, hmh._session_id,
                                                  ','.join(data))
    try:
      self.send_response(200, "OK")
      self.send_header("Content-Type", "application/json")
      self.send_header("Content-Length", len(data))
      self.send_header("X-POX-Messenger-Sequence-Number", str(seq))
      if self.auth_function: self.send_header("WWW-Authenticate",
                                              'Basic realm="POX"')
      self.end_headers()
      self.wfile.write(data)
      del hmh._messages[:num_messages]
    except:
      hmh._tx_seq = old_seq
    hmh._cond.release()


def launch (username='', password=''):
  def _launch ():
    transport = core.registerNew(HTTPTransport)

    # Set up config info
    config = {"transport":transport}
    if len(username) and len(password):
      config['auth'] = lambda u, p: (u == username) and (p == password)

    core.WebServer.set_handler("/_webmsg/",CometRequestHandler,config,True)

  core.call_when_ready(_launch, ["WebServer","MessengerNexus"],
                       name = "webmessenger")
