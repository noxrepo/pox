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
Connects the POX messenger bus to HTTP.
Requires the "webserver" component.
"""

from SocketServer import ThreadingMixIn
from BaseHTTPServer import *
import time
import select

import random
import hashlib
import base64
import json

from pox.lib.recoco import Timer

from pox.messenger.messenger import MessengerConnection

from pox.core import core

from webcore import *

log = core.getLogger()


class HTTPMessengerConnection (MessengerConnection):
  def __init__ (self, source, session_key):
    MessengerConnection.__init__(self, source, ID=str(id(self))) #TODO: better ID
    self.session_key = session_key
    self._messages = []
    self._cond = threading.Condition()
    self._quitting = False

    # We're really protected from attack by the session key, we hope
    self._tx_seq = -1 #random.randint(0, 1 << 32)
    self._rx_seq = None

    #self._t = Timer(10, lambda : self.send({'hi':'again'}), recurring=True)

    self._touched = time.time()

  def _check_timeout (self):
    if (time.time() - self._touched) > 120:
      log.info("Session " + self.session_key + " timed out")
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
    super(HTTPMessengerConnection, self)._close()
    #TODO: track request sockets and cancel them?
    self._quitting = True

  def sendRaw (self, data):
    self._cond.acquire()
    self._messages.append(data)
    self._cond.notify()
    self._cond.release()

  def _do_recv_msg (self, items):
    #print ">>",items
    for item in items:
      self._recv_msg(item)


class HTTPMessengerSource (object):
  def __init__ (self):
    self._session_key_salt = str(time.time()) + "POX"
    self._connections = {}
    #self._t = Timer(5, self._check_timeouts, recurring=True)
    self._t = Timer(60*2, self._check_timeouts, recurring=True)

  def _check_timeouts (self):
    for c in self._connections.values():
      c._check_timeout()

  def _forget (self, connection):
    if connection.session_key in self._connections:
      del self._connections[connection.session_key]
    else:
      #print "Failed to forget", connection
      pass

  def create_session (self):
    key = None
    while True:
      key = str(random.random()) + self._session_key_salt
      key += str(id(key))
      key = base64.encodestring(hashlib.md5(key).digest()).replace('=','').replace('+','').replace('/','').strip()
      if key not in self._connections:
        break
    ses = HTTPMessengerConnection(self, key)
    self._connections[key] = ses
    return ses

  def get_session (self, key):
    return self._connections.get(key, None)



class CometRequestHandler (SplitRequestHandler):
  protocol_version = 'HTTP/1.1'

#  def __init__ (self, *args, **kw):
#    super(CometRequestHandler, self).__init__(*args, **kw)

  def _init (self):
    self.source = self.args['source']
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
      hmh = self.source.create_session()
    else:
      hmh = self.source.get_session(session_key)
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
    if payload is not None:
      if not hmh._check_rx_seq(data['seq']):
        # Bad seq!
        data = '{"seq":-1,"ses":"%s"}' % (hmh.session_key,)
        self.send_response(400, "Bad sequence number")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.send_header("X-POX-Messenger-Sequence-Number", "-1")
        if self.auth_function: self.send_header("WWW-Authenticate",  'Basic realm="POX"')
        self.end_headers()
        self.wfile.write(data)
        hmh._close()
        return
      core.callLater(hmh._do_recv_msg, payload)
    else:
      #print "KeepAlive", hmh
      pass

    try:
      data = '{"seq":-1,"ses":"%s"}' % (hmh.session_key,)
      self.send_response(200, "OK")
      self.send_header("Content-Type", "application/json")
      self.send_header("Content-Length", len(data))
      self.send_header("X-POX-Messenger-Sequence-Number", "-1")
      if self.auth_function: self.send_header("WWW-Authenticate",  'Basic realm="POX"')
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
        data = '{"seq":-1,"ses":"%s"}' % (hmh.session_key,)
        self.send_response(200, "OK")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.send_header("X-POX-Messenger-Sequence-Number", "-1")
        if self.auth_function: self.send_header("WWW-Authenticate",  'Basic realm="POX"')
        self.end_headers()
        self.wfile.write(data)
      except:
        pass
      hmh._cond.release()
      return

    num_messages = min(20, len(hmh._messages))
    data = hmh._messages[:num_messages]
    seq = hmh._new_tx_seq()
    data = '{"seq":%i,"ses":"%s","data":[%s]}' % (seq, hmh.session_key, ','.join(data))
    try:
      self.send_response(200, "OK")
      self.send_header("Content-Type", "application/json")
      self.send_header("Content-Length", len(data))
      self.send_header("X-POX-Messenger-Sequence-Number", str(seq))
      if self.auth_function: self.send_header("WWW-Authenticate",  'Basic realm="POX"')
      self.end_headers()
      self.wfile.write(data)
      del hmh._messages[:num_messages]
      hmh._first_seq += num_messages
      hmh._message_count = 0
    except:
      pass
    hmh._cond.release()


def launch (username='', password=''):
  if not core.hasComponent("WebServer"):
    log.error("WebServer is required but unavailable")
    return

  source = core.registerNew(HTTPMessengerSource)

  # Set up config info
  config = {"source":source}
  if len(username) and len(password):
    config['auth'] = lambda u, p: (u == username) and (p == password)

  core.WebServer.set_handler("/_webmsg/", CometRequestHandler, config, True)

