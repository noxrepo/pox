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
Connects the POX messenger bus to a JSON-RPC based web client.
Requires the "webserver" and "messenger" components.

A disclaimer:
  I think the term "AJAX" is dumb.  But this module was
  originally called httpjsonrpc_transport and had classes with
  names like HTTPJSONRPCConnection and I just couldn't take it.
"""

import time
import select
import threading

from pox.core import core
from pox.web.jsonrpc import JSONRPCHandler, make_error, ABORT
from pox.lib.recoco import Timer
from pox.messenger import Connection, Transport

log = core.getLogger()

SESSION_TIMEOUT = 60#120 # Seconds
CONNECTION_TIMEOUT = 30 # Seconds
MAX_TX_COUNT = 20 # Max messages to send at once


class AjaxTransport (Transport):
  """
  Messenger transport for Messenger Over JSON-RPC Over HTTP.
  """
  def __init__ (self, nexus = None):
    Transport.__init__(self, nexus)
    self._connections = {}
    self._t = Timer(SESSION_TIMEOUT, self._check_timeouts, recurring=True)

  def _check_timeouts (self):
    for c in list(self._connections.values()):
      c._check_timeout()

  def _forget (self, connection):
    # From Transport
    if connection._session_id in self._connections:
      del self._connections[connection._session_id]
    else:
      #print "Failed to forget", connection
      pass

  def create_session (self):
    ses = AjaxConnection(self)
    self._connections[ses._session_id] = ses
    self._nexus.register_session(ses)
    return ses

  def get_session (self, key):
    return self._connections.get(key, None)


def _result (m):
  return {'result':m}


class AjaxConnection (Connection):
  """
  Messenger connection for Messenger Over JSON-RPC Over HTTP.

  Note: The sequence numbers used by this module simply increment and
        never wrap.  This should mean like nine quadrillion, but it
        depends on your browser and I definitely haven't tested this. :)
  """
  def __init__ (self, transport):
    Connection.__init__(self, transport)
    self._cond = threading.Condition()
    self._quitting = False

    # We're really protected from attack by the session key, we hope, so
    # we currently start tx_seq at zero, which makes it easier for the
    # client.
    self._next_tx_seq = 0  # next seq to create
    self._sent_tx_seq = -1 # last seq sent
    self._rx_seq = None

    # Waiting outgoing messages as (seq, msg) pairs
    self._tx_buffer = []

    # Out-of-order messages we've gotten (the in-order ones are dispatched
    # immediately, so they're never buffered)
    self._rx_buffer = []

    self._touch()

    self._send_welcome()

  def _touch (self):
    self._touched = time.time()

  def _check_timeout (self):
    if (time.time() - self._touched) > SESSION_TIMEOUT:
      log.info("Session " + self._session_id + " timed out")
      self._close()

  def _close (self):
    super(AjaxConnection, self)._close()
    #TODO: track request sockets and cancel them?
    self._quitting = True

  def send (self, data):
    if self._is_connected is False: return False
    self._cond.acquire()
    self._tx_buffer.append((self._next_tx_seq, data))
    self._next_tx_seq += 1
    self._cond.notify()
    self._cond.release()

  def _get_tx_batch (self, seq, batch_size = None):
    """
    Returns the next batch of messages to send
    """
    if batch_size is None: batch_size = MAX_TX_COUNT
    o = []
    for m in self._tx_buffer:
      if m[0] < seq: continue
      o.append(m)
      if len(o) >= batch_size:
        break
    return o

  def tx (self, wfile, seq, batch_size):
    """
    Sends outgoing messages to a waiting client.

    Can block long-polling style for a while to wait
    until it has some to send.
    """
    ack = True
    if seq is None:
      seq = self._sent_tx_seq + 1
    else:
      if seq > self._sent_tx_seq + 1:
        # Client asked for something without asking for something before it
        log.debug("Client is living in the future (they sent seq %s but "
                  + "we are only at %s)", seq, self._sent_tx_seq+1)
        ack = False
        #NOTE: They get back from where we are, not from where requested

    if ack:
      # Throw away everything before what they're asking for
      while len(self._tx_buffer):
        if self._tx_buffer[0][0] >= seq: break
        del self._tx_buffer[0]

    with self._cond:
      data = self._get_tx_batch(seq = seq, batch_size = batch_size)
      if len(data) == 0:
        # Wait for messages
        start_time = time.time()
        while True:
          # Every couple seconds check if the socket is dead
          self._cond.wait(2)
          data = self._get_tx_batch(seq = seq, batch_size = batch_size)
          if len(data) > 0:
            # See if we can get a bit more data
            self._cond.wait(.05)
            data = self._get_tx_batch(seq = seq, batch_size = batch_size)
            break
          if self._quitting: break
          r,w,x = select.select([wfile],[],[wfile], 0)
          if len(r) or len(x):
            # Other side disconnected?
            #log.debug("Connection cancelled")
            ##self._cond.release()
            return ABORT
          if time.time() - start_time > CONNECTION_TIMEOUT:
            # Let them reconnect.
            return _result({'seq':seq,'messages':[]})
      # Okay, we have messages
      if self._quitting:
        #NOTE: we don't drain the messages first, but maybe we should?
        ##self._cond.release()
        return _result({'messages':[],'failure':'quit',
                        'seq':self._sent_tx_seq})

      if len(data) > 0:
        if seq < data[0][0]:
         # Bad news.  Requesting stuff we don't have.
         return _result({'messages':[],'failure':'expired',
                         'seq':self._sent_tx_seq})

        if data[0][0] != seq:
          log.info("First sequence sent is not the one asked for")
          seq = data[0][0]

        last = data[-1][0]
        if last > self._sent_tx_seq:
          self._sent_tx_seq = last

      data = [d[1] for d in data]

      #print "Sending",len(data),"of",len(self._tx_buffer)

      return _result({'seq':seq, 'messages':data})

  def rx (self, msg, seq):
    """
    Receive a message (or more than one) from RPC
    """
    good = True
    def do_rx (msg):
      if isinstance(msg, list):
        for m in msg:
          self._rx_message(m)
      else:
        self._rx_message(msg)

    if self._rx_seq is None:
      self._rx_seq = seq
    if seq is None:
      # Just do it
      do_rx(msg)
    elif seq == self._rx_seq:
      self._rx_seq += 1
      do_rx(msg)
      if len(self._rx_buffer) > 0:
        self._rx_buffer.sort()
        if self._rx_buffer[0][0] != self._rx_seq:
          log.info("Still out of order")
          good = False
        else:
          log.info("Resuming rx")
          # This is kind of ugly (recursion would be nicer)
          while self._rx_buffer[0][0] == self._rx_seq:
            m = self._rx_buffer.pop(0)
            self._rx_seq += 1
            do_rx(msg)
          if len(self._rx_buffer) > 0:
            log.info("Re-suspending rx")
            good = False
    else:
      good = False
      self._rx_buffer.append((seq, msg))
      if len(self._rx_buffer) == 1: # First time
        log.info("Got out of order message -- suspending rx")

    return _result({'ok':good,'ack':self._rx_seq})


class AjaxMsgHandler (JSONRPCHandler):
  """
  Handles JSON-RPC messages from webcore for messenger.
  """

  def _exec_stop (self, session_id):
    """
    End a session

    You can always just stop and wait for it to time out, but this is nice
    if you can swing it.
    """
    ses = self._get_session(session_id, create = False)
    if ses is not None:
      log.info("Session " + str(session_id) + " closed")
      ses._close()
    return {'result':True}

  def _exec_send (self, session_id, msg, seq = None):
    """
    Send a message (or messages)

    If seq is specified, it is a sequence number.  This can help
    eliminate problems with ordering.
    """
    ses = self._get_session(session_id)
    if ses is None:
      return make_error("No such session")
    r = ses.rx(msg, seq)
    if isinstance(r, dict) and 'result' in r:
      r['result']['session'] = ses._session_id
    return r

  def _exec_poll (self, session_id, seq = None, batch_size = None):
    """
    Get waiting messages

    If seq is specified, it is the sequence number of the first
    message you want.  This acks all previous messages.
    If batch_size is specified, it is how many messages you want.
    """
    ses = self._get_session(session_id)
    if ses is None:
      #return make_error("No such session")
      return {'messages':[], 'failure':'No session'}

    r = ses.tx(self.wfile, seq, batch_size)
    if isinstance(r, dict) and 'result' in r:
      r['result']['session'] = ses._session_id
    return r

  def _get_session (self, key, create = True):
    if key == "new!":
      if not create: return None
      return self._arg_transport.create_session()
    ses = self._arg_transport.get_session(key)
    if ses is not None:
      ses._touch()
    return ses


def launch (username='', password=''):
  def _launch ():
    transport = core.registerNew(AjaxTransport)

    # Set up config info
    cfg = {"transport":transport}
    if len(username) and len(password):
      cfg['auth'] = lambda u, p: (u == username) and (p == password)

    core.WebServer.set_handler("/_jrpcmsg/",AjaxMsgHandler,cfg,True)

  core.call_when_ready(_launch, ["WebServer","MessengerNexus"],
                       name = "ajax_transport")
