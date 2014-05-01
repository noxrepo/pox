# Copyright 2014 James McCauley
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
For working with OVSDB

Highly experimental.
"""
from pox.core import core
import pox.lib.ioworker
from pox.messenger.test_client import JSONDestreamer
from pox.lib.revent import Event, EventMixin
from pox.lib.ioworker.workers import RecocoIOWorker
from pox.lib.ioworker import RecocoIOLoop
from pox.lib.util import init_helper

import socket
import json
import errno
import time

from dsl import * # Grab the DSL interface
import dsl


#TODO: It'd be nice to use a retrieved schema to build a bunch of types that
#      did validation and stuff on the client side.
#TODO: Handle OVSDB types (set, map, pair, etc.).  Probably requires the
#      former.
#TODO: Add a Notification, like Method but simpler?  (We currently just send
#      notifications by hand.)




class OVSDBEvent (Event):
  """
  Superclass for events coming from OVSDB

  They all have .connection (obvious) and .msg (message which caused the event
  if applicable).
  """
  def __init__ (self, connection, msg = None):
    self.connection = connection
    self.msg = msg

class ConnectionUp (OVSDBEvent):
  pass

class ConnectionDown (OVSDBEvent):
  pass

#TODO: Fire events when DPID appears in OVSDB
# class DPIDAvailable (OVSDBEvent):
#   def __init__ (self, *args, **kw):
#     super(DPIDAvailable,self).__init__(*args, **kw)
#     self.dpid = ...

# class DPIDUnavailable (OVSDBEvent):
#   def __init__ (self, *args, **kw):
#     super(DPIDUnavailable,self).__init__(*args, **kw)
#     self.opaque = self.msg.params[0]
#     self.dpid = ...

class UpdateNotification (OVSDBEvent):
  def __init__ (self, *args, **kw):
    super(UpdateNotification,self).__init__(*args, **kw)
    self.opaque = self.msg.params[0]
    self.updates = self.msg.params[1]

class LockNotification (OVSDBEvent):
  pass

class StolenNotification (OVSDBEvent):
  pass

class Error (OVSDBEvent):
  def __init__ (self, *args, **kw):
    self.method = kw.pop('method', None)
    super(Error,self).__init__(*args, **kw)
    self.should_log = True

class Complete (OVSDBEvent):
  def __init__ (self, *args, **kw):
    self.method = kw.pop('method', None)
    super(Error,self).__init__(*args, **kw)


def to_raw_json (obj, pretty=False):
  """
  Convert a JSON object to a plain JSON string
  """
  def enc (o):
    if isinstance(o, JSON):
      return o._JSON__items
    if hasattr(o, '_format__json'): # Ugh
      return o._format__json()
    return o
  kw = {}
  if pretty:
    kw = dict(sort_keys=True, indent=4, separators=(', ', ': '))
  r = json.dumps(obj, default=enc, **kw)
  return r

def from_raw_json (jobj):
  """
  Convert a JSON string or JSON-friendly Python dictionary to a JSON object
  """
  def hook (o):
    if isinstance(o, dict):
      j = JSON()
      j._JSON__items = o
      return j
    return o

  if isinstance(jobj, (dict,JSON,list)):
    jobj = to_raw_json(jobj)
  r = json.loads(jobj, object_hook=hook)
  r._JSON__set_parents()
  return r


class NO_DEFAULT (object):
  """
  Singleton used for specifying no default value when None is ambiguous
  """
  pass


def json_set (obj, attr, value):
  """
  Set an attribute of a JSON object

  Obsoleted by [...] item access?
  """
  j._JSON__items[attr] = value

def json_get (obj, attr, default=NO_DEFAULT):
  """
  Get an attribute of a JSON item

  Obsoleted by [...] item access except for default?
  """
  if default is NO_DEFAULT:
    if attr not in obj._JSON__items:
      raise KeyError(attr)
  return obj._JSON__items.get(attr)



class JSON (object):
  #FIXME: This is a bit of a mess now.
  #       Also, it probably doesn't really need to CONVERT the JSON from a
  #       Python dictionary, but could instead just be a proxy for accessing it.

  _JSON__items = {}
  _JSON__parent = None
  def __init__ (__self, **kw):
    for k in kw:
      if isinstance(k, basestring):
        if k.startswith("_JSON__"):
          raise RuntimeError("Bad attribute: %s" % (k,))
    __self._JSON__items = kw

  def __contains__ (self, key):
    return key in self._JSON__items

  def __iter__ (self):
    return iter(self._JSON__items)

  def __setitem__ (self, index, value):
    #TODO: validate index as legal for JSON?
    self._JSON__items[index] = value

  def __getitem__ (self, index):
    if index == JSON:
      return self._JSON__items
    return self._JSON__items[index]

  def __getattr__ (self, attr):
    if attr.startswith("_JSON__"):
      return object.__getattribute__(self,attr)
    try:
      return self._JSON__items[attr]
    except:
      raise AttributeError()

  def __setattr__ (self, attr, value):
    if attr.startswith("_JSON__"):
      return object.__setattr__(self, attr,value)
    has_item = attr in self._JSON__items
    has_native = False
    try:
      dummy = object.__getattribute__(self,attr)
      has_native = True
    except:
      pass

    if has_native and not has_item:
      object.__setattr__(self, attr, value)
    else:
      self._JSON__items[attr] = value

  def __repr__ (self):
    return to_raw_json(self)

  def __str__ (self):
    return self.__dump_str()

  def __dump_str (self):
    r = self.__dump()
    n = self.__get_name()
    r.insert(0, "=" * len(n))
    r.insert(0, n)
    return "\n".join(r)

  def __dump (self, level=0, indent='|   '):
    indent *= level
    r = []
    for k,v in sorted(self._JSON__items.items()):
      if isinstance(v, JSON):
        r.append(indent + k + ":")
        r.extend(v.__dump(level+1))
      else:
        r.append(indent + k + ": " + str(v))
      if level == 0: r.append('')
    if r and r[-1] == '':
      del r[-1]
    return r

  def __get_name (self):
    if not self.__parent: return "<Unnamed>"
    for k,v in self.__parent._JSON__items.items():
      if v is self:
        return k
    return "<Unknown>"

  def _JSON__set_parents (self):
    for k,v in self._JSON__items.items():
      if isinstance(v, JSON):
        v.__parent = self
        v._JSON__set_parents()

Row = JSON




class Method (object):
  #TODO: Make an EventMixin
  #TODO: Add timeout

  _method_name = None # Fill this in

  def __init__ (self, owner):
    self._owner = owner
    self._xid = owner.new_xid()
    self._args = None
    self._request = None
    self._reply = None
    self._callbacks = []
    self._errbacks = []
    self._init()

  def _call (self, *params):
    self._args = params
    params = self._preprocess_params(params)
    self._request = JSON(id=self._xid, method=self._method_name, params=params)
    self._owner._pending[self._xid] = self
    self._owner._send(self._request)

  def _complete (self, msg):
    """
    Called when we get a reply or error
    """
    self._reply = msg
    if msg.error is not None:
      self._run_errbacks()
    else:
      self._postprocess()
      self._run_callbacks()

  def _init (self):
    """
    Called during initialization
    """
    pass

  def _preprocess_params (self, params):
    """
    Translates input args to actual params
    """
    return params

  def _postprocess (self):
    """
    Called before running callbacks on success
    """
    pass

  @property
  def _callback_data (self):
    """
    Return data to be passed to callback
    """
    return (self._reply.result,)

  def _run_callbacks (self):
    for cb in self._callbacks:
      cb(*self._callback_data)

  def _run_errbacks (self):
    for cb in self._errbacks:
      cb(self._reply)

  def callback (self, callback, errback=None):
    """
    Add a callback (and optionall an errback)

    Chainable
    """
    self._callbacks.append(callback)
    if errback: self.errback(errback)
    return self

  def errback (self, errback):
    """
    Adds an errback
    """
    self._errbacks.append(errback)
    return self

  def __str__ (self):
    if self._request:
      args = [str(x) if isinstance(x, unicode) else x for x in self._args]
      return "%s(%s)" % (self._method_name, ", ".join(map(repr,args)))
    return repr(self)



class GetSchema (Method):
  _method_name = 'get_schema'


class ListDBs (Method):
  _method_name = 'list_dbs'


class Echo (Method):
  _method_name = 'echo'

  def _postprocess (self):
    # We use this to set our connection's reply time.
    self._owner._last_echo_reply = time.time()


class Transact (Method):
  _method_name = 'transact'

  def _preprocess_params (self, params):
    # If a parameter isn't an Operation, maybe it parses into one...
    params = list(params) # May have to alter it
    for i,p in enumerate(params[1:],1):
      if not isinstance(p, dsl.Operation):
        # It better be a statement!
        assert isinstance(p, dsl.Statement)
        params[i] = p._parse()

    return params

  def _postprocess (self):
    #TODO: Raise events or something?
    for n,r in enumerate(self._reply.result):
      if 'error' in r is not None:
        part = self._request.params[n+1]
        log.error("%s while executing operation #%s of transaction %s",
                  r.error, n+1, self._xid)
        log.debug("Failed transaction operation: %s", part)
        log.error("Details: %s", r.details)

  @property
  def _callback_data (self):
    return (self._reply.result,)


class OVSDBConnection (EventMixin):
  _eventMixin_events = set([
    ConnectionUp,

    UpdateNotification,
    LockNotification,
    StolenNotification,

    Error,
    Complete
  ])

  STATE_CONNECTING = "connecting"
  STATE_CONNECTED = "connected"

  _next_CID = 1 # This is the connection ID
  _next_XID = 1

  def __init__ (self, nexus, worker):
    self._state = self.STATE_CONNECTING
    self._nexus = nexus
    self._worker = worker
    self._destreamer = JSONDestreamer(callback = self._rx_json)
    self._worker.rx_handler = self._rx_raw
    self._worker.connect_handler = self._connect_handler
    self.ID = OVSDBConnection._next_CID
    OVSDBConnection._next_CID += 1
    self.log = core.getLogger('ovsdb-%s'%(self.ID,))
    self._last_echo_request = None
    self._last_echo_reply = None

    self._pending = {} # XID -> (timeout,Pending)

    #TODO: send echo requests

  def new_xid (self):
    x = OVSDBConnection._next_XID
    assert x not in self._pending
    OVSDBConnection._next_XID += 1
    return x

  def close (self):
    self._worker.shutdown()

  def _rx_raw (self, worker):
    #FIXME: I think exceptions inside here are silently being ignored.  It
    #       seems like IOWorker should log something by default?
    #       For now, print them ourself.
    try:
      self._destreamer.push(worker.read())
    except:
      self.log.exception("Exception while handling new data")

  def _rx_json (self, msg):
    msg = from_raw_json(msg)

    if self._state == self.STATE_CONNECTING:
      self._state = self.STATE_CONNECTED
      self.raiseEvent(ConnectionUp, self, msg)
      self._nexus.raiseEvent(ConnectionUp, self, msg)
      #FIXME: Propagate events properly

    method = getattr(msg, 'method', 'FAILURE')
    handler = getattr(self, '_exec_' + method, None)
    if handler:
      handler(msg)
      return

    xid = getattr(msg, 'id', None)
    if xid is not None:
      p = self._pending.pop(xid)
      self.log.debug("Return for: %s", p)

      if msg.error is not None:
        e = self.raiseEvent(Error, self, msg, method=p)
        if not e or e.should_log:
          self.log.error("%s returned error: %s", p, msg.error)
      else:
        self.raiseEvent(Complete, self, msg, method=p)

      if p:
        p._complete(msg)
      return

    self.log.info("RX: %s", msg)

  def _exec_update (self, msg):
    self.raiseEvent(UpdateNotification, self, msg)

  def _exec_echo (self, msg):
    try:
      self._send(JSON(error=None,result=msg.params,id=msg.id))
      self._last_echo_request = time.time()
    except:
      self.log.warn("Malformed echo request")

  def _connect_handler (self, worker):
    # Start out with an echo
    self._call(Echo)

    #HACKING
    #stm = UPDATE|'Interface'|WHERE|'name'=='s1-eth1'|WITH|Row(admin_state='up')
    #self.transact('Open_vSwitch', stm).callback(log.warn)

  def _send (self, msg):
    #print "SEND",to_raw_json(msg, pretty=True)
    self._worker.send(to_raw_json(msg))


  def echo (self, *params):
    return self._call(Echo, *params)

  def list_dbs (self):
    return self._call(ListDBs)

  def get_schema (self, db_name):
    return self._call(GetSchema, db_name)

  def transact (self, db_name, *operations):
    return self._call(Transact, db_name, *operations)
  #TODO: Add transact_one which expects a single response?
  #      Or a SELECT helper for such cases?

  def cancel (self, transaction_id):
    self._send(JSON(method='cancel',params=[transaction_id],id=None))

  def monitor (self, db_name, opaque, *monitor_requests):
    raise NotImplementedError()

  def _call (self, method, *params):
    m = method(self)
    m._call(*params)
    return m


class ClientWorker (RecocoIOWorker):
  #TODO: async name resolution
  def __init__ (self, **kw):
    super(ClientWorker,self).__init__(None)
    self._make_connection(**kw)

  def _make_connection (self, loop, addr, port, **kw):
    self._connecting = True

    self.loop = loop
    self.addr = addr
    self.port = port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket = s
    s.setblocking(0)
    self._debug("Attempting to connect to %s:%s", self.addr, self.port)
    r = s.connect_ex((str(self.addr), self.port))
    if r in (0, errno.EINPROGRESS, errno.EAGAIN, 10035): # 10035=WSAEWOULDBLOCK
      # We either connected or connection is in progress
      pass
    else:
      self._error("Couldn't connect to %s:%s", self.addr, self.port)
      #raise RuntimeError("Couldn't connect")
      core.callLater(self._handle_close)
      return

    self.loop.register_worker(self)

  # Might want to change these...
  #FIXME: Also, it seems like tracebacks for exceptions during handling of
  #       exceptions inside rx_handler are being lost?
  def _error (self, *args, **kw):
    log.error(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)
  def _warn (self, *args, **kw):
    log.warn(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)
  def _info (self, *args, **kw):
    log.info(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)
  def _debug (self, *args, **kw):
    log.debug(type(self).__name__ + ": " + str(args[0]), *args[1:], **kw)



class OVSDBNexus (EventMixin):
  #TODO: Have events from connection propagate here?
  _eventMixin_events = set([
     ConnectionUp,
  #   ConnectionDown,

  #   UpdateNotification,
  #   LockNotification,
  #   StolenNotification,

  #   Error,
  #   Complete
  ])

  def __init__ (self):
    self.loop = pox.lib.ioworker.RecocoIOLoop()
    self.connections = set()

    core.addListenerByName("UpEvent", lambda e:self.loop.start())

    # Temporary hack to start up a connection
    # def hack (event):
    #   self.client = self.connect(addr="127.0.0.1")
    #   core.Interactive.variables['client'] = self.client
    # core.addListenerByName("UpEvent", hack)

  def connect (self, addr, port=6640, **kw):
    w = ClientWorker(loop=self.loop, addr=addr, port=port, **kw)
    c = OVSDBConnection(self, w)
    self.connections.add(c)
    return c



def launch (port = 6640, no_auto_connect = False):
  global log
  log = core.getLogger()
  core.registerNew(OVSDBNexus)

  if not no_auto_connect:
    # When a switch connects, try to connect back to an OVSDB running there
    connected_ips = {}

    def new_connection (event):
      ip = event.connection.sock.getpeername()[0]
      if ip in connected_ips: return
      log.info("Connecting back to switch at %s", ip)
      client = core.OVSDBNexus.connect(ip, port=port)
      connected_ips[ip] = client #FIXME: Not really connected yet!

    core.openflow.addListenerByName("ConnectionUp", new_connection)


def example (port = 6640):
  """
  Every time we get a connection, query what switches it knows
  """
  launch(port)

  def query_dpids (event):
    # Send a query for DPIDs this OVSDB knows about
    def show_result (result):
      log.info("Found %s switches on this OVSDB:", len(result[0].rows))
      for row in result[0].rows:
        log.info("  %s : %s", row.datapath_id, row.name)

    event.connection.transact('Open_vSwitch',
        SELECT|'name'|AND|'datapath_id'|FROM|'Bridge'
        ).callback(show_result)

  core.OVSDBNexus.addListener(ConnectionUp, query_dpids)
