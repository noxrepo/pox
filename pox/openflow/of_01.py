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
This component manages connections to OpenFlow 1.0 switches.

Because many POX applications use OpenFlow, this component gets some
special treatment, and an attempt is made to load it automatically if
any other component references it during initialization.
"""

from pox.core import core
import pox
import pox.lib.util
from pox.lib.addresses import EthAddr
from pox.lib.revent.revent import EventMixin
import datetime
import time
from pox.lib.socketcapture import CaptureSocket
import pox.openflow.debug
from pox.openflow.util import make_type_to_unpacker_table
from pox.openflow import *

log = core.getLogger()

import socket
import select

# List where the index is an OpenFlow message type (OFPT_xxx), and
# the values are unpack functions that unpack the wire format of that
# type into a message object.
unpackers = make_type_to_unpacker_table()

try:
  PIPE_BUF = select.PIPE_BUF
except:
  try:
    # Try to get it from where PyPy (sometimes) has it
    import IN
    PIPE_BUF = IN.PIPE_BUF
  except:
    # (Hopefully) reasonable default
    PIPE_BUF = 512

import pox.openflow.libopenflow_01 as of

import threading
import os
import sys
from errno import EAGAIN, ECONNRESET, EADDRINUSE, EADDRNOTAVAIL, EMFILE


import traceback


# handlers for stats replies
def handle_OFPST_DESC (con, parts):
  msg = parts[0].body
  e = con.ofnexus.raiseEventNoErrors(SwitchDescReceived,con,parts[0],msg)
  if e is None or e.halt != True:
    con.raiseEventNoErrors(SwitchDescReceived, con, parts[0], msg)

def handle_OFPST_FLOW (con, parts):
  msg = []
  for part in parts:
    msg.extend(part.body)
  e = con.ofnexus.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)
  if e is None or e.halt != True:
    con.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)

def handle_OFPST_AGGREGATE (con, parts):
  msg = parts[0].body
  e = con.ofnexus.raiseEventNoErrors(AggregateFlowStatsReceived, con,
                                     parts[0], msg)
  if e is None or e.halt != True:
    con.raiseEventNoErrors(AggregateFlowStatsReceived, con, parts[0], msg)

def handle_OFPST_TABLE (con, parts):
  msg = []
  for part in parts:
    msg.extend(part.body)
  e = con.ofnexus.raiseEventNoErrors(TableStatsReceived, con, parts, msg)
  if e is None or e.halt != True:
    con.raiseEventNoErrors(TableStatsReceived, con, parts, msg)

def handle_OFPST_PORT (con, parts):
  msg = []
  for part in parts:
    msg.extend(part.body)
  e = con.ofnexus.raiseEventNoErrors(PortStatsReceived, con, parts, msg)
  if e is None or e.halt != True:
    con.raiseEventNoErrors(PortStatsReceived, con, parts, msg)

def handle_OFPST_QUEUE (con, parts):
  msg = []
  for part in parts:
    msg.extend(part.body)
  e = con.ofnexus.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)
  if e is None or e.halt != True:
    con.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)


class OpenFlowHandlers (object):
  """
  A superclass for a thing which handles incoming OpenFlow messages

  The only public part of the interface is that it should have a "handlers"
  attribute which is a list where the index is an OFPT and the value is a
  function to call for that type with the parameters (connection, msg).  Oh,
  and the add_handler() method to add a handler.

  The default implementation assumes these handler functions are all methods
  with the names "handle_<TYPE>" and resolves those into the handlers list
  on init.
  """

  def __init__ (self):
    # A list, where the index is an OFPT, and the value is a function to
    # call for that type
    self.handlers = []

    self._build_table()

  def handle_default (self, con, msg):
    pass

  def add_handler (self, msg_type, handler):
    if msg_type >= len(self.handlers):
      missing = msg_type - len(self.handlers) + 1
      self.handlers.extend([self.handle_default] * missing)
    self.handlers[msg_type] = handler

  def _build_table (self):
    try:
      super(OpenFlowHandlers, self)._build_table()
    except:
      pass

    # Set up handlers for incoming OpenFlow messages
    # That is, self.ofp_handlers[OFPT_FOO] = self.handle_foo
    for fname in dir(self):
      h = getattr(self, fname)
      if not fname.startswith('handle_'): continue
      fname = fname.split('_',1)[1]
      if not fname == fname.upper(): continue
      assert callable(h)
      of_type = of.ofp_type_rev_map.get('OFPT_' + fname)
      if of_type is None:
        log.error("No OF message type for %s", fname)
        continue
      from_switch = getattr(of._message_type_to_class.get(of_type),
                            '_from_switch', False)
      assert from_switch, "%s is not switch-to-controller message" % (name,)
      self.add_handler(of_type, h)


class DefaultOpenFlowHandlers (OpenFlowHandlers):
  """
  Basic OpenFlow message handling functionality

  There is generally a single instance of this class which is shared by all
  Connections.
  """
  @staticmethod
  def handle_STATS_REPLY (con, msg):
    e = con.ofnexus.raiseEventNoErrors(RawStatsReply, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(RawStatsReply, con, msg)
    con._incoming_stats_reply(msg)

  @staticmethod
  def handle_PORT_STATUS (con, msg): #A
    if msg.reason == of.OFPPR_DELETE:
      con.ports._forget(msg.desc)
    else:
      con.ports._update(msg.desc)
    e = con.ofnexus.raiseEventNoErrors(PortStatus, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(PortStatus, con, msg)

  @staticmethod
  def handle_PACKET_IN (con, msg): #A
    e = con.ofnexus.raiseEventNoErrors(PacketIn, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(PacketIn, con, msg)

  @staticmethod
  def handle_ERROR (con, msg): #A
    err = ErrorIn(con, msg)
    e = con.ofnexus.raiseEventNoErrors(err)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(err)
    if err.should_log:
      log.error(str(con) + " OpenFlow Error:\n" +
                msg.show(str(con) + " Error: ").strip())

  @staticmethod
  def handle_BARRIER_REPLY (con, msg):
    e = con.ofnexus.raiseEventNoErrors(BarrierIn, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(BarrierIn, con, msg)

  @staticmethod
  def handle_VENDOR (con, msg):
    log.info("Vendor msg: " + str(msg))

  @staticmethod
  def handle_HELLO (con, msg): #S
    #con.msg("HELLO wire protocol " + hex(msg.version))

    # Send a features request
    msg = of.ofp_features_request()
    con.send(msg)

  @staticmethod
  def handle_ECHO_REPLY (con, msg):
    #con.msg("Got echo reply")
    pass

  @staticmethod
  def handle_ECHO_REQUEST (con, msg): #S
    reply = msg

    reply.header_type = of.OFPT_ECHO_REPLY
    con.send(reply)

  @staticmethod
  def handle_FLOW_REMOVED (con, msg): #A
    e = con.ofnexus.raiseEventNoErrors(FlowRemoved, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(FlowRemoved, con, msg)

  @staticmethod
  def handle_FEATURES_REPLY (con, msg):
    con.features = msg
    con.original_ports._ports = set(msg.ports)
    con.ports._reset()
    con.dpid = msg.datapath_id # Check this

    con.ofnexus._connect(con) #FIXME: Should this be here?
    e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(FeaturesReceived, con, msg)

  @staticmethod
  def handle_GET_CONFIG_REPLY (con, msg):
    e = con.ofnexus.raiseEventNoErrors(ConfigurationReceived, con, msg)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(ConfigurationReceived, con, msg)

  @staticmethod
  def handle_QUEUE_GET_CONFIG_REPLY (con, msg):
    #TODO
    pass

# Default handlers for connections in connected state
_default_handlers = DefaultOpenFlowHandlers()


class HandshakeOpenFlowHandlers (OpenFlowHandlers):
  """
  OpenFlow message handling for the handshake state
  """
  # If False, don't send a switch desc request when connecting
  request_description = True

  allowed_versions = (0x01,)

  def __init__ (self):
    self._features_request_sent = False
    self._barrier = None
    super(HandshakeOpenFlowHandlers, self).__init__()

  def handle_BARRIER_REPLY (self, con, msg):
    if not self._barrier: return
    if msg.xid != self._barrier.xid:
      con.dpid = None
      con.err("failed connect")
      con.disconnect()
    else:
      self._finish_connecting(con)

  def handle_ERROR (self, con, msg): #A
    if not self._barrier: return
    if msg.xid != self._barrier.xid: return
    if msg.type != of.OFPET_BAD_REQUEST: return
    if msg.code != of.OFPBRC_BAD_TYPE: return
    # Okay, so this is probably an HP switch that doesn't support barriers
    # (ugh).  We'll just assume that things are okay.
    self._finish_connecting(con)

  def handle_HELLO (self, con, msg): #S
    # Send features and switch desc requests
    if not self._features_request_sent:
      self._features_request_sent = True
      fr = of.ofp_features_request()

      if self.request_description:
        ss = of.ofp_stats_request()
        ss.body = of.ofp_desc_stats_request()

        con.send(fr.pack() + ss.pack())
      else:
        con.send(fr)

  @staticmethod
  def handle_ECHO_REQUEST (con, msg): #S
    reply = msg

    reply.header_type = of.OFPT_ECHO_REPLY
    con.send(reply)

  @staticmethod
  def handle_STATS_REPLY (con, msg):
    if msg.body and isinstance(msg.body, of.ofp_desc_stats_reply):
      con.description = msg.body

  def handle_FEATURES_REPLY (self, con, msg):
    if msg.version not in self.allowed_versions:
      # It's likely you won't see this message because the other side will
      # not have sent a features reply if it doesn't support OF 1.0.
      con.err("OpenFlow version 0x%02x not supported" % (msg.version,))
      con.disconnect()
      return
    connecting = con.connect_time == None
    con.features = msg
    con.original_ports._ports = set(msg.ports)
    con.ports._reset()
    con.dpid = msg.datapath_id

    # If any port status messages come between now and when the connection is
    # actually up, buffer them to raise later.
    con._deferred_port_status = []

    nexus = core.OpenFlowConnectionArbiter.getNexus(con)
    if nexus is None:
      # Cancel connection
      con.info("No OpenFlow nexus for " +
              pox.lib.util.dpidToStr(msg.datapath_id))
      con.disconnect()
      return
    con.ofnexus = nexus

    #TODO: Add a timeout for finish_connecting

    if con.ofnexus.miss_send_len is not None:
      con.send(of.ofp_set_config(miss_send_len =
                                    con.ofnexus.miss_send_len))
    if con.ofnexus.clear_flows_on_connect:
      con.send(of.ofp_flow_mod(match=of.ofp_match(),command=of.OFPFC_DELETE))

    self._barrier = of.ofp_barrier_request()
    con.send(self._barrier)

    # To support old versions of cbench, just finish connecting here.
    #self._finish_connecting(con)

  def handle_PORT_STATUS (self, con, msg): #A
    if con._deferred_port_status is None: return
    con.msg("Got early port status message for port %s" % (msg.desc.port_no,))
    con._deferred_port_status.append(msg)

  def _finish_connecting (self, con):
    con.ofnexus._connect(con)
    con.info("connected")
    con.connect_time = time.time()
    con.handlers = _default_handlers.handlers
    con.ofnexus.raiseEventNoErrors(ConnectionHandshakeComplete, con)

    e = con.ofnexus.raiseEventNoErrors(ConnectionUp, con, con.features)
    if e is None or e.halt != True:
      con.raiseEventNoErrors(ConnectionUp, con, con.features)

    if con.features:
      e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, con.features)
      if e is None or e.halt != True:
        con.raiseEventNoErrors(FeaturesReceived, con, con.features)

    # Now that we're connected, raise deferred events, if any
    if con._deferred_port_status:
      h = con.handlers[of.OFPT_PORT_STATUS]
      for msg in con._deferred_port_status:
        h(con,msg)
      con._deferred_port_status = None

statsHandlerMap = {
  of.OFPST_DESC : handle_OFPST_DESC,
  of.OFPST_FLOW : handle_OFPST_FLOW,
  of.OFPST_AGGREGATE : handle_OFPST_AGGREGATE,
  of.OFPST_TABLE : handle_OFPST_TABLE,
  of.OFPST_PORT : handle_OFPST_PORT,
  of.OFPST_QUEUE : handle_OFPST_QUEUE,
}


# Deferred sending should be unusual, so don't worry too much about
# efficiency
class DeferredSender (threading.Thread):
  """
  Class that handles sending when a socket write didn't complete
  """
  def __init__ (self):
    threading.Thread.__init__(self)
    core.addListeners(self)
    self._dataForConnection = {}
    self._lock = threading.RLock()
    self._waker = pox.lib.util.makePinger()
    self.sending = False

    self.start()

  def _handle_GoingDownEvent (self, event):
    self._waker.ping()

  def _sliceup (self, data):
    """
    Takes an array of data bytes, and slices into elements of
    PIPE_BUF bytes each
    """
    out = []
    while len(data) > PIPE_BUF:
      out.append(data[0:PIPE_BUF])
      data = data[PIPE_BUF:]
    if len(data) > 0:
      out.append(data)
    return out

  def send (self, con, data):
    with self._lock:
      self.sending = True

      data = self._sliceup(data)

      if con not in self._dataForConnection:
        self._dataForConnection[con] = data
      else:
        self._dataForConnection[con].extend(data)

      self._waker.ping()

  def kill (self, con):
    with self._lock:
      try:
        del self._dataForConnection[con]
      except:
        pass

      self._waker.ping()

  def run (self):
    while core.running:

      with self._lock:
        cons = list(self._dataForConnection.keys())

      rlist, wlist, elist = select.select([self._waker], cons, cons, 5)
      if not core.running: break

      with self._lock:
        if len(rlist) > 0:
          self._waker.pongAll()

        for con in elist:
          try:
            del self._dataForConnection[con]
          except:
            pass

        for con in wlist:
          try:
            alldata = self._dataForConnection[con]
            while len(alldata):
              data = alldata[0]
              try:
                l = con.sock.send(data)
                if l != len(data):
                  alldata[0] = data[l:]
                  break
                del alldata[0]
              except socket.error as e:
                if e.errno != EAGAIN:
                  con.msg("DeferredSender/Socket error: " + e.strerror)
                  con.disconnect()
                  del self._dataForConnection[con]
                break
              except:
                con.msg("Unknown error doing deferred sending")
                break
            if len(alldata) == 0:
              try:
                del self._dataForConnection[con]
                if len(self._dataForConnection) == 0:
                  self.sending = False
                  break
              except:
                pass
          except:
            try:
              del self._dataForConnection[con]
            except:
              pass

class DummyOFNexus (object):
  def raiseEventNoErrors (self, event, *args, **kw):
    log.warning("%s raised on dummy OpenFlow nexus" % event)
  def raiseEvent (self, event, *args, **kw):
    log.warning("%s raised on dummy OpenFlow nexus" % event)
  def _disconnect (self, dpid):
    log.warning("%s disconnected on dummy OpenFlow nexus",
                pox.lib.util.dpidToStr(dpid))

_dummyOFNexus = DummyOFNexus()


"""
class FileCloser (object):
  def __init__ (self):
    from weakref import WeakSet
    self.items = WeakSet()
    core.addListeners(self)
    import atexit
    atexit.register(self._handle_DownEvent, None)

  def _handle_DownEvent (self, event):
    for item in self.items:
      try:
        item.close()
      except Exception:
        log.exception("Couldn't close a file while shutting down")
    self.items.clear()

_itemcloser = FileCloser()
"""


class OFCaptureSocket (CaptureSocket):
  """
  Captures OpenFlow data to a pcap file
  """
  def __init__ (self, *args, **kw):
    super(OFCaptureSocket,self).__init__(*args, **kw)
    self._rbuf = bytes()
    self._sbuf = bytes()
    self._enabled = True
    #_itemcloser.items.add(self)

  def _recv_out (self, buf):
    if not self._enabled: return
    self._rbuf += buf
    l = len(self._rbuf)
    while l > 4:
      if self._rbuf[0] != of.OFP_VERSION:
        log.error("Bad OpenFlow version while trying to capture trace")
        self._enabled = False
        break
      packet_length = self._rbuf[2] << 8 | self._rbuf[3]
      if packet_length > l: break
      try:
        self._writer.write(False, self._rbuf[:packet_length])
      except Exception:
        log.exception("Exception while writing controller trace")
        self._enabled = False
      self._rbuf = self._rbuf[packet_length:]
      l = len(self._rbuf)

  def _send_out (self, buf, r):
    if not self._enabled: return
    self._sbuf += buf
    l = len(self._sbuf)
    while l > 4:
      if self._sbuf[0] != of.OFP_VERSION:
        log.error("Bad OpenFlow version while trying to capture trace")
        self._enabled = False
        break
      packet_length = self._sbuf[2] << 8 | self._sbuf[3]
      if packet_length > l: break
      try:
        self._writer.write(True, self._sbuf[:packet_length])
      except Exception:
        log.exception("Exception while writing controller trace")
        self._enabled = False
      self._sbuf = self._sbuf[packet_length:]
      l = len(self._sbuf)


class PortCollection (object):
  """
  Keeps track of lists of ports and provides nice indexing.

  One of the complexities of this class is due to how we get port information
  from OpenFlow.  We get an initial set of ports during handshake.  We then
  get updates after that.  We actually want to keep the original info around,
  but we *usually* are only interested in the "up to date" version with
  all the "delta" updates applied.  Thus, this collection can "chain" to a
  parent collection.  The original ports are stored in one collection, and
  deltas are applied to a child.  It's usually this child which is queried.

  If a port is removed from a child, the child *masks* it.  If the entry were
  simply removed from the child, then when a user queries for it, we might
  walk down the chain and find it in a parent which isn't what we want.

  NOTE: It's possible this could be simpler by inheriting from UserDict,
        but I couldn't swear without looking at UserDict in some detail,
        so I just implemented a lot of stuff by hand.
  """
  def __init__ (self):
    self._ports = set() # Set of ofp_phy_ports
    self._masks = set() # port_nos of ports which have been removed
    self._chain = None  # A parent port collection

  def _reset (self):
    self._ports.clear()
    self._masks.clear()

  def _forget (self, port):
    # Note that all we really need here is the port_no.  We pass an entire
    # ofp_phy_port anyway for consistency with _update(), though this could
    # be re-evaluated if there's ever another caller of _forget().
    self._masks.add(port.port_no)
    self._ports = set([p for p in self._ports if p.port_no != port.port_no])

  def _update (self, port):
    self._masks.discard(port.port_no)
    self._ports = set([p for p in self._ports if p.port_no != port.port_no])
    self._ports.add(port)

  def __str__ (self):
    if len(self) == 0:
      return "<Ports: Empty>"
    l = ["%s:%i"%(p.name,p.port_no) for p in sorted(self.values())]
    return "<Ports: %s>" % (", ".join(l),)

  def __len__ (self):
    return len(self.keys())

  def __getitem__ (self, index):
    if isinstance(index, int):
      for p in self._ports:
        if p.port_no == index:
          return p
    elif isinstance(index, EthAddr):
      for p in self._ports:
        if p.hw_addr == index:
          return p
    else:
      for p in self._ports:
        if p.name == index:
          return p
    if self._chain:
      p = self._chain[index]
      if p.port_no not in self._masks:
        return p

    raise IndexError("No key %s" % (index,))

  def keys (self):
    if self._chain:
      k = set(self._chain.keys())
      k.difference_update(self._masks)
    else:
      k = set()
    k.update([p.port_no for p in self._ports])
    return list(k)

  def __iter__ (self):
    return iter(self.keys())

  def iterkeys (self):
    return iter(self.keys())

  def __contains__ (self, index):
    try:
      self[index]
      return True
    except Exception:
      pass
    return False

  def values (self):
    return [self[k] for k in self.keys()]

  def items (self):
    return [(k,self[k]) for k in self.keys()]

  def iterkeys (self):
    return iter(self.keys())
  def itervalues (self):
    return iter(self.values())
  def iteritems (self):
    return iter(self.items())
  def has_key (self, k):
    return k in self
  def get (self, k, default=None):
    try:
      return self[k]
    except IndexError:
      return default
  def copy (self):
    r = PortCollection()
    r._ports = set(self.values())


class Connection (EventMixin):
  """
  A Connection object represents a single TCP session with an
  openflow-enabled switch.
  If the switch reconnects, a new connection object is instantiated.
  """
  _eventMixin_events = set([
    ConnectionUp,
    ConnectionDown,
    PortStatus,
    PacketIn,
    ErrorIn,
    BarrierIn,
    RawStatsReply,
    SwitchDescReceived,
    FlowStatsReceived,
    AggregateFlowStatsReceived,
    TableStatsReceived,
    PortStatsReceived,
    QueueStatsReceived,
    FlowRemoved,
    FeaturesReceived,
    ConfigurationReceived,
  ])

  # Globally unique identifier for the Connection instance
  ID = 0

  _aborted_connections = 0

  def msg (self, m):
    #print str(self), m
    log.debug(str(self) + " " + str(m))
  def err (self, m):
    #print str(self), m
    log.error(str(self) + " " + str(m))
  def info (self, m):
    pass
    #print str(self), m
    log.info(str(self) + " " + str(m))

  def __init__ (self, sock):
    self._previous_stats = []

    self.ofnexus = _dummyOFNexus
    self.sock = sock
    self.buf = b''
    Connection.ID += 1
    self.ID = Connection.ID

    # DPID of connected switch.  None before connection is complete.
    self.dpid = None

    # Switch features reply.  Set during handshake.
    self.features = None

    # Port status messages that arrive before the handshake finishes are
    # temporarily kept here, and raised as events *after* the handshake.
    self._deferred_port_status = None

    # Switch desc stats reply.  Set during handshake ordinarily, but may
    # be None.
    self.description = None

    self.disconnected = False
    self.disconnection_raised = False
    self.connect_time = None
    self.idle_time = time.time()

    self.send(of.ofp_hello())

    self.original_ports = PortCollection()
    self.ports = PortCollection()
    self.ports._chain = self.original_ports

    #TODO: set a time that makes sure we actually establish a connection by
    #      some timeout

    self.unpackers = unpackers
    self.handlers = HandshakeOpenFlowHandlers().handlers

  @property
  def eth_addr (self):
    dpid = self.dpid
    if self.dpid is None:
      raise RuntimeError("eth_addr not available")
    return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

  def fileno (self):
    return self.sock.fileno()

  def close (self):
    self.disconnect('closed')
    try:
      self.sock.close()
    except:
      pass

  def _do_abort_message (self):
    """
    Log a message about aborted (no DPID) disconnects
    """
    assert Connection._aborted_connections > 0
    msg = str(Connection._aborted_connections) + " connection"
    if Connection._aborted_connections != 1: msg += "s"
    msg += " aborted"
    log.debug(msg)
    Connection._aborted_connections = 0

  def disconnect (self, msg = 'disconnected', defer_event = False):
    """
    disconnect this Connection (usually not invoked manually).
    """
    if self.disconnected:
      self.msg("already disconnected")
    if self.dpid is None:
      # If we never got a DPID, log later (coalesce the messages)
      Connection._aborted_connections += 1
      if Connection._aborted_connections == 1:
        core.callDelayed(20, self._do_abort_message)
    else:
      self.info(msg)
    self.disconnected = True
    try:
      self.ofnexus._disconnect(self.dpid)
    except:
      pass
    if self.dpid is not None:
      if not self.disconnection_raised and not defer_event:
        self.disconnection_raised = True
        self.ofnexus.raiseEventNoErrors(ConnectionDown, self)
        self.raiseEventNoErrors(ConnectionDown, self)

    try:
      #deferredSender.kill(self)
      pass
    except:
      pass
    try:
      self.sock.shutdown(socket.SHUT_RDWR)
    except:
      pass
    try:
      pass
      #TODO disconnect notification
    except:
      pass

  def send (self, data):
    """
    Send data to the switch.

    Data should probably either be raw bytes in OpenFlow wire format, or
    an OpenFlow controller-to-switch message object from libopenflow.
    """
    if self.disconnected: return
    if type(data) is not bytes:
      # There's actually no reason the data has to be an instance of
      # ofp_header, but this check is likely to catch a lot of bugs,
      # so we check it anyway.
      assert isinstance(data, of.ofp_header)
      data = data.pack()

    if deferredSender.sending:
      log.debug("deferred sender is sending!")
      deferredSender.send(self, data)
      return
    try:
      l = self.sock.send(data)
      if l != len(data):
        self.msg("Didn't send complete buffer.")
        data = data[l:]
        deferredSender.send(self, data)
    except socket.error as e:
      if e.errno == EAGAIN:
        self.msg("Out of send buffer space.  " +
                 "Consider increasing SO_SNDBUF.")
        deferredSender.send(self, data)
      else:
        self.msg("Socket error: " + e.strerror)
        self.disconnect(defer_event=True)

  def read (self):
    """
    Read data from this connection.  Generally this is just called by the
    main OpenFlow loop below.

    Note: This function will block if data is not available.
    """
    try:
      d = self.sock.recv(2048)
    except:
      return False
    if len(d) == 0:
      return False
    self.buf += d
    buf_len = len(self.buf)


    offset = 0
    while buf_len - offset >= 8: # 8 bytes is minimum OF message size
      # We pull the first four bytes of the OpenFlow header off by hand
      # to find the version/length/type so that we can correctly call
      # libopenflow to unpack it.

      ofp_type = self.buf[offset+1]

      if self.buf[offset] != of.OFP_VERSION:
        if ofp_type == of.OFPT_HELLO:
          # We let this through and hope the other side switches down.
          pass
        else:
          log.warning("Bad OpenFlow version (0x%02x) on connection %s"
                      % (self.buf[offset], self))
          return False # Throw connection away

      msg_length = self.buf[offset+2] << 8 | self.buf[offset+3]

      if buf_len - offset < msg_length: break

      new_offset,msg = self.unpackers[ofp_type](self.buf, offset)
      assert new_offset - offset == msg_length
      offset = new_offset

      try:
        h = self.handlers[ofp_type]
        h(self, msg)
      except:
        log.exception("%s: Exception while handling OpenFlow message:\n" +
                      "%s %s", self,self,
                      ("\n" + str(self) + " ").join(str(msg).split('\n')))
        continue

    if offset != 0:
      self.buf = self.buf[offset:]

    return True

  def _incoming_stats_reply (self, ofp):
    # This assumes that you don't receive multiple stats replies
    # to different requests out of order/interspersed.
    if not ofp.is_last_reply:
      if ofp.type not in [of.OFPST_FLOW, of.OFPST_TABLE,
                                of.OFPST_PORT, of.OFPST_QUEUE]:
        log.error("Don't know how to aggregate stats message of type " +
                  str(ofp.type))
        self._previous_stats = []
        return

    if len(self._previous_stats) != 0:
      if ((ofp.xid == self._previous_stats[0].xid) and
          (ofp.type == self._previous_stats[0].type)):
        self._previous_stats.append(ofp)
      else:
        log.error("Was expecting continued stats of type %i with xid %i, " +
                  "but got type %i with xid %i" %
                  (self._previous_stats_reply.xid,
                    self._previous_stats_reply.type,
                    ofp.xid, ofp.type))
        self._previous_stats = [ofp]
    else:
      self._previous_stats = [ofp]

    if ofp.is_last_reply:
      handler = statsHandlerMap.get(self._previous_stats[0].type, None)
      s = self._previous_stats
      self._previous_stats = []
      if handler is None:
        log.warn("No handler for stats of type " +
                 str(self._previous_stats[0].type))
        return
      handler(self, s)

  def __str__ (self):
    #return "[Con " + str(self.ID) + "/" + str(self.dpid) + "]"
    if self.dpid is None:
      d = str(self.dpid)
    else:
      d = pox.lib.util.dpidToStr(self.dpid)
    return "[%s %i]" % (d, self.ID)


def wrap_socket (new_sock):
  fname = datetime.datetime.now().strftime("%Y-%m-%d-%I%M%p")
  fname += "_" + new_sock.getpeername()[0].replace(".", "_")
  fname += "_" + repr(new_sock.getpeername()[1]) + ".pcap"
  pcapfile = file(fname, "w")
  try:
    new_sock = OFCaptureSocket(new_sock, pcapfile,
                               local_addrs=(None,None,6633))
  except Exception:
    import traceback
    traceback.print_exc()
    pass
  return new_sock


from pox.lib.recoco.recoco import *

class OpenFlow_01_Task (Task):
  """
  The main recoco thread for listening to openflow messages
  """
  def __init__ (self, port = 6633, address = '0.0.0.0',
                ssl_key = None, ssl_cert = None, ssl_ca_cert = None):
    """
    Initialize

    This listener will be for SSL connections if the SSL params are specified
    """
    Task.__init__(self)
    self.port = int(port)
    self.address = address
    self.started = False
    self.ssl_key = ssl_key
    self.ssl_cert = ssl_cert
    self.ssl_ca_cert = ssl_ca_cert

    if self.ssl_key or self.ssl_cert or ssl_ca_cert:
      global ssl
      ssl = None
      try:
        import ssl as sslmodule
        ssl = sslmodule
      except:
        raise RuntimeError("SSL is not available")

    core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)

  def _handle_GoingUpEvent (self, event):
    self.start()

  def start (self):
    if self.started:
      return
    self.started = True
    return super(OpenFlow_01_Task,self).start()

  def run (self):
    # List of open sockets/connections to select on
    sockets = []

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
      listener.bind((self.address, self.port))
    except socket.error as e:
      log.error("Error %i while binding %s:%s: %s",
                e.errno, self.address, self.port, e.strerror)
      if e.errno == EADDRNOTAVAIL:
        log.error(" You may be specifying a local address which is "
                  "not assigned to any interface.")
      elif e.errno == EADDRINUSE:
        log.error(" You may have another controller running.")
        log.error(" Use openflow.of_01 --port=<port> to run POX on "
                  "another port.")
      return

    listener.listen(16)
    listener.setblocking(0)
    sockets.append(listener)

    log.debug("Listening on %s:%s" %
              (self.address, self.port))

    con = None
    while core.running:
      try:
        while True:
          con = None
          rlist, wlist, elist = yield Select(sockets, [], sockets, 5)
          if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
            if not core.running: break

          for con in elist:
            if con is listener:
              raise RuntimeError("Error on listener socket")
            else:
              try:
                con.close()
              except:
                pass
              try:
                sockets.remove(con)
              except:
                pass

          timestamp = time.time()
          for con in rlist:
            if con is listener:
              new_sock = listener.accept()[0]

              if self.ssl_key or self.ssl_cert or self.ssl_ca_cert:
                cert_reqs = ssl.CERT_REQUIRED
                if self.ssl_ca_cert is None:
                  cert_reqs = ssl.CERT_NONE
                new_sock = ssl.wrap_socket(new_sock, server_side=True,
                    keyfile = self.ssl_key, certfile = self.ssl_cert,
                    ca_certs = self.ssl_ca_cert, cert_reqs = cert_reqs,
                    do_handshake_on_connect = False,
                    suppress_ragged_eofs = True)
                #FIXME: We currently do a blocking handshake so that SSL errors
                #       can't occur out of the blue later.  This isn't a good
                #       thing, but getting around it will take some effort.
                try:
                  new_sock.setblocking(1)
                  new_sock.do_handshake()
                except ssl.SSLError as exc:
                  if exc.errno == 8 and "EOF occurred" in exc.strerror:
                    # Annoying, but just ignore
                    pass
                  else:
                    #log.exception("SSL negotiation failed")
                    log.warn("SSL negotiation failed: " + str(exc))
                  continue

              if pox.openflow.debug.pcap_traces:
                new_sock = wrap_socket(new_sock)
              new_sock.setblocking(0)
              # Note that instantiating a Connection object fires a
              # ConnectionUp event (after negotation has completed)
              newcon = Connection(new_sock)
              sockets.append( newcon )
              #print str(newcon) + " connected"
            else:
              con.idle_time = timestamp
              if con.read() is False:
                con.close()
                sockets.remove(con)
      except KeyboardInterrupt:
        break
      except:
        def log_tb ():
          log.exception("Exception reading connection " + str(con))

        do_break = False # Break OpenFlow loop?
        do_close = True # Close this socket?

        sock_error = None
        if sys.exc_info()[0] is socket.error:
          sock_error = sys.exc_info()[1][0]

        if con is listener:
          do_close = False
          if sock_error == ECONNRESET:
            con.info("Connection reset")
          elif sock_error == EMFILE:
            log.error("Couldn't accept connection: out of file descriptors.")
          else:
            do_close = True
            log_tb()
            log.error("Exception on OpenFlow listener.  Aborting.")
            do_break = True
        else:
          # Normal socket
          if sock_error == ECONNRESET:
            con.info("Connection reset")
          else:
            log_tb()

        if do_close:
          try:
            con.close()
          except:
            pass
          try:
            sockets.remove(con)
          except:
            pass

        if do_break:
          # Leave the OpenFlow loop
          break

    log.debug("No longer listening for connections")

    #pox.core.quit()



# Used by the Connection class
deferredSender = None

def launch (port=6633, address="0.0.0.0", name=None,
            private_key=None, certificate=None, ca_cert=None,
            __INSTANCE__=None):
  """
  Start a listener for OpenFlow connections

  If you want to enable SSL, pass private_key/certificate/ca_cert in reasonable
  combinations and pointing to reasonable key/cert files.  These have the same
  meanings as with Open vSwitch's old test controller, but they are more
  flexible (e.g., ca-cert can be skipped).
  """
  if name is None:
    basename = "of_01"
    counter = 1
    name = basename
    while core.hasComponent(name):
      counter += 1
      name = "%s-%s" % (basename, counter)

  if core.hasComponent(name):
    log.warn("of_01 '%s' already started", name)
    return None

  global deferredSender
  if not deferredSender:
    deferredSender = DeferredSender()

  if of._logger is None:
    of._logger = core.getLogger('libopenflow_01')

  l = OpenFlow_01_Task(port = int(port), address = address,
                       ssl_key = private_key, ssl_cert = certificate,
                       ssl_ca_cert = ca_cert)
  core.register(name, l)
  return l
