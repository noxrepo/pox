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
In charge of OpenFlow 1.0 switches.

NOTE: This module is loaded automatically on startup unless POX is run
      with --no-openflow .
"""
from pox.core import core
import pox
import pox.lib.util
from pox.lib.revent.revent import EventMixin
import datetime
from pox.lib.socketcapture import CaptureSocket
import pox.openflow.debug
from pox.openflow.util import make_type_to_class_table
from pox.openflow.connection_arbiter import *

from pox.openflow import *

log = core.getLogger()

import socket
import select

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
import exceptions
from errno import EAGAIN, ECONNRESET


import traceback


def handle_HELLO (con, msg): #S
  #con.msg("HELLO wire protocol " + hex(msg.version))

  # Send a features request
  msg = of.ofp_features_request()
  con.send(msg.pack())

def handle_ECHO_REQUEST (con, msg): #S
  reply = msg
  
  reply.header_type = of.OFPT_ECHO_REPLY
  con.send(reply.pack())

def handle_FLOW_REMOVED (con, msg): #A
  con.ofnexus.raiseEventNoErrors(FlowRemoved, con, msg)
  con.raiseEventNoErrors(FlowRemoved, con, msg)

def handle_FEATURES_REPLY (con, msg):
  connecting = con.connect_time == None
  con.features = msg
  con.dpid = msg.datapath_id

  if not connecting:
    con.ofnexus._connect(con)
    return

  nexus = core.OpenFlowConnectionArbiter.getNexus(con)
  if nexus is None:
    # Cancel connection
    con.info("No OpenFlow nexus for " +
             pox.lib.util.dpidToStr(msg.datapath_id))
    con.disconnect()
    return
  con.ofnexus = nexus
  con.ofnexus._connect(con)
  #connections[con.dpid] = con

  barrier = of.ofp_barrier_request()

  listeners = []

  def finish_connecting (event):
    if event.xid != barrier.xid:
      con.dpid = None
      con.err("Failed connect for " + pox.lib.util.dpidToStr(
              msg.datapath_id))
      con.disconnect()
    else:
      con.info("Connected to " + pox.lib.util.dpidToStr(msg.datapath_id))
      import time
      con.connect_time = time.time()
      #for p in msg.ports: print(p.show())
      con.ofnexus.raiseEventNoErrors(ConnectionUp, con, msg)
      con.raiseEventNoErrors(ConnectionUp, con, msg)
    con.removeListeners(listeners)
  listeners.append(con.addListener(BarrierIn, finish_connecting))

  def also_finish_connecting (event):
    if event.xid != barrier.xid: return
    if event.ofp.type != of.OFPET_BAD_REQUEST: return
    if event.ofp.code != of.OFPBRC_BAD_TYPE: return
    # Okay, so this is probably an HP switch that doesn't support barriers
    # (ugh).  We'll just assume that things are okay.
    finish_connecting(event)
  listeners.append(con.addListener(ErrorIn, also_finish_connecting))

  #TODO: Add a timeout for finish_connecting

  if con.ofnexus.miss_send_len is not None:
    con.send(of.ofp_switch_config(miss_send_len =
                                  con.ofnexus.miss_send_len))
  if con.ofnexus.clear_flows_on_connect:
    con.send(of.ofp_flow_mod(match=of.ofp_match(), command=of.OFPFC_DELETE))

  con.send(barrier)


def handle_STATS_REPLY (con, msg):
  con.ofnexus.raiseEventNoErrors(RawStatsReply, con, msg)
  con.raiseEventNoErrors(RawStatsReply, con, msg)
  con._incoming_stats_reply(msg)

def handle_PORT_STATUS (con, msg): #A
  con.ofnexus.raiseEventNoErrors(PortStatus, con, msg)
  con.raiseEventNoErrors(PortStatus, con, msg)

def handle_PACKET_IN (con, msg): #A
  con.ofnexus.raiseEventNoErrors(PacketIn, con, msg)
  con.raiseEventNoErrors(PacketIn, con, msg)
#  if PacketIn in con.ofnexus._eventMixin_handlers:
#    p = ethernet(msg.data)
#    con.ofnexus.raiseEventNoErrors(PacketIn(con, msg, p))

def handle_ERROR_MSG (con, msg): #A
  log.error(str(con) + " OpenFlow Error:\n" +
            msg.show(str(con) + " Error: ").strip())
  con.ofnexus.raiseEventNoErrors(ErrorIn, con, msg)
  con.raiseEventNoErrors(ErrorIn, con, msg)

def handle_BARRIER (con, msg):
  con.ofnexus.raiseEventNoErrors(BarrierIn, con, msg)
  con.raiseEventNoErrors(BarrierIn, con, msg)

#TODO: def handle_VENDOR (con, msg): #S


def _processStatsBody (body, obj):
  r = []
  t = obj.__class__
  remaining = len(body)
  while remaining:
    obj = t()
    body = obj.unpack(body)
    assert len(body) < remaining # Should have read something
    remaining = len(body)
    r.append(obj)
  return r

# handlers for stats replies
def handle_OFPST_DESC (con, parts):
  msg = of.ofp_desc_stats()
  msg.unpack(parts[0].body)
  con.ofnexus.raiseEventNoErrors(SwitchDescReceived, con, parts[0], msg)
  con.raiseEventNoErrors(SwitchDescReceived, con, parts[0], msg)

def handle_OFPST_FLOW (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_flow_stats())
  con.ofnexus.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)

def handle_OFPST_AGGREGATE (con, parts):
  msg = of.ofp_aggregate_stats_reply()
  msg.unpack(parts[0].body)
  con.ofnexus.raiseEventNoErrors(AggregateFlowStatsReceived, con,
                                 parts[0], msg)
  con.raiseEventNoErrors(AggregateFlowStatsReceived, con, parts[0], msg)

def handle_OFPST_TABLE (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_table_stats())
  con.ofnexus.raiseEventNoErrors(TableStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(TableStatsReceived, con, parts, msg)

def handle_OFPST_PORT (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_port_stats())
  con.ofnexus.raiseEventNoErrors(PortStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(PortStatsReceived, con, parts, msg)

def handle_OFPST_QUEUE (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_queue_stats())
  con.ofnexus.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)


# A list, where the index is an OFPT, and the value is a libopenflow
# class for that type
classes = []

# A list, where the index is an OFPT, and the value is a function to
# call for that type
# This is generated automatically based on handlerMap
handlers = []

# Message handlers
handlerMap = {
  of.OFPT_HELLO : handle_HELLO,
  of.OFPT_ECHO_REQUEST : handle_ECHO_REQUEST,
  of.OFPT_PACKET_IN : handle_PACKET_IN,
  of.OFPT_FEATURES_REPLY : handle_FEATURES_REPLY,
  of.OFPT_PORT_STATUS : handle_PORT_STATUS,
  of.OFPT_ERROR : handle_ERROR_MSG,
  of.OFPT_BARRIER_REPLY : handle_BARRIER,
  of.OFPT_STATS_REPLY : handle_STATS_REPLY,
  of.OFPT_FLOW_REMOVED : handle_FLOW_REMOVED,
}

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
    # Threads, not recoco?
    threading.Thread.__init__(self)
    self._dataForConnection = {}
    self._lock = threading.RLock()
    self._waker = pox.lib.util.makePinger()
    self.daemon = True
    self.sending = False

    self.start()

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
        cons = self._dataForConnection.keys()

      rlist, wlist, elist = select.select([self._waker], cons, cons, 1)
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
              except socket.error as (errno, strerror):
                if errno != EAGAIN:
                  con.msg("DeferredSender/Socket error: " + strerror)
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

# Used by the Connection class below
deferredSender = DeferredSender()

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
      if ord(self._rbuf[0]) != of.OFP_VERSION:
        log.error("Bad OpenFlow version while trying to capture trace")
        self._enabled = False
        break
      packet_length = ord(self._rbuf[2]) << 8 | ord(self._rbuf[3])
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
      if ord(self._sbuf[0]) != of.OFP_VERSION:
        log.error("Bad OpenFlow version while trying to capture trace")
        self._enabled = False
        break
      packet_length = ord(self._sbuf[2]) << 8 | ord(self._sbuf[3])
      if packet_length > l: break
      try:
        self._writer.write(True, self._sbuf[:packet_length])
      except Exception:
        log.exception("Exception while writing controller trace")
        self._enabled = False
      self._sbuf = self._sbuf[packet_length:]
      l = len(self._sbuf)


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
    FlowRemoved,
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
  ])
  
  # Globally unique identifier for the Connection instance
  ID = 0

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
    self.buf = ''
    Connection.ID += 1
    self.ID = Connection.ID
    # TODO: dpid and features don't belong here; they should be eventually
    # be in topology.switch
    self.dpid = None
    self.features = None
    self.disconnected = False
    self.connect_time = None

    self.send(of.ofp_hello())

    #TODO: set a time that makes sure we actually establish a connection by
    #      some timeout

  def fileno (self):
    return self.sock.fileno()

  def close (self):
    if not self.disconnected:
      self.info("closing connection")
    else:
      #self.msg("closing connection")
      pass
    try:
      self.sock.shutdown(socket.SHUT_RDWR)
    except:
      pass
    try:
      self.sock.close()
    except:
      pass

  def disconnect (self):
    """
    disconnect this Connection (usually not invoked manually).
    """
    if self.disconnected:
      self.err("already disconnected!")
    self.msg("disconnecting")
    self.disconnected = True
    try:
      self.ofnexus._disconnect(self.dpid)
    except:
      pass
    """
    try:
      if self.dpid != None:
        self.ofnexus.raiseEvent(ConnectionDown(self))
    except:
      self.err("ConnectionDown event caused exception")
    """
    if self.dpid != None:
      self.ofnexus.raiseEventNoErrors(ConnectionDown(self))

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
    Send raw data to the switch.

    Generally, data is a bytes object.  If not, we check if it has a pack()
    method and call it (hoping the result will be a bytes object).  This
    way, you can just pass one of the OpenFlow objects from the OpenFlow
    library to it and get the expected result, for example.
    """
    if self.disconnected: return
    if type(data) is not bytes:
      if hasattr(data, 'pack'):
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
    except socket.error as (errno, strerror):
      if errno == EAGAIN:
        self.msg("Out of send buffer space.  " +
                 "Consider increasing SO_SNDBUF.")
        deferredSender.send(self, data)
      else:
        self.msg("Socket error: " + strerror)
        self.disconnect()

  def read (self):
    """
    Read data from this connection.  Generally this is just called by the
    main OpenFlow loop below.

    Note: This function will block if data is not available.
    """
    d = self.sock.recv(2048)
    if len(d) == 0:
      return False
    self.buf += d
    l = len(self.buf)
    while l > 4:
      if ord(self.buf[0]) != of.OFP_VERSION:
        log.warning("Bad OpenFlow version (" + str(ord(self.buf[0])) +
                    ") on connection " + str(self))
        return False
      # OpenFlow parsing occurs here:
      ofp_type = ord(self.buf[1])
      packet_length = ord(self.buf[2]) << 8 | ord(self.buf[3])
      if packet_length > l: break
      msg = classes[ofp_type]()
      # msg.unpack implicitly only examines its own bytes, and not trailing
      # bytes 
      msg.unpack(self.buf)
      self.buf = self.buf[packet_length:]
      l = len(self.buf)
      try:
        h = handlers[ofp_type]
        h(self, msg)
      except:
        log.exception("%s: Exception while handling OpenFlow message:\n" +
                      "%s %s", self,self,
                      ("\n" + str(self) + " ").join(str(msg).split('\n')))
        continue
    return True

  def _incoming_stats_reply (self, ofp):
    # This assumes that you don't receive multiple stats replies
    # to different requests out of order/interspersed.
    more = (ofp.flags & 1) != 0
    if more:
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

    if not more:
      handler = statsHandlerMap.get(self._previous_stats[0].type, None)
      s = self._previous_stats
      self._previous_stats = []
      if handler is None:
        log.warn("No handler for stats of type " +
                 str(self._previous_stats[0].type))
        return
      handler(self, s)

  def __str__ (self):
    return "[Con " + str(self.ID) + "/" + str(self.dpid) + "]"


def wrap_socket (new_sock):
  fname = datetime.datetime.now().strftime("%Y-%m-%d-%I%M%p")
  fname += "_" + new_sock.getpeername()[0].replace(".", "_")
  fname += "_" + `new_sock.getpeername()[1]` + ".pcap"
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
  def __init__ (self, port = 6633, address = '0.0.0.0'):
    Task.__init__(self)
    self.port = int(port)
    self.address = address

    core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)

  def _handle_GoingUpEvent (self, event):
    self.start()

  def run (self):
    # List of open sockets/connections to select on
    sockets = []

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((self.address, self.port))
    listener.listen(16)
    sockets.append(listener)

    log.debug("Listening for connections on %s:%s" %
              (self.address, self.port))

    con = None
    while core.running:
      try:
        while True:
          con = None
          rlist, wlist, elist = yield Select(sockets, [], sockets, 5)
          if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
            """
            try:
              timer_callback()
            except:
              print "[Timer]", sys.exc_info
            continue
            """
            if not core.running: break
            pass

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

          for con in rlist:
            if con is listener:
              new_sock = listener.accept()[0]
              if pox.openflow.debug.pcap_traces:
                new_sock = wrap_socket(new_sock)
              new_sock.setblocking(0)
              # Note that instantiating a Connection object fires a
              # ConnectionUp event (after negotation has completed)
              newcon = Connection(new_sock)
              sockets.append( newcon )
              #print str(newcon) + " connected"
            else:
              if con.read() is False:
                con.close()
                sockets.remove(con)
      except exceptions.KeyboardInterrupt:
        break
      except:
        doTraceback = True
        if sys.exc_info()[0] is socket.error:
          if sys.exc_info()[1][0] == ECONNRESET:
            con.info("Connection reset")
            doTraceback = False

        if doTraceback:
          log.exception("Exception reading connection " + str(con))

        if con is listener:
          log.error("Exception on OpenFlow listener.  Aborting.")
          break
        try:
          con.close()
        except:
          pass
        try:
          sockets.remove(con)
        except:
          pass

    log.debug("No longer listening for connections")

    #pox.core.quit()

classes.extend( make_type_to_class_table())

handlers.extend([None] * (1 + sorted(handlerMap.keys(), reverse=True)[0]))
for h in handlerMap:
  handlers[h] = handlerMap[h]
  #print handlerMap[h]


def launch (port = 6633, address = "0.0.0.0"):
  if core.hasComponent('of_01'):
    return None
  l = OpenFlow_01_Task(port = int(port), address = address)
  core.register("of_01", l)
  return l

