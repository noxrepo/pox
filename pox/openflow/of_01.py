from pox.core import core
import pox
import pox.lib.util
from pox.lib.revent.revent import EventMixin

from pox.openflow.openflow import *

log = core.getLogger()

import socket
import select
import pox.openflow.libopenflow_01 as of

import threading
import os
import sys
import exceptions


import traceback


def handle_HELLO (con, msg): #S
  #con.msg("HELLO wire protocol " + hex(msg.version))

  # Send a features request
  msg = of.ofp_features_request()
  con.send(msg.pack())

def handle_ECHO_REQUEST (con, msg): #S
  reply = msg
  # Ha ha, just change the type and send it back
  reply.header_type = of.OFPT_ECHO_REPLY
  con.send(reply.pack())

def handle_FLOW_REMOVED (con, msg):
  openflowHub.raiseEventNoErrors(FlowRemoved, con, msg)
  con.raiseEventNoErrors(FlowRemoved, con, msg)

def handle_FEATURES_REPLY (con, msg):
  con.features = msg
  con.dpid = msg.datapath_id
  con.msg("Connected to dpid " + str(msg.datapath_id))
  openflowHub._connections[con.dpid] = con
  #for p in msg.ports: print(p.show())
  openflowHub.raiseEvent(ConnectionUp, con, msg)
  con.raiseEvent(ConnectionUp, con, msg)

def handle_STATS_REPLY (con, msg):
  openflowHub.raiseEventNoErrors(RawStatsReply, con, msg)
  con.raiseEventNoErrors(RawStatsReply, con, msg)
  con._incoming_stats_reply(msg)

def handle_PORT_STATUS (con, msg): #A
  openflowHub.raiseEventNoErrors(PortStatus, con, msg)
  con.raiseEventNoErrors(PortStatus, con, msg)

def handle_PACKET_IN (con, msg): #A
  openflowHub.raiseEventNoErrors(PacketIn, con, msg)
  con.raiseEventNoErrors(PacketIn, con, msg)
#  if PacketIn in openflowHub._eventMixin_handlers:
#    p = ethernet(msg.data)
#    openflowHub.raiseEventNoErrors(PacketIn(con, msg, p))

def handle_ERROR_MSG (con, msg): #A
  log.error(str(con) + " OpenFlow Error:\n" + msg.show(str(con) + " Error: ").strip())
  openflowHub.raiseEventNoErrors(ErrorIn, con, msg)
  con.raiseEventNoErrors(ErrorIn, con, msg)

def handle_FLOW_REMOVED (con, msg): #A
  openflowHub.raiseEventNoErrors(FlowRemoved, con, msg)
  con.raiseEventNoErrors(FlowRemoved, con, msg)

def handle_BARRIER (con, msg):
  openflowHub.raiseEventNoErrors(BarrierIn, con, msg)
  con.raiseEventNoErrors(BarrierIn, con, msg)

#TODO: def handle_VENDOR (con, msg): #S


def _processStatsBody (body, obj):
  l = len(obj)
  t = obj.__class__
  r = []
  for i in range(len(body) // l):
    if i != 0: obj = t()
    obj.unpack(body[i * l: i * l + l])
    r.append(obj)
  return r

# handlers for stats replies
def handle_OFPST_DESC (con, parts):
  msg = of.ofp_desc_stats()
  msg.unpack(parts[0].body)
  openflowHub.raiseEventNoErrors(SwitchDescReceived, con, parts[0], msg)
  con.raiseEventNoErrors(SwitchDescReceived, con, parts[0], msg)

def handle_OFPST_FLOW (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_flow_stats())
  openflowHub.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)

def handle_OFPST_AGGREGATE (con, parts):
  msg = of.ofp_aggregate_stats_reply()
  msg.unpack(parts[0].body)
  openflowHub.raiseEventNoErrors(AggregateFlowStatsReceived, con, parts[0], msg)
  con.raiseEventNoErrors(AggregateFlowStatsReceived, con, parts[0], msg)

def handle_OFPST_TABLE (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_table_stats())
  openflowHub.raiseEventNoErrors(TableStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(TableStatsReceived, con, parts, msg)

def handle_OFPST_PORT (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_port_stats())
  openflowHub.raiseEventNoErrors(PortStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(PortStatsReceived, con, parts, msg)

def handle_OFPST_QUEUE (con, parts):
  msg = []
  for part in parts:
    msg += _processStatsBody(part.body, of.ofp_queue_stats())
  openflowHub.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)
  con.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)


# See "classes"
def make_type_to_class_table ():
  classes = {}
  max = -1
  d = of.__dict__
  for k in d.keys():
    if k.startswith('OFPT_'):
      c = 'ofp' + k[4:].lower()
      cls = (d[c])
      num = d[k]
      classes[num] = cls
      if num > max: max = num

  if len(classes) != max + 1:
    raise "Bad protocol to class mapping"

  return [classes[i] for i in range(0, max)]


# A list, where the index is an OFPT, and the value is a libopenflow class for that type
classes = []

# A list, where the index is an OFPT, and the value is a function to call for that type
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

# Deferred sending should be unusual, so don't worry too much about efficiency
class DeferredSender (threading.Thread):
  def __init__ (self):
    threading.Thread.__init__(self)
    self._dataForConnection = {}
    self._lock = threading.RLock()
    self._waker = pox.lib.util.makePinger()
    self.daemon = True
    self.sending = False

    self.start()

  def _sliceup (self, data):
    out = []
    while len(data) > select.PIPE_BUF:
      out.append(data[0:select.PIPE_BUF])
      data = data[select.PIPE_BUF:]
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
                if errno != socket.EAGAIN:
                  con.msg("Socket errror: " + strerror)
                  con.disconnect()
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

deferredSender = DeferredSender()

class Connection (EventMixin):
  _eventMixin_events = set([
    ConnectionUp,
    ConnectionDown,
    PortStatus,
    FlowRemoved,
    PacketIn,
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

    self.sock = sock
    self.buf = ''
    Connection.ID += 1;
    self.ID = Connection.ID
    self.dpid = None
    self.features = None

    msg = of.ofp_hello()
    self.send(msg.pack())

    #TODO: set a time that makes sure we actually establish a connection by some timeout

  def fileno (self):
    return self.sock.fileno()

  def disconnect (self):
    self.msg("disconnected")
    try:
      del openflowHub._connections[self.dpid]
    except:
      pass
    """
    try:
      if self.dpid != None:
        openflowHub.raiseEvent(ConnectionDown(self))
    except:
      self.err("ConnectionDown event caused exception")
    """
    if self.dpid != None:
      openflowHub.raiseEventNoErrors(ConnectionDown(self))

    try:
      #deferredSender.kill(self)
      pass
    except:
      pass
    try:
      self.sock.close()
    except:
      pass
    try:
      pass
      #TODO disconnect notification
    except:
      pass

  def send (self, data):
    if type(data) is not bytes:
      if hasattr(data, 'pack'):
        data = data.pack()

    if deferredSender.sending:
      deferredSender.send(self, data)
      return
    try:
      l = self.sock.send(data)
      if l != len(data):
        self.msg("Didn't send complete buffer.")
        data = data[l:]
        deferredSender.send(self, data)
    except socket.error as (errno, strerror):
      if errno == socket.EAGAIN:
        self.msg("Out of send buffer space.  Consider increasing SO_SNDBUF.")
        deferredSender.send(self, data)
      else:
        self.msg("Socket errror: " + strerror)
        self.disconnect()

  def read (self):
    d = self.sock.recv(2048)
    if len(d) == 0:
      return False
    self.buf += d
    l = len(self.buf)
    while l > 4:
      if ord(self.buf[0]) != of.OFP_VERSION:
        log.warning("Bad OpenFlow version (" + str(ord(self.buf[0])) + ") on connection " + str(self))
        return False
      t = ord(self.buf[1])
      pl = ord(self.buf[2]) << 8 | ord(self.buf[3])
      if pl > l: break
      msg = classes[t]()
      msg.unpack(self.buf)
      self.buf = self.buf[pl:]
      l = len(self.buf)
      try:
        h = handlers[t]
        h(self, msg)
      except:
        print msg.show(str(self) + " " + str(of.ofp_type[t]) + " caused:")
        import traceback
        traceback.print_exc()
        continue
    return True

  def _incoming_stats_reply (self, ofp):
    # This assumes that you don't recieve multiple stats replies
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


from pox.lib.recoco.recoco import *

class OpenFlow_01_Task (Task):
  def __init__ (self, port = 6633, address = '0.0.0.0'):
    Task.__init__(self)
    self.port = int(port)
    self.address = address
    self.daemon = True

    core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)

  def _handle_GoingUpEvent (self, event):
    global openflowHub
    openflowHub = core.openflow
    self.start()

  def run (self):
    #TODO: This is actually "the main thread", and should actually be pulled out
    #      so that other things (OpenFlow 1.1 switches, etc.) can use it too.
    #      Probably this should mean that this thread will run the cooperative
    #      threads.

    # List of open sockets/connections to select on
    sockets = []

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((self.address, self.port))
    listener.listen(16)
    sockets.append(listener)
    wsocks = []

    log.debug("Listening for connections")

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
                con.disconnect()
              except:
                pass
              try:
                sockets.remove(con)
              except:
                pass

          for con in rlist:
            if con is listener:
              new_sock = listener.accept()[0]
              new_sock.setblocking(0)
              newcon = Connection(new_sock)
              sockets.append( newcon )
              #print str(newcon) + " connected"
            else:
              if con.read() == False:
                con.disconnect()
                sockets.remove(con)
      except exceptions.KeyboardInterrupt:
        break
      except:
        print "Exception",con,sys.exc_info()[0],sys.exc_info()[1]
        print "Traceback (most recent last):"
        traceback.print_tb(sys.exc_info()[2])

        if con is listener:
          print "Error in listener.  Aborting"
          break
        try:
          con.disconnect()
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


def launch (*args, **kw):
  if core.hasComponent('of_01'):
    return None
  l = OpenFlow_01_Task(*args, **kw)
  #l = OpenFlow_01_Loop(*args, **kw)
  core.register("of_01", l)
  return l

