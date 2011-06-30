from pox.core import core
import pox

from pox.openflow.openflow import *

log = core.getLogger()

import socket
import select
import pox.openflow.libopenflow_01 as of

import threading
import os
import sys
import exceptions

"""
from packet.tcp           import tcp
from packet.udp           import udp
from packet.vlan          import vlan
from packet.ipv4         import ipv4
from packet.icmp         import icmp
from packet.ethernet     import ethernet
from packet.packet_utils import mac_to_str, mac_to_int

from time import time
from socket import htons

"""


import traceback


def handle_HELLO (con, msg): #S
  #con.msg("HELLO wire protocol " + hex(msg.header.version))

  # Send a features request
  msg = of.ofp_features_request()
  con.send(msg.pack())

def handle_ECHO_REQUEST (con, msg): #S
  reply = msg
  # Ha ha, just change the type and send it back
  reply.header.type = of.OFPT_ECHO_REPLY
  con.send(reply.pack())

def handle_FEATURES_REPLY (con, msg):
  con.features = msg
  con.dpid = msg.datapath_id
  con.msg("Connected to dpid " + str(msg.datapath_id))
  openflowHub.raiseEvent(ConnectionUp(con))

def handle_PORT_STATUS (con, msg): #A
  openflowHub.raiseEventNoErrors(PortStatus(con, msg))

def handle_PACKET_IN (con, msg): #A
  openflowHub.raiseEventNoErrors(PacketIn, con, msg)
#  if PacketIn in openflowHub._eventMixin_handlers:
#    p = ethernet(msg.data)
#    openflowHub.raiseEventNoErrors(PacketIn(con, msg, p))

def handle_ERROR_MSG (con, msg): #A
  log.error(str(con) + " OpenFlow Error:\n" + msg.show(str(con) + " Error: ").strip())

"""
def handle_FLOW_REMOVED (con, msg): #A

def handle_VENDOR (con, msg): #S
"""








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


# A list, where the index is an OFPT, and the value is a pyopenflow class for that type
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
}

# Deferred sending should be unusual, so don't worry too much about efficiency
class DeferredSender (threading.Thread):
  def __init__ (self):
    threading.Thread.__init__(self)
    self._dataForConnection = {}
    self._lock = threading.RLock()
    self._waker = os.pipe()
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

      os.write(self._waker[1], ' ')

  def kill (self, con):
    with self._lock:
      try:
        del self._dataForConnection[con]
      except:
        pass

      os.write(self._waker[1], ' ')

  def run (self):
    while core.running:

      with self._lock:
        cons = self._dataForConnection.keys()

      rlist, wlist, elist = select.select([self._waker[0]], cons, cons, 1)
      if not core.running: break

      with self._lock:
        if len(rlist) > 0:
          os.read(self._waker[0], 1024)

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

#deferredSender = DeferredSender()

class Connection:
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
    print str(self) + " disconnected"
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
      deferredSender.kill(self)
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
        print "Bad OpenFlow version (" + str(ord(self.buf[0])) + ") on connection " + str(self)
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
        print msg.show(str(self) + " " + of.ofp_type[t] + " "),
        continue
    return True

  def __str__ (self):
    return "[Con " + str(self.ID) + "/" + str(self.dpid) + "]"


from pox.lib.recoco.recoco import *

class OpenFlow_01_Task (Task):
  def __init__ (self, port = 6633, address = '0.0.0.0'):
    Task.__init__(self)
    self.port = port
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
    listener.listen(0)
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


def start (*args, **kw):
  l = OpenFlow_01_Task(*args, **kw)
  #l = OpenFlow_01_Loop(*args, **kw)
  return l

