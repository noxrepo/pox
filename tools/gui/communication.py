'''
This module implements the communication between 
    - the topology view and the monitoring backend that feeds it
    - the log view and NOX's logger
    - the json command prompt and NOX's json messenger

@author Kyriakos Zarifis
'''
from PyQt4 import QtGui, QtCore


import SocketServer
import socket
import logging
import json
import asyncore
from time import sleep
import cPickle
import struct

# JSON decoder used by default
defaultDecoder = json.JSONDecoder()
      
class Communication(QtCore.QThread, QtGui.QWidget):

    ''' 
    Communicates with backend in order to receive topology-view
    information. Used to communicate with GuiMessenger for other, component-
    specific event notification too.
    '''
    # Define signals that are emitted when messages are received
    # Interested custom views connect these signals to their slots
    
    # Signal used to notify te view that tunnels have been updated
    #tunnels_reply_received_signal = QtCore.pyqtSignal()
    
    # Signal used to notify te view that new TED info was received
    #ted_reply_received_signal = QtCore.pyqtSignal()
    
    # Signal used to notify te view that tunnels might have changed 
    #link_status_change_signal = QtCore.pyqtSignal()
    
    # Define a new signal that takes a SwitchQueryReply type as an argument
    #switch_query_reply_received_signal = QtCore.pyqtSignal()# SwitchQueryReply )
    
    # Signal used to notify monitoring view of new msg 
    monitoring_received_signal = QtCore.pyqtSignal(object)
    
    # Define a new signal that takes a Topology type as an argument
    topology_received_signal = QtCore.pyqtSignal(object)
   
    # Signal used to notify STP view of new msg 
    spanning_tree_received_signal = QtCore.pyqtSignal(object)
    
    # Signal used to notify routing view of new msg 
    routing_received_signal = QtCore.pyqtSignal(object)
    
    # Signal used to notify FlowTracer view of new msg 
    flowtracer_received_signal = QtCore.pyqtSignal(object)
    
    # Signal used to notify Log of new msg 
    log_received_signal = QtCore.pyqtSignal(object)
    
    def __init__(self, parent):
        QtCore.QThread.__init__(self)
        self.xid_counter = 1
        
        self.parent = parent
        self.backend_ip = self.parent.backend_ip
        self.backend_port = self.parent.backend_port
        
        # Connect socket
        self.connected = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.setblocking(0)
        try:
            self.sock.connect((self.backend_ip,self.backend_port))
            self.connected = True
        except:
            self.retry_connection()
            
        #self.subscribe_for_topochanges()
        #self.subscribe_for_linkutils()
        
        self.listener = Listener(self)
        self.listener.start()
        
        
    def retry_connection(self):
        print "Retrying connection to POX...(is 'messenger' running?)"
        sleep(2)
        try:
            self.sock.connect((self.backend_ip,self.backend_port))
            self.connected = True
        except:
            self.retry_connection()
    
    def send(self, msg):
        if not self.connected:
            print "Not connected to POX"
            return
        #if not "xid" in msg:
        #    msg["xid"] = self.xid_counter
        #self.xid_counter += 1   
        print 'Sending :', msg 
        self.sock.send(json.dumps(msg))
        
    def shutdown(self):
        #self.listener.stop()
        self.sock.shutdown(1)
        self.sock.close()
      
class Listener(QtCore.QThread):
    def __init__(self, p):
        QtCore.QThread.__init__(self)
        self.p = p
        
        self._buf = bytes()
        
    def run (self):
        while 1:
            data = self.p.sock.recv(1024)
            if data is None or len(data) == 0:
                break
            #if len(data) == 0: return
            if len(self._buf) == 0:
                if data[0].isspace():
                    self._buf = data.lstrip()
                else:
                    self._buf = data
            else:
                self._buf += data
  
            while len(self._buf) > 0:
                try:
                    msg, l = defaultDecoder.raw_decode(self._buf)
                except:
                    # Need more data before it's a valid message
                    # (.. or the stream is corrupt and things will never be okay ever again)
                    return
                        
                self._buf = self._buf[l:]
                if len(self._buf) != 0 and self._buf[0].isspace():
                    self._buf = self._buf.lstrip()
                if msg["type"] == "topology":
                    print "Recieved :", msg
                    self.p.topology_received_signal.emit(msg)
                elif msg["type"] == "monitoring":
                    self.p.monitoring_received_signal.emit(msg)
                elif msg["type"] == "spanning_tree":
                    self.p.spanning_tree_received_signal.emit(msg)
                elif msg["type"] == "sample_routing":
                    self.p.routing_received_signal.emit(msg)
                elif msg["type"] == "flowtracer":
                    self.p.flowtracer_received_signal.emit(msg)
                elif msg["type"] == "log":
                    self.p.log_received_signal.emit(msg)
                    
class ConsoleInterface():
    '''
    Sends JSON commands to NOX
    '''        
    def __init__(self, parent):
        self.consoleWidget = parent
        ##NOX host
        self.nox_host = "localhost"
        ##Port number
        self.port_no = 2703
        
    def send_cmd(self, cmd=None, expectReply=False):        
        # if textbox empty, construct command
        if not cmd:
            print "sending dummy cmd"
            cmd = "{\"type\":\"lavi\",\"command\":\"request\",\"node_type\":\"all\"}"
        #Send command
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.nox_host,self.port_no))
        sock.send(cmd)
        if expectReply:
            print json.dumps(json.loads(sock.recv(4096)), indent=4)
        sock.send("{\"type\":\"disconnect\"}")
        sock.shutdown(1)
        sock.close() 