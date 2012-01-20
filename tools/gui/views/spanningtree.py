'''
Spanning_tree GUI view

@author Kyriakos Zarifis (kyr.zarifis@gmail.com)
'''

from PyQt4 import QtGui, QtCore
from view import View
#import simplejson as json
import json

class STP_View(View):

    def __init__(self, topoWidget):
        # Custom view name must be defined here
        View.__init__(self, topoWidget, "STP")    

        # Add custom view buttons 
        infoBtn = QtGui.QPushButton('What is STP?')
        self.connect(infoBtn, QtCore.SIGNAL('clicked()'), self.showInfo)
        self.buttons.append(infoBtn)
        
        # Connect signal raised when msg arrives from backend to handler
        self.topologyInterface.spanning_tree_received_signal.connect( \
            self.got_json_msg )
            
        # Subscribe for stp_ports 
        msg = {}
        msg["_mux"] = "gui"
        msg["type"] = "spanning_tree"
        msg["command"] = "subscribe"
        msg["msg_type"] = "stp_ports"
        self.topologyInterface.send( msg )     
        
        # Holds ST state (enabled links, root)    
        self.stp_ports = {} # Format {dpid : [port1, ..., portn]}
                            # also holds 'root':dpid
        
    def got_json_msg(self, msg):
        ''' Handle json messages received from NOX spanning_tree component '''
        jsonmsg = json.loads(str(msg))
        if jsonmsg["msg_type"] == "stp_ports":
            self.stp_ports = jsonmsg['ports']
            if 'root' in self.stp_ports:
                self.root = self.stp_ports['root']
        
    def node_color(self, node):
        ''' Paint root yellow, rest of the nodes default '''
        if node.id == self.root:
            return QtGui.QColor(QtCore.Qt.yellow)

    def link_color(self, link):
        ''' Paint STP links green, rest gray '''
        if self.isSTPEnabled(link):
            return QtCore.Qt.green
        return QtCore.Qt.gray

    def link_pattern(self, link):
        ''' Paint STP links solid, rest dotted '''
        if self.isSTPEnabled(link):
            return QtCore.Qt.SolidLine
        return QtCore.Qt.DotLine

    def isSTPEnabled(self,link):
        ''' Checks if a link is part of the spanning_tree '''
        dp = link.source.id
        port = link.sport
        if dp in self.stp_ports:
            if int(port) in self.stp_ports[dp]:
                return True
        return False
    
    def showInfo(self):
        ''' Spanning Tree view information popup'''
        self.buttons[0].setChecked(True)

        msgBox = QtGui.QMessageBox()
        msgBox.setWindowTitle("Spanning Tree View")
        msgBox.setText("This is the frontend view to the spanning_tree "+\
            "module. The backend component calculates a ST periodically or "+\
            "after topology changes and notifies the GUI if the SP has "+\
            "changed. The ST root appears in yellow. All items will appear "+\
            "gray if the STP backend is not running.")
        msgBox.exec_()
