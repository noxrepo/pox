'''
Spanning_tree GUI view

@author Kyriakos Zarifis (kyr.zarifis@gmail.com)
'''

from PyQt4 import QtGui, QtCore
from view import View
#import simplejson as json
import json
from collections import deque
import random


colors = [QtCore.Qt.red, QtCore.Qt.green, QtCore.Qt.blue, QtCore.Qt.yellow]

class Sample_Routing_View(View):

    def __init__(self, topoWidget):
        # Custom view name must be defined here
        View.__init__(self, topoWidget, "Routing")    

        # Add custom view buttons 
        infoBtn = QtGui.QPushButton('What is Routing?')
        self.connect(infoBtn, QtCore.SIGNAL('clicked()'), self.showInfo)
        self.buttons.append(infoBtn)
        
        self.topologyInterface.routing_received_signal.connect( \
            self.got_json_msg )
            
        # Subscribe to messages from backend 
        msg = {}
        msg["_mux"] = "gui"
        msg["type"] = "sample_routing"
        msg["command"] = "subscribe"
        msg["msg_type"] = "highlight"
        self.topologyInterface.send( msg )     
        
        # throw paths that we want to highlight in this queue and remove them
        # after a while to restore color.
        self.highlighted_paths = deque()
        
    def got_json_msg(self, msg):
        ''' Handle json messages received from NOX sample_routing component '''
        jsonmsg = json.loads(str(msg))
        
        if jsonmsg["type"] != "sample_routing":
            return
            
        if jsonmsg["msg_type"] == "highlight":
            p = jsonmsg['path']
            
        # Timer to signal end of highlighting the new path
        timer = QtCore.QTimer(self)
        timer.setSingleShot(True)
        self.connect(timer,
                     QtCore.SIGNAL("timeout()"),
                     self.timerhandler)
        timer.start(500)
        
        # Put links that we'll highlight here
        links = []
        
        # Add first link
        minend=min(self.topologyView.nodes[p[1]].neighbors[p[0]], p[1])
        maxend=max(self.topologyView.nodes[p[1]].neighbors[p[0]], p[1])
        firstlink = minend+'-'+maxend
        links.append(firstlink)
        
        # Add last link
        minend=min(self.topologyView.nodes[p[len(p)-2]].neighbors[p[len(p)-1]],\
            p[len(p)-2])
        maxend=max(self.topologyView.nodes[p[len(p)-2]].neighbors[p[len(p)-1]],\
            p[len(p)-2])
        lastlink = minend+'-'+maxend
        links.append(lastlink)
        
        # Add intermediate links
        p = p[1:len(p)-1]
        for i in range(0,len(p)-1):
            links.append( (min((p[i],p[i+1]))+'-'+max((p[i],p[i+1]))) )
        
        # Add path-to-be-highlighted on the highlighted_paths list
        # along with a random color to paint it
        self.highlighted_paths.append((links,random.choice(colors)))
            
        # Redraw those links       
        for l in links:
            #if l in self.topologyView.links: 
            self.topologyView.links[l].update()
       
    def timerhandler(self):
        # Remove last path from the highlighted list
        self.highlighted_paths.popleft()
        self.topologyView.updateAllLinks()
        
    def node_color(self, node):
        pass

    def link_color(self, link):
        s = link.source.id
        d = link.dest.id
        l = str((min(s,d))) +'-'+str(max((s,d)))
        
        for path in self.highlighted_paths:
            if l in path[0]: 
                return path[1]
        return QtCore.Qt.gray

    def link_pattern(self, link):
        pass
        
    def showInfo(self):
        ''' Routing view information popup'''
        self.buttons[0].setChecked(True)

        msgBox = QtGui.QMessageBox()
        msgBox.setWindowTitle("Routing View")
        msgBox.setText("This is the frontend view to NOX's 'sample_routing' "+\
            "module. Whenever 'sample_routing' calculates a path for a "+\
            "new flow, it communicates it to the GUI, which momentarily "+\
            "highlights the path of the newly established flow.")
        msgBox.exec_()
