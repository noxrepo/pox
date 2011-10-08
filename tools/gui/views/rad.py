'''
RAD view for drawn topology

@author Kyriakos Zarifis (kyr.zarifis@gmail.com)
'''

from PyQt4 import QtGui, QtCore
from view import View
import simplejson as json
import random

class RAD_View(View):

    def __init__(self, topoWidget):
        View.__init__(self, topoWidget, "RAD")    

        #self.name = "RAD"
        self.logDisplay = self.topoWidget.parent.logWidget.logDisplay
        infoBtn = QtGui.QPushButton('What is RAD?')

        self.connect(infoBtn, QtCore.SIGNAL('clicked()'), self.showInfo)
        
        self.buttons.append(infoBtn)
        
        self.nodeMenu.addAction( 'Draw DAG', self.draw_DAG )
        
    def node_color(self, node):
        pass

    def link_color(self, link):
        srcID = link.source.id
        srcPort = link.sport
        dstID = link.dest.id
        dstPort = link.dport

        return QtCore.Qt.gray

    def link_pattern(self, link):
        pattern = QtCore.Qt.SolidLine
        return pattern

    def draw_DAG(self): #(,node)
        print "Drawing DAG for node X"
        links = self.topoWidget.topologyView.links
        for key,link in links.items():
            # For now, randomly draw direction:
            #src, dst = key.split('-')
            links[key].drawArrow = True
            #links[src+"-"+dst].drawArrow = False
            #links[dst+"-"+src].drawArrow = True

    def showInfo(self):
        self.buttons[0].setChecked(True)

        msgBox = QtGui.QMessageBox()
        msgBox.setWindowTitle("RAD View")
        msgBox.setText("Basic RAD description")
        msgBox.exec_()
