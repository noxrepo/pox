'''
TE view for drawn topology

Stores information specific to the TE view, eg tunnel table with
characteristics, colors, TunnelTablePopup window, etc 

@author Kyriakos Zarifis
'''
from PyQt4 import QtGui, QtCore

from view import View

class Default_View(View):
    def __init__(self, topoWidget):
        View.__init__(self, topoWidget, "Default")    
        
        self.a = QtGui.QLabel(" Toggle: (<font color='green'>N</font>)odes")
        self.b = QtGui.QLabel(" Node(<font color='green'>I</font>)Ds \
                Lin(<font color='green'>K</font>)s")
        self.c = QtGui.QLabel(" (<font color='green'>L</font>)inkIDs \
               (<font color='green'>P</font>)orts")
        self.d = QtGui.QLabel(" (<font color='green'>R</font>)efresh \
                                Topology")
        self.buttons.append(self.a)
        self.buttons.append(self.b)
        self.buttons.append(self.c)
        self.buttons.append(self.d)
        
    def link_pattern(self, link):
        pattern = QtCore.Qt.SolidLine
        return pattern
        
    def link_color(self, link):
        color = QtCore.Qt.gray
        return color
    
    def node_color(self, node):
        return
