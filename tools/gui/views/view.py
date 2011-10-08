'''
Base class for custom topology views

Custom topology views extend this by optionally adding secondary buttons,
coloring behavior, communication with the backend. Any logic is included in the
custom view files. (for example, spanning_tree view has the notion of st-enabled
links)

@author Kyriakos Zarifis (kyr.zarifis@gmail.com)
'''
from PyQt4 import QtGui, QtCore

class View(QtGui.QWidget):
    def __init__(self, topoWidget, name):
        QtGui.QWidget.__init__(self)
        
        # Convenience references
        self.topoWidget = topoWidget
        self.topologyView = self.topoWidget.topologyView
        self.topologyInterface = self.topologyView.topologyInterface
        self.infoDisplay = self.topoWidget.parent.infoWidget
        self.logDisplay = self.topoWidget.parent.logWidget.logDisplay
        
        # View-specific buttons, added by derived views
        self.buttons = []      
        
        # View must be initialized be derived views
        self.name = name         
        
        # View-specific node commands (right-click on nodes)
        self.nodeMenu = QtGui.QMenu(self.name)
        
        # View-specific link commands (right-click on links)
        self.linkMenu = QtGui.QMenu('&View-Specific')
        
    def show(self):
        # Give draw access
        self.topoWidget.topologyView.drawAccess = self.name
        
        # Clear view-specific buttons
        for btn in self.topoWidget.changeViewWidget.secondaryBtns:
            self.topoWidget.changeViewWidget.grid.removeWidget(btn) 
            btn.hide()
        # Add view-specific buttons, if any defined in derived class
        for i in range(0,len(self.buttons)): 
            self.topoWidget.changeViewWidget.grid.addWidget(self.buttons[i], 1, i)
            self.buttons[i].show()
            
        self.topoWidget.changeViewWidget.secondaryBtns = self.buttons
        
    #def leave(self):
        # Views override this method in order to reset any drawing state
        # when exiting the view.
