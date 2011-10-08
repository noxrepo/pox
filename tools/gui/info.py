'''
The info display of the GUI. This presents the custom information triggered by
View requests. (eg switch query replies)

@author Kyriakos Zarifis
'''

from PyQt4 import QtGui, QtCore, QtSql

class InfoWidget(QtGui.QListView):
    '''
    The panel used to display information interactively (e.g. switch info)  
    '''
    def __init__(self, parent=None):
        QtGui.QListWidget.__init__(self, parent)
        
        # Configure Widget
        self.parent = parent
        
        # Colors
        self.setStyleSheet("background-color: black; color: green")
        
        self.setWordWrap(True)
        
        self.model = QtGui.QStringListModel()
        self.setModel(self.model)
        
        self.append("Ready")
        self.show()
        
    def append(self, msg):
        '''
        Appends an entry to the model and the ListView
        '''
        row = self.model.rowCount()
        self.model.insertRow(row,QtCore.QModelIndex())
        index = self.model.index(row, 0, QtCore.QModelIndex());
        self.model.setData(index, msg)
        
    def grab(self):
        '''
        Gives logDisplay access to an entity
        '''
        self.show()
        self.clear()
            
    def clear(self):
        '''
        Resets the model and ListView
        '''
        self.model.removeRows(0, self.model.rowCount())
        self.model.reset()
        self.reset()

    def selectedRowToString(self):
        '''
        Returns the text of the selected row
        '''
        if (self.selectedIndexes()):
            index = self.selectedIndexes()[0]
            return index.data().toString()
        return 0
