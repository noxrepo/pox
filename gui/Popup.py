'''
Collection of popup widgets 

@author Kyriakos Zarifis
'''

from PyQt4 import QtGui, QtCore
import os

class FilterComboBox(QtGui.QDialog):
        '''
        Base for CompComboBox and VerbComboBox
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.combo = QtGui.QGroupBox(self) 
            
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            self.hbox = QtGui.QHBoxLayout()
            self.hbox.addStretch(1)
            self.hbox.addWidget(cancel)
            self.hbox.addWidget(ok)

            self.vbox = QtGui.QVBoxLayout()
            self.checkboxes = [] 
            self.addCheckboxes()
            self.combo.setLayout(self.vbox)
            self.vbox.addLayout(self.hbox)
            self.vbox.addStretch(1)
            
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.setCompFilter)
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            
            #print self.sizeHint()
            self.adjustSize()
                            
        def setCompFilter(self):
            self.selection = ''
            for cb in self.checkboxes:
                if cb.isChecked():
                    self.selection = self.selection +' '+ cb.text()
            self.textbox.setText(self.selection[1:])
            self.parent._filter()
            self.accept()
                
        def cancel(self):
            self.reject()
      
class TsComboBox(QtGui.QDialog):
        '''
        Popup a ComboBox for timestamp selection
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QDialog.__init__(self,self.parent)
            self.textbox = self.parent.tsEdit                
            self.setWindowTitle('Select range')            
            
            self.grid = QtGui.QGridLayout()
            rangeFrom = QtGui.QLabel("From:")
            rangeTo = QtGui.QLabel("To:")
            self.fromEdit = QtGui.QLineEdit()
            self.toEdit = QtGui.QLineEdit()
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            ok.setDefault(True)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.start)
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            self.grid.addWidget(rangeFrom,       0, 0)
            self.grid.addWidget(self.fromEdit,   0, 1)
            self.grid.addWidget(rangeTo,         1, 0)
            self.grid.addWidget(self.toEdit,     1, 1)
            self.grid.addWidget(cancel,          2, 0)
            self.grid.addWidget(ok,              2, 1)
            self.setLayout(self.grid)
            self.adjustSize()
            
        def start(self):
            self.textbox.setText(self.fromEdit.text()+"-"+self.toEdit.text())
            self.parent._filter()
            self.accept()
                
        def cancel(self):
            self.reject()            
                    
        def addCheckboxes(self):
            pass            
                                
class CompComboBox(FilterComboBox):
        '''
        Popup a ComboBox with running components
        '''
        def __init__(self, parent=None):
            self.parent = parent
            FilterComboBox.__init__(self,self.parent)
            self.textbox = self.parent.compEdit            
            self.setWindowTitle('Filter by components')
            self.resize(250, 600)
                    
        def addCheckboxes(self):            
            self.vbox.addWidget(QtGui.QLabel("Show the following components:"))
            
            select = "select distinct component from messages"
                
            q = self.parent.parent.dbWrapper.q       
            q.exec_("select distinct component from messages")  
            fieldNo = q.record().indexOf("component")
            while q.next():
                b = QtGui.QCheckBox(q.value(fieldNo).toString())
                self.vbox.addWidget(b)
                self.checkboxes.append(b)
                                  
class VerbComboBox(FilterComboBox):
        '''
        Popup a ComboBox with verbosity levels
        '''
        def __init__(self, parent=None):
            self.parent = parent
            FilterComboBox.__init__(self,self.parent)
            self.textbox = self.parent.verbEdit                
            self.setWindowTitle('Select verbosity')
            self.resize(250, 250)
                    
        def addCheckboxes(self):
            levels = ['EMER','ERR', 'WARN','INFO', 'DEBUG']
            for lvl in levels:
                b = QtGui.QCheckBox(lvl)
                self.vbox.addWidget(b)
                self.checkboxes.append(b)
            
class StartComboBox(QtGui.QDialog):
        '''
        NOX Initialization dialog
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.resize(600, 330)   
            self.setWindowTitle('Start NOX')            
            
            
            vsep = QtGui.QFrame()
            vsep.setFrameStyle(QtGui.QFrame.VLine)
            hsep = QtGui.QFrame()
            hsep.setFrameStyle(QtGui.QFrame.HLine)
            
            label1 = QtGui.QLabel('Select options:', self) 
            
            # Select Interface
            int_ptcp = QtGui.QRadioButton("ptcp")
            int_ptcp.setChecked(True)
            int_nl = QtGui.QRadioButton("netlink")
            int_pssl = QtGui.QRadioButton("pssl")
            int_pcap = QtGui.QRadioButton("pcap")
            int_pgen = QtGui.QRadioButton("pgen")
            int_port = QtGui.QLineEdit('6633')
            int_dpid =QtGui.QLineEdit()
            int_grid = QtGui.QGridLayout()
            int_grid.addWidget(QtGui.QLabel('Interface:'),   1, 0)
            int_grid.addWidget(int_ptcp,    2, 0)
            int_grid.addWidget(QtGui.QLabel('Port:'),   2, 1)
            int_grid.addWidget(int_port,    2, 2)
            int_grid.addWidget(int_nl,      3, 0)
            int_grid.addWidget(QtGui.QLabel('Datapath ID:'),   3, 1)
            int_grid.addWidget(int_dpid,    3, 2)
            int_grid.addWidget(int_pssl,    4, 0)
            int_grid.addWidget(int_pcap,    5, 0)
            int_grid.addWidget(int_pgen,    6, 0)
            interface = QtGui.QGroupBox() 
            interface.setLayout(int_grid)
                    
            # Other Options
            opt_verb = QtGui.QCheckBox("Verbosity")
            opt_verb.setChecked(True)
            opt_libdir = QtGui.QCheckBox("Look for app libs:")
            opt_conf = QtGui.QCheckBox("Configuration file:")
            opt_info = QtGui.QCheckBox("Info file:")
            opt_daem = QtGui.QCheckBox("Run as daemon")
            opt_grid = QtGui.QGridLayout()
            opt_grid.addWidget(QtGui.QLabel('Other options:'),   1, 0)
            opt_grid.addWidget(opt_verb,    2, 0)
            opt_grid.addWidget(QtGui.QLabel('Level:'),   2, 1)
            #opt_grid.addWidget(int_port,    2, 3)
            opt_grid.addWidget(opt_libdir,  3, 0)
            opt_grid.addWidget(opt_conf,    4, 0)
            opt_grid.addWidget(opt_info,    5, 0)
            opt_grid.addWidget(opt_daem,    6, 0)
            options = QtGui.QGroupBox() 
            #options.setLayout(opt_vbox) 
            options.setLayout(opt_grid)        
            
            hbox1 = QtGui.QHBoxLayout()
            hbox1.addWidget(interface)
            #hbox1.addWidget(vsep)
            hbox1.addWidget(options)
            int_opt = QtGui.QGroupBox(self)
            int_opt.setLayout(hbox1)
            
            hbox2 = QtGui.QHBoxLayout()
            self.command = QtGui.QLineEdit()
            self.command.setText("./nox_core -v -i ptcp:6633")
            hbox2.addWidget(QtGui.QLabel('Or type command:'))
            hbox2.addWidget(self.command) 
            command = QtGui.QGroupBox(self)
            command.setLayout(hbox2)
            
            # Buttons
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            ok.setDefault(True)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.start)
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            
            # cancel/ok hbox
            hbox3 = QtGui.QHBoxLayout()
            hbox3.addStretch(1)
            hbox3.addWidget(cancel)
            hbox3.addWidget(ok)
            buttons = QtGui.QGroupBox(self) 
            buttons.setLayout(hbox3)   
            
            # Lay out objects (x, y)
            label1.move(20,10)
            command.move(0,230)
            buttons.move(380,260)
            
                            
        def start(self):
            # Fork and execute ./nox_core command
            '''
            pid = os.fork()
            if pid:
                print "child starting nox"
                os.system(str(self.command.text()))
                print "dead"
                #os._exit(0)
            '''
            self.parent.logWidget.logDisplay.setText('For now, please start NOX manually from the console')
            self.accept()
                
        def cancel(self):
            self.reject()

