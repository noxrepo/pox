'''
Collection of popup widgets 

@author Kyriakos Zarifis
'''

from PyQt4 import QtGui, QtCore
import os

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
            
        def start(self):
            self.textbox.setText(self.fromEdit.text()+"-"+self.toEdit.text())
            self.parent._filter()
            self.accept()
                
        def cancel(self):
            self.reject()            
                    
        def addCheckboxes(self):
            pass            
       
                      
class FilterComboBox(QtGui.QDialog):
        '''
        Base for CompComboBox and VerbComboBox
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            
            self.checkboxes = []
            checkboxes = self.createCheckboxList()            
            buttons = self.createButtons()
            
            self.grid = QtGui.QVBoxLayout()            
            self.grid.addWidget(checkboxes)
            self.grid.addWidget(buttons)
            
            self.setLayout(self.grid) 
                            
        def createButtons(self):
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            hbox = QtGui.QHBoxLayout()
            hbox.insertStretch(0)
            hbox.addWidget(cancel)
            hbox.addWidget(ok)          
            
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.setCompFilter)
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            
            buttons = QtGui.QGroupBox()
            buttons.setLayout(hbox)
            return buttons
        
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
            
class VerbComboBox(FilterComboBox):
        '''
        Popup a ComboBox with verbosity levels
        '''
        def __init__(self, parent=None):
            self.parent = parent
            FilterComboBox.__init__(self,self.parent)
            self.textbox = self.parent.verbEdit                
            self.setWindowTitle('Select verbosity')
                    
        def createCheckboxList(self):
            vbox = QtGui.QVBoxLayout()
            levels = ['EMER','ERR', 'WARN','INFO', 'DEBUG']
            for lvl in levels:
                b = QtGui.QCheckBox(lvl)
                vbox.addWidget(b)
                self.checkboxes.append(b)
            levels = QtGui.QGroupBox("Verbosity levels")
            levels.setLayout(vbox)
            return levels        

class CompComboBox(FilterComboBox):
        '''
        Popup a ComboBox with running components
        '''
        def __init__(self, parent=None):
            self.parent = parent
            FilterComboBox.__init__(self, self.parent)
            self.textbox = self.parent.compEdit
            self.setWindowTitle('Filter')                                    
            
        def createCheckboxList(self):
            vbox = QtGui.QVBoxLayout()
            select = "select distinct component from messages"                
            q = self.parent.parent.dbWrapper.q       
            q.exec_("select distinct component from messages")  
            fieldNo = q.record().indexOf("component")
            while q.next():
                b = QtGui.QCheckBox(q.value(fieldNo).toString())
                vbox.addWidget(b)
                self.checkboxes.append(b)
            if not self.checkboxes:
                vbox.addWidget(QtGui.QLabel("No components found yet"))
            components = QtGui.QGroupBox("Running Components")
            components.setLayout(vbox)
            return components                
            
class StartComboBox(QtGui.QDialog):
        '''
        NOX Initialization dialog
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.setWindowTitle('Start POX')            
            
            interface = self.createInterfaceBox()
            options = self.createOptionsBox()
            command = self.createCommandBox()
            buttons = self.createButtonsBox()
                        
            finalGrid = QtGui.QGridLayout()
            finalGrid.addWidget(interface, 1, 0)
            finalGrid.addWidget(options,   1, 1)
            finalGrid.addWidget(command,   2, 0)
            finalGrid.addWidget(buttons,   2, 1)
            self.setLayout(finalGrid)
            
        def createInterfaceBox(self):
            # Interface Options
            int_ptcp = QtGui.QRadioButton("ptcp")
            int_ptcp.setChecked(True)
            int_nl = QtGui.QRadioButton("netlink")
            int_pssl = QtGui.QRadioButton("pssl")
            int_pcap = QtGui.QRadioButton("pcap")
            int_pgen = QtGui.QRadioButton("pgen")
            int_port = QtGui.QLineEdit('6633')
            int_dpid = QtGui.QLineEdit()
            int_grid = QtGui.QGridLayout()
            int_grid.addWidget(int_ptcp,    1, 0)
            int_grid.addWidget(QtGui.QLabel('Port:'),   1, 1)
            int_grid.addWidget(int_port,    1, 2)
            int_grid.addWidget(int_nl,      2, 0)
            int_grid.addWidget(QtGui.QLabel('Datapath ID:'),   2, 1)
            int_grid.addWidget(int_dpid,    2, 2)
            int_grid.addWidget(int_pssl,    3, 0)
            int_grid.addWidget(int_pcap,    4, 0)
            int_grid.addWidget(int_pgen,    5, 0)
            interface = QtGui.QGroupBox("Interface") 
            interface.setLayout(int_grid)
            return interface
    
        def createOptionsBox(self):      
            # Other Options
            opt_verb = QtGui.QCheckBox("Verbosity")
            opt_verb.setChecked(True)
            opt_verblevel = QtGui.QComboBox()
            opt_verblevel.addItem("DEBUG")
            opt_verblevel.addItem("INFO")
            opt_verblevel.addItem("WARN")
            opt_verblevel.addItem("ERROR")
            opt_verblevel.addItem("EMER")
            opt_libdir = QtGui.QCheckBox("Look for app libs:")
            self.opt_libdir_path = QtGui.QLineEdit()
            self.opt_libdir_path.setMaximumWidth(60)
            opt_libdir_browse = QtGui.QPushButton ("...")
            self.opt_conf = QtGui.QCheckBox("Configuration file:")
            self.opt_conf_path = QtGui.QLineEdit()
            self.opt_conf_path.setMaximumWidth(60)
            opt_conf_browse = QtGui.QPushButton ("...")
            opt_conf_browse.setMaximumWidth(30)
            self.opt_info = QtGui.QCheckBox("Info file:")
            self.opt_info_path = QtGui.QLineEdit()
            self.opt_info_path.setMaximumWidth(60)
            opt_info_browse = QtGui.QPushButton ("...")
            opt_info_browse.setMaximumWidth(30)
            opt_daem = QtGui.QCheckBox("Run as daemon")
            opt_grid = QtGui.QGridLayout()
            opt_grid.addWidget(opt_verb,    1, 0)
            opt_grid.addWidget(opt_verblevel,   1, 1)
            opt_grid.addWidget(opt_libdir,  2, 0)
            opt_grid.addWidget(self.opt_conf,    3, 0)
            opt_grid.addWidget(self.opt_conf_path,    3, 1)
            opt_grid.addWidget(opt_conf_browse,    3, 2)
            opt_grid.addWidget(self.opt_info,    4, 0)
            opt_grid.addWidget(self.opt_info_path,    4, 1)
            opt_grid.addWidget(opt_info_browse,    4, 2)
            opt_grid.addWidget(opt_daem,    5, 0)
            options = QtGui.QGroupBox("Other options") 
            options.setLayout(opt_grid)            
            
            self.connect(opt_conf_browse, QtCore.SIGNAL('clicked()'), self.selectConf)
            self.connect(opt_info_browse, QtCore.SIGNAL('clicked()'), self.selectInfo)
            
            return options
        
        def selectConf(self):
            title = "Choose configuration file"
            filename = QtGui.QFileDialog.getOpenFileName(self,title,"")
            f = QtCore.QFile(filename)
            self.opt_conf_path.setText(f.fileName())
            self.confFile = f
            self.opt_conf.setChecked(True)
            
        def selectInfo(self):
            title = "Choose information file"
            filename = QtGui.QFileDialog.getOpenFileName(self,title,"")
            f = QtCore.QFile(filename)
            self.opt_info_path.setText(f.fileName())
            selfinfoFile = f
            self.opt_info.setChecked(True)
        
        def createCommandBox(self):
            hbox = QtGui.QHBoxLayout()
            self.command = QtGui.QLineEdit()
            self.command.setText("./nox_core -v -i ptcp:6633")
            hbox.addWidget(QtGui.QLabel('Or type command:'))
            hbox.addWidget(self.command) 
            command = QtGui.QGroupBox(self)
            command.setLayout(hbox)
            return command
        
        def createButtonsBox(self):
            # Buttons
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            ok.setDefault(True)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.start)
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            
            # cancel/ok hbox
            hbox = QtGui.QHBoxLayout()
            hbox.addStretch(1)
            hbox.addWidget(cancel)
            hbox.addWidget(ok)
            buttons = QtGui.QGroupBox(self) 
            buttons.setLayout(hbox)
            return buttons
            
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

