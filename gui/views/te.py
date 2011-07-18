'''
TE view for drawn topology

Stores information specific to the TE view, eg tunnel table with
characteristics, colors, TunnelTablePopup window, etc 

@author Kyriakos Zarifis
'''
from PyQt4 import QtGui, QtCore

from view import View
'''
from nox.ripcordapps.dispatch_server.ripcord_pb2 import Vertex, Edge, Path, \
Tunnel, Tunnels, TunnelsRequest, Topology, DisplayTunnel, NewTunnelRequest, \
TEDRequest, TEDReply, RemoveTunnelRequest
'''
class TE_View(View):   
    
    def __init__(self, topoWidget):
        View.__init__(self, topoWidget, "Traffic Engineering")    
        
        # TE view buttons
        TTBtn = QtGui.QPushButton('&Tunnel Table')
        TEDBtn = QtGui.QPushButton('Traffic Engineering &Database')
        NewTunBtn = QtGui.QPushButton('New Tunnel...')
        DelTunBtn = QtGui.QPushButton('Delete Tunnel...')
        
        self.connect(TTBtn, QtCore.SIGNAL('clicked()'), self.handle_TTBtnClick)

        self.connect(TEDBtn, QtCore.SIGNAL('clicked()'), self.request_TED)

        self.connect(NewTunBtn, QtCore.SIGNAL('clicked()'), self.new_tunnel)
        self.connect(DelTunBtn, QtCore.SIGNAL('clicked()'), self.remove_tunnel)
                    
        self.buttons.append(TTBtn)
        self.buttons.append(TEDBtn)   
        self.buttons.append(NewTunBtn)  
        self.buttons.append(DelTunBtn)       
        
        self.buttons[0].setCheckable(True)
        #self.buttons[2].setCheckable(True)
        #self.buttons[3].setCheckable(True)
        
        # tunnel descriptions, taken from te backend
        self.tunnels = []
        
        # backup tables, string taken from te backend
        self.backup_tables = ""
        
        # unprotected hops per tunnel, string taken from te backend
        self.uprotected_hops = ""
        
        # unaccommodated tunnels, string taken from te backend
        self.unaccomodated_tunnels = ""
        
        # latest TED, string taken from te backend
        self.ted = ""
                
        # tunnel colors (tid:color)
        self.tunnel_colors = {'default':QtCore.Qt.blue,\
            1:QtGui.QColor(QtCore.Qt.red),\
            2:QtGui.QColor(QtCore.Qt.yellow)}
        
        # draw tunnel? (tid:true/false)
        self.tunnel_displays = {1:True, 2:True} #{0:False, 1:False} 
        
        # connect signals to slots
        self.topologyInterface.tunnels_reply_received_signal.connect \
                (self.show_tunnel_table)
        self.topologyInterface.ted_reply_received_signal.connect \
                (self.show_TED)
        self.topologyInterface.link_status_change_signal.connect \
                (self.update_tunnel_table)
    
        self.popupTT = False
        
    def handle_TTBtnClick(self):
        self.buttons[0].setChecked(True)
        self.popupTT = True
        self.update_tunnel_table()
        
    def update_tunnel_table(self):
        '''
        Send tunnelsrequest to NOX to get updated Tunnel Table
        ''' 
        msg = TunnelsRequest()
        self.topologyInterface.send(msg)
        
    def show_tunnel_table(self):
        '''
        Called by communication when tunnels reply is received.
        Displays Tunnel Table
        '''
        self.show_TT()
        
        # popup TT?
        if self.popupTT:
            self.popupTT = False
            #popup TT and color path on hover over tunnel names
            tunnel_table = TunnelTablePopup(self)
            tunnel_table.exec_()
                          
    def request_TED(self):
        """
        Send TEDRequest to TE backend
        """
        msg = TEDRequest()
        self.topologyInterface.send(msg)
        
    def show_TED(self):
        """
        Display received TED on left panel
        """
        self.logDisplay.parent.freezeLog = True
        #self.logDisplay.setText("Displaying TED:")
        self.logDisplay.setText(self.ted)
        
    def new_tunnel(self):
        self.buttons[2].setChecked(True)
        self.popupTT = True
        
        new_tunnel_popup = NewTunnelPopup(self)
        new_tunnel_popup.exec_()
        
    def remove_tunnel(self):
        self.buttons[3].setChecked(True)
        self.popupTT = True
        
        remove_tunnel_popup = RemoveTunnelPopup(self)
        remove_tunnel_popup.exec_()
        
    def link_pattern(self, link):
        pattern = QtCore.Qt.SolidLine
        return pattern
        
    def link_color(self, link):
        '''
        if link is used by a tunnel, paints according to tunnel color
        If used by >1 tunnels, paints based on one of them
        If no tunnel or no color set, paints default
        '''
        color = self.tunnel_colors['default']
        #colors = []
        #for each deployed tunnel:
        for tunnel in self.tunnels:
            # if custom color has been defined:
            if tunnel.tid in self.tunnel_colors:
                # if tunnel is set to be displayed:
                if tunnel.tid in self.tunnel_displays:
                    if self.tunnel_displays[tunnel.tid] == True:
                        path = []
                        if not tunnel.temp_path.links:
                            # primary active
                            path.append(tunnel.path.links[0].dpid1)
                            for tunnel_link in tunnel.path.links:            
                                path.append(tunnel_link.dpid2)
                        else:
                            # backup active
                            path.append(tunnel.temp_path.links[0].dpid1)
                            for tunnel_link in tunnel.temp_path.links:            
                                path.append(tunnel_link.dpid2)
                                
                        if long(link.source.id) in path:
                            i = path.index(long(link.source.id))
                            if (i>0 and int(path[i-1]) == int(link.dest.id)) \
                                or (i<len(path) and int(path[i+1]) == int(link.dest.id)):
                            #if (i>0 and int(path[i-1]) == int(link.dest.id)) \
                            #    or (i<len(path) and int(path[i]) == int(link.dest.id)):
                                color = self.tunnel_colors[tunnel.tid]
                                #colors.append(color)
        '''                
        # mix colors
        color = QtCore.Qt.white
        for c in colors:
            color += c   
        '''             
                        
        return color
    
    def node_color(self, node):
        # return
        return QtGui.QColor(QtCore.Qt.blue)
        
    def show_TT(self):
        self.logDisplay.parent.freezeLog = True
        self.logDisplay.setText('') 
        self.logDisplay.textCursor().insertText("| Tunnel Table |\n")
        self.logDisplay.textCursor().insertText("-------------------\n") 
        self.logDisplay.textCursor().insertText("  TunID\tTEclass\tCIR\tPath\n")
        for t in self.tunnels:
            if t.tid in self.tunnel_colors:
                self.logDisplay.setTextColor(self.tunnel_colors[t.tid])
            else:
                self.logDisplay.setTextColor(QtCore.Qt.green)  
            self.logDisplay.textCursor().insertText('  ' + str(t.tid) + '\t')
            self.logDisplay.textCursor().insertText(str(t.te_class) + '\t')
            self.logDisplay.textCursor().insertText(str(t.cir) + '\t')
            if not t.temp_path.links:
                path = t.path
            else:
                path = t.temp_path
            self.logDisplay.textCursor().insertText(\
                    str(hex(path.links[0].dpid1))[2:len(\
                    str(hex(path.links[0].dpid1)))-1] + ' ')
            for edge in path.links:
                self.logDisplay.textCursor().insertText(\
                    str(hex(edge.dpid2))[2:len(\
                    str(hex(edge.dpid2)))-1] + ' ')
            self.logDisplay.textCursor().insertText('\n')
        self.logDisplay.setTextColor(QtCore.Qt.green)  
        self.logDisplay.textCursor().insertText('\n\n')
        self.logDisplay.textCursor().insertText(self.backup_tables)
        self.logDisplay.textCursor().insertText('\n\n')
        self.logDisplay.textCursor().insertText(self.unprotected_hops)
        self.logDisplay.textCursor().insertText('\n\n')
        self.logDisplay.textCursor().insertText(self.unaccommodated_tunnels)

class TunnelTablePopup(QtGui.QDialog):
        '''
        Tunnel Table popup
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.setWindowTitle("TE Tunnel Table")
            self.resize(260, 250)
            self.combo = QtGui.QGroupBox(self) 
            
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.ok)
            self.hbox = QtGui.QHBoxLayout()
            self.hbox.addStretch(1)
            self.hbox.addWidget(cancel)
            self.hbox.addWidget(ok)

            self.vbox = QtGui.QVBoxLayout()  
            grid = QtGui.QGridLayout()
            self.colorBtns = []
            self.colors = []
            self.checkboxes = {}
            l = QtGui.QLabel('     Show:')
            grid.addWidget(l, 0, 1)
            for i in range(0,len(self.parent.tunnels)):
                tid = int(self.parent.tunnels[i].tid)
                checkbox = QtGui.QCheckBox("Tunnel " + str(tid))
                # set existing checked/unchecked state, if any
                if tid in self.parent.tunnel_displays:
                    checkbox.setChecked(self.parent.tunnel_displays[tid])
                else:
                    checkbox.setChecked
                self.checkboxes[tid] = checkbox
                
                b = QtGui.QPushButton("Tunnel " + str(self.parent.tunnels[i].tid) + ' Color...')
                # use existing color, if any
                print "exists?"
                if self.parent.tunnels[i].tid in self.parent.tunnel_colors:
                    print "YES"
                    b.setStyleSheet("QWidget { background-color: %s }" % self.parent.tunnel_colors[self.parent.tunnels[i].tid].name())
                self.colorBtns.append(b)
                self.connect(b, QtCore.SIGNAL('clicked()'), self.choose_color)
                grid.addWidget(checkbox, i+1, 1)
                grid.addWidget(b, i+1, 2)
                
            reset = QtGui.QPushButton ("Reset Colors")
            self.connect(reset, QtCore.SIGNAL('clicked()'), self.reset_colors)
            grid.addWidget(reset, len(self.parent.tunnels)+1, 2)
            grid.addWidget(QtGui.QLabel(), len(self.parent.tunnels)+2, 2)
            
            self.combo.setLayout(self.vbox)
            self.vbox.addLayout(grid)
            self.vbox.addLayout(self.hbox)
            self.vbox.addStretch(1)
            
            # Set Modal so than user can still use topology view
            self.setModal(False)
            self.hide()
            self.show()
            
            #self.adjustSize()            
            
        def reset_colors(self):
            self.parent.tunnel_colors = {'default':QtCore.Qt.blue}
            
        def choose_color(self):
            color = QtGui.QColorDialog().getColor()
            b = self.sender()
            tid = int(str(b.text()).split()[1])
            b.setStyleSheet("QWidget { background-color: %s }" % color.name())
            self.parent.tunnel_colors[tid] = color
            self.parent.topoWidget.topologyView.updateAll()
            self.parent.show_TT()
                
        def ok(self):
            for tid in self.checkboxes.keys():
                if self.checkboxes[tid].isChecked():
                    self.parent.tunnel_displays[tid] = True
                else :
                    self.parent.tunnel_displays[tid] = False
            self.parent.topoWidget.topologyView.updateAll()
            self.parent.buttons[0].setChecked(False)
            self.accept()        
            
        def cancel(self):
            self.parent.buttons[0].setChecked(False)
            self.reject()
            
class NewTunnelPopup(QtGui.QDialog):
        '''
        New Tunnel popup
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.setWindowTitle("Deploy New Tunnel")
            self.resize(330, 350)
            self.combo = QtGui.QGroupBox(self) 
            
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Add Tunnel")
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.ok)
            self.hbox = QtGui.QHBoxLayout()
            self.hbox.addStretch(1)
            self.hbox.addWidget(cancel)
            self.hbox.addWidget(ok)
            
            self.vbox = QtGui.QVBoxLayout()  
            grid = QtGui.QGridLayout()
            grid.addWidget(QtGui.QLabel("New Tunnel Attributes:"), 1, 1)
            
            grid.addWidget(QtGui.QLabel("Tunnel ID:"), 4, 1)
            self.tid = QtGui.QLineEdit("10")
            grid.addWidget(self.tid, 4, 2,)
            
            grid.addWidget(QtGui.QLabel("TE Class"), 5, 1)
            self.te_class = QtGui.QLineEdit("0")
            grid.addWidget(self.te_class, 5, 2,)
            
            grid.addWidget(QtGui.QLabel("Ingress dpID:"), 6, 1)
            self.idpid = QtGui.QLineEdit("101")
            grid.addWidget(self.idpid, 6, 2,)
            
            grid.addWidget(QtGui.QLabel("Ingress port:"), 7, 1)
            self.iport = QtGui.QLineEdit("2")
            grid.addWidget(self.iport, 7, 2,)
            
            grid.addWidget(QtGui.QLabel("Engress dpID:"), 8, 1)
            self.edpid = QtGui.QLineEdit("30001")
            grid.addWidget(self.edpid, 8, 2,)
            
            grid.addWidget(QtGui.QLabel("Engress port:"), 9, 1)
            self.eport = QtGui.QLineEdit("4")
            grid.addWidget(self.eport, 9, 2,)
            
            grid.addWidget(QtGui.QLabel("Reserved BW (CIR):"), 10, 1)
            self.cir = QtGui.QLineEdit("800")
            grid.addWidget(self.cir, 10, 2,)
            
            class_map = QtGui.QPushButton("Class Map...")
            self.connect(class_map, QtCore.SIGNAL('clicked()'), \
                                        self.set_class_map)
            grid.addWidget(class_map, 11, 1,)
            
            self.combo.setLayout(self.vbox)
            self.vbox.addLayout(grid)
            self.vbox.addLayout(self.hbox)
            self.vbox.addStretch(1)
            
            # Set Modal so than user can still use topology view
            self.setModal(False)
            self.hide()
            self.show()
            
        def set_class_map(self):
            cm_popup = ClassMapPopup(self)
            cm_popup.exec_()
            
        def ok(self):
            #send protobuf to attempt to setup new tunnel
            msg = NewTunnelRequest()
            msg.new_tunnel.tid = int(self.tid.text())
            msg.new_tunnel.idpid = int(self.idpid.text())
            msg.new_tunnel.iport = int(self.iport.text())
            msg.new_tunnel.edpid = int(self.edpid.text())
            msg.new_tunnel.eport = int(self.eport.text())
            #msg.new_tunnel.class_map =
            msg.new_tunnel.cir = int(self.cir.text())
            msg.new_tunnel.te_class = int(self.te_class.text())
            msg.new_tunnel.flags = 0
            self.parent.topologyInterface.send(msg)
            self.parent.update_tunnel_table()
            self.parent.buttons[2].setChecked(False)
            self.accept()
            
        def cancel(self):
            self.parent.buttons[2].setChecked(False)
            self.reject()            
            
class ClassMapPopup(QtGui.QDialog):
        '''
        Class map definition popup
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.setWindowTitle("New Class Map Definition")
            self.resize(340, 360)
            self.combo = QtGui.QGroupBox(self) 
            
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Ok")
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.ok)
            self.hbox = QtGui.QHBoxLayout()
            self.hbox.addStretch(1)
            self.hbox.addWidget(cancel)
            self.hbox.addWidget(ok)
            
            self.vbox = QtGui.QVBoxLayout()  
            grid = QtGui.QGridLayout()
            grid.addWidget(QtGui.QLabel("Add flow descriptions"), 1, 1)
            grid.addWidget(QtGui.QLabel("Separate values with ',':"), 2, 1)
            grid.addWidget(QtGui.QLabel("Empty fields=wildcards"), 3, 1)
            
            grid.addWidget(QtGui.QLabel("dl_src:"), 4, 1)
            dl_src = QtGui.QLineEdit("00:00:00:00:00:10")
            grid.addWidget(dl_src, 4, 2,)
            
            grid.addWidget(QtGui.QLabel("dl_dst:"), 5, 1)
            dl_dst = QtGui.QLineEdit()
            grid.addWidget(dl_dst, 5, 2,)
            
            grid.addWidget(QtGui.QLabel("dl_vlan:"), 6, 1)
            dl_vlan = QtGui.QLineEdit()
            grid.addWidget(dl_vlan, 6, 2,)
            
            grid.addWidget(QtGui.QLabel("dl_type:"), 7, 1)
            dl_type = QtGui.QLineEdit()
            grid.addWidget(dl_type, 7, 2,)
            
            grid.addWidget(QtGui.QLabel("nw_proto:"), 8, 1)
            nw_proto = QtGui.QLineEdit()
            grid.addWidget(nw_proto, 8, 2,)
            
            grid.addWidget(QtGui.QLabel("nw_src:"), 9, 1)
            nw_src = QtGui.QLineEdit("10.0.0.10")
            grid.addWidget(nw_src, 9, 2,)
            
            grid.addWidget(QtGui.QLabel("nw_dst"), 10, 1)
            nw_dst = QtGui.QLineEdit()
            grid.addWidget(nw_dst, 10, 2,)
            
            self.combo.setLayout(self.vbox)
            self.vbox.addLayout(grid)
            self.vbox.addLayout(self.hbox)
            self.vbox.addStretch(1)
            
            # Set Modal so than user can still use topology view
            self.setModal(False)
            self.hide()
            self.show()
            
        def ok(self):
            self.accept()
            
        def cancel(self):
            self.reject()                      

class RemoveTunnelPopup(QtGui.QDialog):
        '''
        New Tunnel popup
        '''
        def __init__(self, parent=None):
            self.parent = parent
            QtGui.QWidget.__init__(self)
            self.setWindowTitle("Remove Tunnel")
            self.resize(290, 130)
            self.combo = QtGui.QGroupBox(self) 
            
            cancel = QtGui.QPushButton ("Cancel")
            ok = QtGui.QPushButton ("Remove")
            self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)
            self.connect(ok, QtCore.SIGNAL('clicked()'), self.ok)
            self.hbox = QtGui.QHBoxLayout()
            self.hbox.addStretch(1)
            self.hbox.addWidget(cancel)
            self.hbox.addWidget(ok)
            
            self.vbox = QtGui.QVBoxLayout()  
            grid = QtGui.QGridLayout()
            grid.addWidget(QtGui.QLabel("Remove tunnel:"), 1, 1)
            
            grid.addWidget(QtGui.QLabel("Tunnel ID:"), 4, 1)
            self.tid = QtGui.QLineEdit("10")
            grid.addWidget(self.tid, 4, 2,)
            
            self.combo.setLayout(self.vbox)
            self.vbox.addLayout(grid)
            self.vbox.addLayout(self.hbox)
            self.vbox.addStretch(1)
            
            # Set Modal so than user can still use topology view
            self.setModal(False)
            self.hide()
            self.show()
            
        def ok(self):
            #send protobuf to attempt to remove tunnel
            msg = RemoveTunnelRequest()
            msg.tid = int(self.tid.text())
            #self.popupTT = False
            self.parent.topologyInterface.send(msg)
            self.parent.update_tunnel_table()
            self.parent.buttons[3].setChecked(False)
            self.accept()
            
        def cancel(self):
            self.parent.buttons[3].setChecked(False)
            self.reject()          

