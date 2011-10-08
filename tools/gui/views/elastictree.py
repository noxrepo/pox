'''
ElasticTree view for drawn topology

@author Albert Wu (awu12345@stanford.edu)
'''

from nox.ripcordapps.dispatch_server.ripcord_pb2 import Vertex, Edge, \
Path, Tunnels, Tunnel, TunnelsRequest, NewTunnelRequest, Topology,\
DisplayTunnel, DisplaySwitch, TopologyRequest, TopologyReply, \
LinkUtilizationRequest, LinkUtilizationReply, PathUtilizationRequest, \
PathUtilizationReply, EventSubscription, PortUtilization, PortUtilizations, \
SwitchQuery, Generic, UtilBound, TrafficMsg

from PyQt4 import QtGui, QtCore
from view import View
from ripcord.et.elastictree import findPower

class ET_View(View):

    powerSliderSignal = QtCore.pyqtSignal()

    def __init__(self, topoWidget):
        View.__init__(self, topoWidget, "Elastic Tree")    

        self.logDisplay = self.topoWidget.parent.logWidget.logDisplay
        utilBtn = QtGui.QPushButton('Change Util Bound')
        infoBtn = QtGui.QPushButton('What is ElasticTree?')

        self.connect(utilBtn, QtCore.SIGNAL('clicked()'),
                    self.changeUtil)
        self.connect(infoBtn, QtCore.SIGNAL('clicked()'), self.showInfo)
#        self.connect(powerBtn, QtCore.SIGNAL('clicked()'),
#                    self.showPowerStats)
#        self.buttons.append(powerBtn)
        self.buttons.append(utilBtn)
        self.buttons.append(infoBtn)
        self.utilBound = 0.01

        self.slider = QtGui.QSlider(QtCore.Qt.Horizontal, self)
        self.slider.setMinimum(0)
        self.slider.setMaximum(100)
        self.buttons.append(self.slider)
        self.sliderValue = 0
        self.stats = {}  # maps tuples (dpid, port) to utilization

        self.powerSliderSignal.connect(self.changeSlider)
        
        self.indicator = QtGui.QLabel()
        self.buttons.append(self.indicator)
        

    def changeSlider(self):
        self.slider.setValue(self.sliderValue)
        msg = str(self.sliderValue) + "%"
        self.indicator.setText("<font color='red'>"+msg+"</font>")

    def node_color(self, node):  # green node when on, gray when off
        #topo = self.topoWidget.topologyView.topology
        #if topo.node_info[node.dpid].power_on:
        #    return QtCore.Qt.green
        #else:
        #    return QtCore.Qt.gray
        return

    def link_color(self, link):
        # reflected by shades of colors based on utilizations
        # assumes 1 GB links

        srcID = link.source.dpid
        srcPort = link.sport
        dstID = link.dest.dpid
        dstPort = link.dport

        if not link.isUp:
            return QtCore.Qt.gray

        if not (srcID, srcPort) in self.stats and \
                not (dstID, dstPort) in self.stats:
            return QtCore.Qt.green

        if not (srcID, srcPort) in self.stats:
            util = self.stats[(dstID, dstPort)]
        elif not (dstID, dstPort) in self.stats:
            util = self.stats[(srcID, srcPort)]
        else: 
            util1 = self.stats[(srcID, srcPort)]
            util2 = self.stats[(dstID, dstPort)]
            util = (util1 + util2) / 2

        if util >= 0.8:
            return QtCore.Qt.red
        if util > 0:
            return QtCore.Qt.red
        return QtCore.Qt.white

    def link_pattern(self, link):
        pattern = QtCore.Qt.SolidLine
        return pattern

    def changeUtil(self):
        self.buttons[0].setChecked(True)

        change_util_popup = ChangeUtilPopup(self)
        change_util_popup.exec_()
        #return

    def showInfo(self):
        self.buttons[1].setChecked(True)

        info_popup = InfoPopup(self)
        info_popup.exec_()

    def showPowerStats(self):
        ''' method that shows stats for a specific ElasticTree subset
        currently not implemented'''
#        self.logDisplay.parent.freezeLog = True
#        topo = self.topoWidget.topologyView.topology
#        numSwitches = len(topo.nodes.keys())
#        numLinks = len(topo.links.keys())
#
#        k = 4
#        # this next portion will have to be updated eventually
#        totSwitches = k * k / 4 + k * k
#        totLinks = 3 * k * k * k / 4
#
#        stats = "Displaying Switch and Edge Power Stats\n"
#        stats += "Switches on: %d\n" % numSwitches
#        stats += "Links on: %d\n" % numLinks
#        stats += "% Original Network Power: %d\n" % \
#            findPower(numSwitches, numLinks, totSwitches, totLinks, k)
#
#        self.logDisplay.setText(stats)
        return

    def updateStats(self, utils):
        ''' updates link stats from dispatch_server message '''
        self.stats = {}
        for util in utils:
            self.stats[(util.dpid, util.port)] = \
                            (util.gbps_transmitted + util.gbps_received) / 2

class InfoPopup(QtGui.QDialog):
    ''' popup showing basic background for Elastic Tree '''

    def __init__(self, parent=None):
        ''' Sets up graphics for popup '''
        self.parent = parent
        QtGui.QWidget.__init__(self)
        self.setWindowTitle("ElasticTree Basic Info")
        self.resize(500, 150)
        self.combo = QtGui.QGroupBox(self) 

        ok = QtGui.QPushButton("Ok")
        self.connect(ok, QtCore.SIGNAL('clicked()'), self.ok)
        self.hbox = QtGui.QHBoxLayout()
        self.hbox.addStretch(1)
        self.hbox.addWidget(ok)

        self.vbox = QtGui.QVBoxLayout()
        grid = QtGui.QGridLayout()
        msg1 = "ElasticTree saves energy by turning off unneeded switches / links."
        msg2 = "This view visualizes the subset of switches. Also, the user can "
        msg3 = "adjust the utilization bound, the amount of bandwidth reserved per link."
        l = QtGui.QLabel(msg1)
        m = QtGui.QLabel(msg2)
        n = QtGui.QLabel(msg3)
        grid.addWidget(l, 1, 1)
        grid.addWidget(m, 2, 1)
        grid.addWidget(n, 3, 1)

        self.combo.setLayout(self.vbox)
        self.vbox.addLayout(grid)
        self.vbox.addLayout(self.hbox)
        self.vbox.addStretch(1)

    def ok(self):
        self.accept()

class ChangeUtilPopup(QtGui.QDialog):
    ''' allows user to adjust slider to change utilization bound for ET'''

    def __init__(self, parent=None):
        ''' Sets up graphics '''
        self.parent = parent
        QtGui.QWidget.__init__(self)
        self.setWindowTitle("Change Utilization Bound, Mbps")
        self.resize(350, 100)
        self.combo = QtGui.QGroupBox(self)

#        self.slider = QtGui.QSlider(QtCore.Qt.Horizontal, self)
#        self.slider.setFocusPolicy(QtCore.Qt.NoFocus)
#        self.slider.setGeometry(30, 40, 100, 30)
#        self.slider.setMinimum(0)
#        self.slider.setMaximum(1000)
#        self.slider.setValue(self.parent.utilBound * 1000)
        self.utilEdit = QtGui.QLineEdit()
        self.utilEdit.setText('')

        ok = QtGui.QPushButton("Ok")
        cancel = QtGui.QPushButton("Cancel")
        self.connect(ok, QtCore.SIGNAL('clicked()'), self.ok)
        self.connect(cancel, QtCore.SIGNAL('clicked()'), self.cancel)

        self.hbox = QtGui.QHBoxLayout()
        self.hbox.addStretch(1)
        self.hbox.addWidget(cancel)
        self.hbox.addWidget(ok)

        self.vbox = QtGui.QVBoxLayout()
        grid = QtGui.QGridLayout()
        grid.addWidget(self.utilEdit, 1, 1)

        self.combo.setLayout(self.vbox)
        self.vbox.addLayout(grid)
        self.vbox.addLayout(self.hbox)
        self.vbox.addStretch(1)

    def changeValue(self):
        return

    def ok(self):
        # send util bound message

        value = float(self.utilEdit.text())
        display = 'Util bound set to: ' + str(value) + " Gbps"
        self.parent.topoWidget.parent.setStatusTip(display)
        self.parent.utilBound = value
        msg = UtilBound()
        msg.util_bound = self.parent.utilBound
        self.parent.topoWidget.topologyView.topologyInterface.send(msg)
        self.accept()

    def cancel(self):
        self.parent.buttons[0].setChecked(False)
        self.parent.topoWidget.parent.setStatusTip('Util bound not changed')
        self.reject()
