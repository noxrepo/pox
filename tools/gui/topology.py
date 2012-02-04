'''
The topology panel of the GUI 

@author Kyriakos Zarifis (kyr.zarifis@gmail.com)
'''

from PyQt4 import QtGui, QtCore
import math
from random import randint
from communication import Communication
from views.default import Default_View
import json
import jsonrpc

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Add custom topology views here  (add them in topoWidget.__init__() below)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from views.monitoring import Monitoring_View
from views.spanningtree import STP_View
from views.samplerouting import Sample_Routing_View
from views.flowtracer import Flow_Tracer_View


class Node(QtGui.QGraphicsItem):
    '''
    Interactive Node object
    '''
    Type = QtGui.QGraphicsItem.UserType + 1
    
    def __init__(self, graphWidget, _id, _type, _layer=1):
        QtGui.QGraphicsItem.__init__(self)

        self.graph = graphWidget
        self.topoWidget = self.graph.parent
        self.infoDisplay = self.topoWidget.parent.infoWidget
        #self._id = _id
        self.id = _id
        self.type = _type
        self.linkList = []
        self.neighbors = {}  # "str(port) : str(neigh.ID)"
        #self.layer = _layer
        self.newPos = QtCore.QPointF()
        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)
        self.setFlag(QtGui.QGraphicsItem.ItemSendsGeometryChanges)
        self.setZValue(1)
        self.setAcceptHoverEvents(True)
        
        # Node attributes
        self.isUp = True        # up/down state   
        self.showID = True      # Draw NodeId
        self.showNode = True    # Draw Node
        self.isSilent = False   # is switch unresponsive? - draw X
        
    def query_port_stats(self):
        self.infoDisplay.grab()
        self.infoDisplay.append('Querying port stats for switch: 0x%s'%self.id)
        self.topoWidget.monitoring_view.get_port_stats( self.id )

    def query_table_stats(self):
        self.infoDisplay.grab()
        self.infoDisplay.append('Querying table stats for switch: 0x%s'%self.id)
        self.topoWidget.monitoring_view.get_table_stats( self.id )

    def query_agg_stats(self):
        self.infoDisplay.grab()
        self.infoDisplay.append('Querying agg stats for switch: 0x%s'%self.id)
        self.topoWidget.monitoring_view.get_aggregate_stats( self.id )

    def query_latest_snapshot(self):
        self.infoDisplay.grab()
        self.infoDisplay.append('Querying latest snapshot for switch: 0x%s'%self.id )
        self.topoWidget.monitoring_view.get_latest_snapshot( self.id )

    def query_flow_stats(self):
        self.infoDisplay.grab()
        self.infoDisplay.append('Querying flow stats for switch: %s'%self.id)
        self.topoWidget.monitoring_view.get_flow_stats( self.id )
        self.infoDisplay.grab()

    def query_queue_stats(self):
        self.infoDisplay.grab()
        self.infoDisplay.append('Querying queue stats for switch: 0x%s'%self.id)
        self.topoWidget.monitoring_view.get_queue_stats( self.id )

    def type(self):
        return Node.Type

    def addLink(self, link):
        self.linkList.append(link)
        
        # create localPort->neighborID mapping
        if link.source.id == self.id:
            neibID = link.dest.id
        else:
            neibID = link.source.id
        
        self.neighbors[link.dport] = neibID
        
        link.adjust()

    def links(self):
        return self.linkList

        self.setPos(self.newPos)
        return True

    def boundingRect(self):
        adjust = 2.0
        return QtCore.QRectF(-10-adjust, -10-adjust, 23+adjust, 23+adjust)

    def shape(self):
        path = QtGui.QPainterPath()
        path.addEllipse(-10, -10, 20, 20)
        return path

    def paint(self, painter, option, widget):    
        """ too many IF checks, optimize """
        if self.showNode:
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(QtGui.QColor(QtCore.Qt.darkGray).light(25))
            if self.type == "host":
                painter.drawRect(-9, -9, 15, 15)
            else:
                painter.drawEllipse(-9, -10, 20, 20)

            gradient = QtGui.QRadialGradient(-3, -3, 10)
            
            # Choose pattern/color based on who controls drawing
            activeView = self.graph.parent.views[self.graph.drawAccess]
            #pattern = activeView.node_pattern(self) not implemented
            color = activeView.node_color(self)
            
            if not color:
                color = QtGui.QColor(QtCore.Qt.green)
            """
            if self.type == "host":
                color = QtGui.QColor(QtCore.Qt.yellow)
            else:
                if not color:
                    color = QtGui.QColor(QtCore.Qt.green)
            """
            if option.state & QtGui.QStyle.State_Sunken:
                gradient.setCenter(3, 3)
                gradient.setFocalPoint(3, 3)
                if self.isUp:
                    gradient.setColorAt(1, color.light(100))
                    gradient.setColorAt(0, color.light(30))
                else:
                    gradient.setColorAt(1, QtGui.QColor(QtCore.Qt.gray).light(80))
                    gradient.setColorAt(0, QtGui.QColor(QtCore.Qt.gray).light(20))
            else:
                if self.isUp:
                    gradient.setColorAt(0, color.light(85))
                    gradient.setColorAt(1, color.light(25))
                else:
                    gradient.setColorAt(0, QtGui.QColor(QtCore.Qt.gray).light(60))
                    gradient.setColorAt(1, QtGui.QColor(QtCore.Qt.gray).light(10))

            painter.setBrush(QtGui.QBrush(gradient))
            painter.setPen(QtGui.QPen(QtCore.Qt.black, 0))
            if self.type == "host":
                painter.drawRect(-10, -10, 15, 15)
            else:
                painter.drawEllipse(-10, -10, 20, 20)
        
        if self.showID:
            # Text.
            textRect = self.boundingRect()
            message = str(self.id)

            font = painter.font()
            font.setBold(True)
            font.setPointSizeF(self.topoWidget.parent.settings.node_id_size)
            painter.setFont(font)
            painter.setPen(QtCore.Qt.gray)
            painter.drawText(textRect.translated(0.1, 0.1), message)
            painter.setPen(QtGui.QColor(QtCore.Qt.gray).light(130))
            painter.drawText(textRect.translated(0, 0), message)
        
        if self.isSilent: # remove
            # Big red X.
            textRect = self.boundingRect()
            message = "X"

            font = painter.font()
            font.setBold(True)
            font.setPointSize(16)
            painter.setFont(font)
            painter.setPen(QtGui.QColor(QtCore.Qt.red).light(30))
            painter.drawText(textRect.translated(4, 2), message)
            painter.setPen(QtGui.QColor(QtCore.Qt.red).light(90))
            painter.drawText(textRect.translated(3, 1), message)

    def itemChange(self, change, value):
        if change == QtGui.QGraphicsItem.ItemPositionChange:
            for link in self.linkList:
                link.adjust()
            self.graph.itemMoved()

        return QtGui.QGraphicsItem.itemChange(self, change, value)

    def mousePressEvent(self, event):
        self.stillHover = False
        self.update()
        QtGui.QGraphicsItem.mousePressEvent(self, event)

    def mouseDoubleClickEvent(self, event):
        self.query_flow_stats()
        QtGui.QGraphicsItem.mouseDoubleClickEvent(self, event)
        
    def mouseReleaseEvent(self, event):
        if event.button() == QtCore.Qt.RightButton:
            popup = QtGui.QMenu()
            # Switch Details Menu
            if self.type == "switch":
                popup.addAction("Show &Flow Table", self.query_flow_stats)
                popup.addSeparator()
                popup.addMenu(self.nodeDetails)
                popup.addSeparator()
                # Build new stats menu (move to init and build once?)
                statsMenu = QtGui.QMenu( '&Get Switch Stats' )
                statsMenu.addAction('Port Stats', self.query_port_stats)
                statsMenu.addAction('Table Stats', self.query_table_stats)
                statsMenu.addAction('Aggregate Stats', self.query_agg_stats)
                statsMenu.addAction('Flow Stats', self.query_flow_stats)
                statsMenu.addAction('Queue Stats', self.query_queue_stats)
                statsMenu.addAction('Latest snapshot', self.query_latest_snapshot)
                popup.addMenu(statsMenu)
                popup.addSeparator()
                #popup.addAction("Bring switch &up", self.alertSwitchUp)
                #popup.addAction("Bring switch &down", self.alertSwitchDown)
                #popup.addAction("Select/deselect switch", self.selectSwitch)
                popup.addSeparator()
                activeView = self.graph.parent.views[self.graph.drawAccess]
                popup.addMenu(activeView.nodeMenu)
                mininetMenu = QtGui.QMenu( '&Mininet' )
                mininetMenu.addAction('Link from here', self.linkFrom)
                mininetMenu.addAction('Link to here', self.linkTo)
                popup.addMenu(mininetMenu)
            # Host Details Menu
            if self.type == "host":
                popup.addMenu(self.nodeDetails)
                
            popup.exec_(event.lastScreenPos())
        self.update()
        QtGui.QGraphicsItem.mouseReleaseEvent(self, event)
        
    def linkFrom(self):
        self.graph.mininetLinkFrom(self.id)
        
    def linkTo(self):
        self.graph.mininetLinkTo(self.id)
        
    def alertSwitchDown(self):
        ''' when user turns switch off from GUI, sends message
        to dispatch server '''
        mainWindow = self.topoWidget.parent
        sendMsg = SwitchAdminStatus()
        sendMsg.dpid = self.dpid
        sendMsg.admin_up = False
        self.topoWidget.topologyView.topologyInterface.send(sendMsg)
        mainWindow.setStatusTip("Brought down switch %0x" % self.dpid)

    def alertSwitchUp(self):
        ''' when user turns switch on from GUI, sends message
        to dispatch server '''
        mainWindow = self.topoWidget.parent
        sendMsg = SwitchAdminStatus()
        sendMsg.dpid = self.dpid
        sendMsg.admin_up = True
        self.topoWidget.topologyView.topologyInterface.send(sendMsg)
        mainWindow.setStatusTip("Brought down switch %0x" % self.dpid)

    def selectSwitch(self):
        ''' interactive selection of switches by user '''
        if self.layer != HOST_LAYER:
            return
        mainWindow = self.topoWidget.parent
        if self.topoWidget.selectedNode == None:
            self.topoWidget.selectedNode = self
            mainWindow.setStatusTip('Node %d selected' % self.dpid)
        elif self.topoWidget.selectedNode.dpid == self.dpid:
            self.topoWidget.selectedNode = None
            mainWindow.setStatusTip('Node %d deselected' % self.dpid)
        else:
            msg = 'Sending traffic from node ' + self.topoWidget.selectedNode.id \
                    + ' to ' + self.id
            mainWindow.setStatusTip(msg)
            sendMsg = TrafficMsg()
            sendMsg.src = self.topoWidget.selectedNode.dpid
            sendMsg.dst = self.dpid
            self.topoWidget.topologyView.topologyInterface.send(sendMsg)
            self.topoWidget.selectedNode = None
        
    def toggleStatus(self):
        if self.isUp:
            self.alertSwitchDown()
        else:
            self.alertSwitchUp()    
        
    def bringSwitchDown(self):
        self.isUp = False
        for l in self.linkList:
            l.isUp = False
            l.update()
        self.update()

    def bringSwitchUp(self, allLinks = True):
        self.isUp = True
        if allLinks:
            for l in self.linkList:
                l.isUp = True
                l.update()
        self.update()
       
    def hoverEnterEvent(self, event):
        self.stillHover = True
        
        # refresh nodeDetails menu
        self.nodeDetails = QtGui.QMenu('&Switch Details')
        if self.type == "switch":
            self.nodeDetails.addAction('Datapath ID: 0x%s' % self.id)
            self.nodeDetails.addAction('Table Size: '+ '')
        elif self.type == "host":
            self.nodeDetails.addAction('Host ID: 0x%s' % self.id)
        self.nodeDetails.addAction('Links: ' + str(len(self.linkList)))
        
        self.hoverPos = event.lastScreenPos() + QtCore.QPoint(10,10)
        self.hoverTimer = QtCore.QTimer()
        self.hoverTimer.singleShot(500, self.popupNodeDetailsMenu)
    
    @QtCore.pyqtSlot()    
    def popupNodeDetailsMenu(self):
        if self.stillHover:
            #pos = self.mapToItem(self,self.pos() + QtCore.QPointF(10,10))
            self.nodeDetails.exec_(self.hoverPos)
        
    def hoverLeaveEvent(self, event):
        self.stillHover = False
        # hide popup...(currently user has to click somewhere)
        
class Link(QtGui.QGraphicsItem):
    '''
    Interactive Link 
    '''
    
    Type = QtGui.QGraphicsItem.UserType + 2

    def __init__(self, graphWidget, sourceNode, destNode, sport, dport, uid):
        QtGui.QGraphicsItem.__init__(self)
        
        self.graph = graphWidget
        self.topoWidget = self.graph.parent
        self.uid = uid
        self.arrowSize = 10.0
        self.sourcePoint = QtCore.QPointF()
        self.destPoint = QtCore.QPointF()
        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)
        self.setAcceptedMouseButtons(QtCore.Qt.RightButton)
        self.setAcceptHoverEvents(False)
        self.source = sourceNode
        self.dest = destNode
        self.sport = sport
        self.dport = dport
        self.drawArrow = False
        self.source.addLink(self)
        self.dest.addLink(self)
        self.adjust()
        
        # Link attributes
        self.isUp = True        # up/down state  
        self.showLink = True    # Draw link
        self.showID = False     # Draw link ID   
        self.showPorts = True   # Draw connecting ports  
        
        # Link details menu
        self.linkDetails = QtGui.QMenu('&Link Details')
        self.linkDetails.addAction('Link ID: %s'%self.uid)
        self.linkDetails.addAction("Ends: %i:%i - %i:%i"%(self.source.id,
                                   self.sport, self.dest.id, self.dport))
        self.linkDetails.addAction('Capacity: ')

    def type(self):
        return Link.Type

    def sourceNode(self):
        return self.source

    def setSourceNode(self, node):
        self.source = node
        self.adjust()

    def destNode(self):
        return self.dest

    def setDestNode(self, node):
        self.dest = node
        self.adjust()

    def adjust(self):
        if not self.source or not self.dest:
            return

        line = QtCore.QLineF(self.mapFromItem(self.source, 0, 0),\
                                self.mapFromItem(self.dest, 0, 0))
        length = line.length()
        
        if length == 0.0:
            return
        
        linkOffset = QtCore.QPointF((line.dx() * 10) / length, (line.dy() * 10) / length)

        self.prepareGeometryChange()
        self.sourcePoint = line.p1() + linkOffset
        self.destPoint = line.p2() - linkOffset

    def boundingRect(self):
        if not self.source or not self.dest:
            return QtCore.QRectF()
        '''
        return QtCore.QRectF(self.sourcePoint,
                             QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                                           self.destPoint.y() - self.sourcePoint.y())).normalized()
        
        '''
        penWidth = 1
        extra = (penWidth + self.arrowSize) / 2.0

        return QtCore.QRectF(self.sourcePoint,
                             QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                                           self.destPoint.y() - self.sourcePoint.y())).normalized().adjusted(-extra, -extra, extra, extra)
        
        
    def paint(self, painter, option, widget):
        if not self.source or not self.dest:
            return

        # Draw the line itself.
        if self.showLink:
            line = QtCore.QLineF(self.sourcePoint, self.destPoint)
            if line.length() == 0.0:
                return
            
            # Select pen for line (color for util, pattern for state)
            if self.isUp:
                # Choose pattern/color based on who controls drawing
                activeView = self.graph.parent.views[self.graph.drawAccess]
                pattern = activeView.link_pattern(self)
                color = activeView.link_color(self)
                # Highlight when clicked/held
                if option.state & QtGui.QStyle.State_Sunken:
                    color = QtGui.QColor(color).light(256)
                else:
                    color = QtGui.QColor(color).light(90)
            else:
                color = QtCore.Qt.darkGray
                pattern = QtCore.Qt.DashLine
            
            if not color:
                color = QtCore.Qt.gray
            if not pattern:
                pattern = QtCore.Qt.SolidLine
                
            painter.setPen(QtGui.QPen(color, 1, 
                pattern, QtCore.Qt.RoundCap, QtCore.Qt.RoundJoin))
            painter.drawLine(line)
        
        
            # Draw the arrows if there's enough room.
            angle = math.acos(line.dx() / line.length())
            if line.dy() >= 0:
                angle = 2*math.pi - angle

            destArrowP1 = self.destPoint + \
                QtCore.QPointF(math.sin(angle-math.pi/3)*self.arrowSize,
                math.cos(angle-math.pi/3)*self.arrowSize)
            destArrowP2 = self.destPoint + \
                QtCore.QPointF(math.sin(angle-math.pi+math.pi/3)*self.arrowSize,
                math.cos(angle-math.pi+math.pi/3)*self.arrowSize)
            
            if self.drawArrow:
                painter.setBrush(color)
                painter.drawPolygon(QtGui.QPolygonF([line.p2(), \
                    destArrowP1, destArrowP2]))
        
        
        # Draw port numbers
        if self.showPorts:
            offs = 0.2
            offset = QtCore.QPointF(offs,offs)
            sPortPoint = self.sourcePoint + offset 
            dPortPoint = self.destPoint + offset
            textRect = self.boundingRect()
            font = painter.font()
            font.setBold(True)
            font.setPointSize(4)
            painter.setFont(font)
            sx = self.sourcePoint.x()+self.destPoint.x()/12
            sy = self.sourcePoint.y()+self.destPoint.y()/12
            dx = self.sourcePoint.x()/12+self.destPoint.x()
            dy = self.sourcePoint.y()/12+self.destPoint.y()
            painter.setPen(QtCore.Qt.green)
            painter.drawText(sx, sy, str(self.sport))
            painter.drawText(dx, dy, str(self.dport))
            
        # Draw link ID
        if self.showID:
            textRect = self.boundingRect()
            font = painter.font()
            font.setBold(True)
            font.setPointSize(4)
            painter.setFont(font)
            painter.setPen(QtCore.Qt.darkRed)
            painter.drawText((self.sourcePoint.x()+self.destPoint.x())/2, 
                        (self.sourcePoint.y()+self.destPoint.y())/2, str(self.uid))
        
    def mouseReleaseEvent(self, event):
        if event.button() == QtCore.Qt.RightButton:
            popup = QtGui.QMenu()
            popup.addMenu(self.linkDetails)
            popup.addSeparator()
            m = popup.addMenu("Mininet")
            m.addAction("Bring link &up", self.bringLinkUp)
            m.addAction("Bring link &down", self.bringLinkDown)
            popup.exec_(event.lastScreenPos())
        self.update()
        QtGui.QGraphicsItem.mouseReleaseEvent(self, event)

    def bringLinkUp(self):
        ''' when user turns link on from GUI, sends message
        to dispatch server '''
        self.graph.mininetLinkDown(self.source.id, self.dest.id)

    def bringLinkDown(self):
        ''' when user turns link off from GUI, sends message
        to dispatch server '''
        self.graph.mininetLinkDown(self.source.id, self.dest.id)
        #self.sport
        #self.dport

    def setLinkUp(self):
        self.isUp = True
        self.update()

    def setLinkDown(self):
        self.isUp = False
        self.update()

class TopoWidget(QtGui.QWidget):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)
        self.parent = parent
        
        # Handle to infoDisplay
        self.infoDisplay = self.parent.infoWidget
        
        self.topologyView = TopologyView(self)
        
        # Dictionary keeping track of views
        self.views = {}
        
        # Default view
        default_view = Default_View(self)
        self.views[default_view.name] = default_view
        
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        ### Add custom topology views here
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        self.monitoring_view = Monitoring_View(self)
        self.stp_view = STP_View(self)
        self.routing_view = Sample_Routing_View(self)
        self.flowtracer_view = Flow_Tracer_View(self)
        
        self.views[self.monitoring_view.name] = self.monitoring_view
        self.views[self.stp_view.name] = self.stp_view
        self.views[self.routing_view.name] = self.routing_view
        self.views[self.flowtracer_view.name] = self.flowtracer_view
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        ### This is the only addition required in this file when adding views
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        
        self.changeViewWidget = ChangeViewWidget(self)
  
        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(self.topologyView)
        vbox.addWidget(self.changeViewWidget)

        self.setLayout(vbox)
        self.resize(300, 150)

        self.views["Default"].show()
        
        self.selectedNode = None
        
        
class ChangeViewWidget(QtGui.QWidget):
    def __init__(self, parent):
        self.parent = parent
        QtGui.QWidget.__init__(self, parent)
        
        # Configure Widget
        # Primary view buttons
        self.viewBtns = []
        
    
        # Add 'Default' button first
        button = QtGui.QPushButton("Default")
        button.setCheckable(True)
        button.setStatusTip("Switch to Default view")
        self.viewBtns.append(button)
        self.connect(button, QtCore.SIGNAL('clicked()'),
                parent.views["Default"].show)
        self.connect(button, QtCore.SIGNAL('clicked()'),
                self.parent.topologyView.updateAll)
        self.connect(button, QtCore.SIGNAL('clicked()'),
                self.markView)
        self.connect(button, QtCore.SIGNAL('clicked()'),
                self.notify_backend)
        
        self.viewBtns[0].setChecked(True)
        # Add the rest view buttons, random order
        for viewName, viewObject in self.parent.views.items():
            if viewName == "Default" :
                continue
            button = QtGui.QPushButton(viewName)
            button.setCheckable(True)
            button.setStatusTip("Switch to %s view"%viewName)
            self.viewBtns.append(button)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    viewObject.show)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    self.parent.topologyView.updateAll)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    self.markView)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    self.notify_backend)
        
        # Added by custom views
        self.secondaryBtns = []
        
        # Layout           
        self.grid = QtGui.QGridLayout()
        for i in range(0,len(self.viewBtns)): 
            self.grid.addWidget(self.viewBtns[i], 0, i)
        self.setLayout(self.grid)
        
    def markView(self):
        for b in self.viewBtns:            
            b.setChecked(False)
        self.sender().setChecked(True)
        
    def notify_backend(self):
        return
        #msg = GuiViewChanged()
        #msg.active_view = str(self.sender().text())
        #self.parent.topologyView.topologyInterface.send(msg)
        
class TopologyView(QtGui.QGraphicsView):

    updateAllSignal = QtCore.pyqtSignal() 
    
    def __init__(self, parent=None):
        QtGui.QGraphicsView.__init__(self, parent)
        self.parent = parent
        # topologyInterface exchanges json messages with monitoring server
        
        #self.topologyInterface = TopologyInterface(self)
        self.topologyInterface = self.parent.parent.communication
        #self.topologyInterface.start()
        self.mininet = jsonrpc.ServerProxy(jsonrpc.JsonRpc20(),
            jsonrpc.TransportTcpIp(addr=(self.parent.parent.mininet_address, 31415)))

    
        self.setStyleSheet("background: black")
    
        self.topoScene = QtGui.QGraphicsScene(self)
        self.topoScene.setItemIndexMethod(QtGui.QGraphicsScene.NoIndex)
        self.topoScene.setSceneRect(-300, -300, 600, 600)
        self.setScene(self.topoScene)
        self.setCacheMode(QtGui.QGraphicsView.CacheBackground)
        self.setRenderHint(QtGui.QPainter.Antialiasing)
        self.setTransformationAnchor(QtGui.QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QtGui.QGraphicsView.AnchorViewCenter)
        
        self.drawAccess = 'Default'  #(utilization/te/et/etc)

        self.scale(0.9, 0.9)
        self.setMinimumSize(400, 400)
        
        # Pan
        self.setDragMode(self.ScrollHandDrag)
        self.setCursor(QtCore.Qt.ArrowCursor)        
        
        # Connect signals to slots
        self.topologyInterface.topology_received_signal[object].connect \
                (self.got_topo_msg)
        self.updateAllSignal.connect(self.updateAll)
        
        # Dictionaries holding node and link QGraphicsItems
        self.nodes = {}
        self.links = {}
                
        self.helloMessenger()        
                
        self.get_nodes()
        
        # Get an initial current snapshot of the topology
        #self.get_topology()
                
        # Subscribe to LAVI for topology changes
        #self.subscribe_to_topo_changes()
        
    def helloMessenger(self):
        '''
        Initialize communication with backend messenger
        '''
        msg = {"hello":"mux"}
        self.topologyInterface.send(msg)
        msg = {"_mux":"gui", "hello":"gui"}
        self.topologyInterface.send(msg)
        
    def subscribe_to_topo_changes(self):
        '''
        Subscribe to topology backend for topology changes
        '''
        msg = {}
        msg["_mux"] = "gui"
        msg["type"] = "topology"
        msg["command"] = "subscribe"
        msg["node_type"] = "all"
        #msg = json.dumps(msg)
        self.topologyInterface.send(msg)
        
        msg = {}
        msg["_mux"] = "gui"
        msg["type"] = "topology"
        msg["command"] = "subscribe"
        msg["link_type"] = "all"
        self.topologyInterface.send(msg)
        
    def get_nodes(self):
        '''
        Ask topology for an updated nodes set
        '''
        msg = {}
        msg["_mux"] = "gui"
        msg["type"] = "topology"
        msg["command"] = "request"
        msg["node_type"] = "all"
        #msg = json.dumps(msg)
        self.topologyInterface.send(msg)

    def get_links(self):
        '''
        Ask topology for an updated links set
        '''
        msg = {}
        msg["_mux"] = "gui"
        msg["type"] = "topology"
        msg["command"] = "request"
        msg["link_type"] = "all"
        #msg = json.dumps(msg)
        self.topologyInterface.send(msg)
        
    def get_topology(self):
        '''
        Ask topology for updated nodes and links sets
        '''
        self.get_nodes()
        self.get_links()
        
    def got_topo_msg(self, msg):
        '''
        Handle received links/nodes message 
        '''
        if "node_id" in msg:
            if msg["command"] == "add":
                nodes = msg["node_id"]
                new_nodes = []
                # Populate nodes
                for nodeID in nodes:
                    """
                    # prepend 0s until len = 12
                    while len(nodeID) < 12 :
                        nodeID = "0"+nodeID
                    """
                    # If nodeItem doesn't already exist
                    if nodeID not in self.nodes.keys():
                        nodeItem = Node(self, nodeID, msg["node_type"])
                        self.nodes[nodeID] = nodeItem
                        new_nodes.append(nodeItem)  
                self.addNodes(new_nodes)
                self.positionNodes(new_nodes)
                
            elif msg["command"] == "delete":
                nodes = msg["node_id"]
                for nodeID in nodes:
                    if not msg["node_type"] == "host":
                        """
                        # prepend 0s until len = 12
                        while len(nodeID) < 12 :
                            nodeID = "0"+nodeID
                        """
                    if nodeID in self.nodes.keys():
                        #un-draw node
                        n = self.nodes[nodeID]
                        self.topoScene.removeItem(n)
                        n.update()
                        '''Should I delete nodes or store in 'down' state?'''
                        del self.nodes[nodeID]
                        
        elif "links" in msg:
            if msg["command"] == "add":
                links = msg["links"]
                new_links = []
                # Populate Links
                linkid = len(self.links)
                for link in links:
                
                    # Lavi advertises 1 link for each direction
                    # We'll add a single object for a biderectional link
                    # We'll always use 'minend-maxend' as the key
                    srcid = link["src id"]
                    """
                    while len(srcid) < 12 :
                        srcid = "0"+srcid
                    """
                    dstid = link["dst id"]
                    """
                    while len(dstid) < 12 :
                        dstid = "0"+dstid
                    """
                    
                    minend = str(min(srcid,dstid))
                    maxend = str(max(srcid,dstid))
                    key = minend+'-'+maxend
                    
                    if key in self.links:
                        continue
                       
                    # If src_port is missing, default to 1
                    if not "src port" in link:
                        link["src port"] = 1
                    linkid = linkid+1
                    
                    # Create new linkItem
                    linkItem = Link(self, self.nodes[srcid], self.nodes[dstid],\
                        link["src port"], link["dst port"], linkid) 
                    self.links[key]=linkItem                    
                    new_links.append(linkItem)
                    
                self.addLinks(new_links)
                
            elif msg["command"] == "delete":
                links = msg["links"]
                for link in links:
                    # Only do this once (for both directions)
                    if link["src id"] > link["dst id"]:
                        continue
                    # First, check if link exists
                    key = str(link["src id"])+"-"+str(link["dst id"])
                    if key in self.links:
                        #un-draw link
                        l = self.links[key]
                        self.topoScene.removeItem(l)
                        l.update()
                        '''Should I delete links or store in 'down' state?'''
                        del self.links[key]
                        
                    else:    
                        print "Attempted to removed inexistent link:", key
        
        self.updateAll()
    
    def addNodes(self, new_nodes):
        '''
        Add nodes to topology Scene
        '''
        for nodeItem in new_nodes:
            self.topoScene.addItem(nodeItem)
            
    def addLinks(self, new_links):
        '''
        Add links to topology Scene
        '''
        for linkItem in new_links:
            self.topoScene.addItem(linkItem)
            
    def positionNodes(self, new_nodes):
        '''
        Position nodes according to current loaded layout (or random if none)
        '''
        
        minX, maxX = -300, 300
        minY, maxY = -200, 200
        
        layout = self.parent.parent.settings.current_topo_layout 
        
        if layout == "random":
            for node in new_nodes:
                node.setPos(randint(minX,maxX), randint(minY,maxY))
        
        else:
            '''
            If node position is described in current layout file, choose that,
            otherwise place randomly
            '''        
            # Optimize: scan file into a dictionary. same for load.
            f = QtCore.QFile("gui/layouts/"+layout)
            f.open(QtCore.QIODevice.ReadOnly)
            for node in new_nodes:
                line = f.readLine()
                found = False
                while not line.isNull():
                    nodeid,x,y = str(line).split()
                    line = f.readLine()
                    if str(node.id) == nodeid:
                        node.setPos(float(x), float(y))
                        found = True
                if not found:
                    node.setPos(randint(minX,maxX), randint(minY,maxY))
            f.close()
        
    def itemMoved(self):
        pass
    
    def disableAllLinks(self):
        for e in self.links.values():
            e.setLinkDown()
            e.update()

    def enableAllLinks(self):
        for e in self.links.values():
            e.setLinkUp()
            e.update()

    def disableAllNodes(self):
        for n in self.nodes.values():
            n.bringSwitchDown()
            n.update()

    def enableAllNodes(self):
        for n in self.nodes.values():
            n.bringSwitchUp()
            n.update()

    def updateAllNodes(self):
        '''
        Refresh all Nodes
        '''
        for n in self.nodes.values():
            n.update()
            
    def updateAllLinks(self):
        '''
        Refresh all Links
        '''
        for e in self.links.values():
            e.update()
            e.adjust()
            
    def updateAll(self):
        '''
        Refresh all Items
        # see if there is a auto way to updateall (updateScene()?)
        '''
        self.updateAllNodes()
        self.updateAllLinks()
            
    def keyPressEvent(self, event):
        '''
        Topology View hotkeys
        '''
        key = event.key()
        if key == QtCore.Qt.Key_Plus:
            self.scaleView(1.2)
        elif key == QtCore.Qt.Key_Minus:
            self.scaleView(1 / 1.2)
        elif key == QtCore.Qt.Key_N:
            self.toggleNodes()
        elif key == QtCore.Qt.Key_I:
            self.toggleNodeIDs()
        elif key == QtCore.Qt.Key_K:
            self.toggleLinks()
        elif key == QtCore.Qt.Key_L:
            # LAVI counts a biderctional link as 2 separate links, so IDs overlap
            self.toggleLinkIDs()
            self.updateAllLinks()
        elif key == QtCore.Qt.Key_P:
            self.togglePorts()
            self.updateAllLinks()
        elif key == QtCore.Qt.Key_H:
            self.toggleHosts()
            self.updateAllNodes()
        #elif key == QtCore.Qt.Key_R:
        #    # Refresh topology
        #    self.get_topology()
        elif key == QtCore.Qt.Key_Space or key == QtCore.Qt.Key_Enter:
            # Redraw topology
            self.positionNodes(self.nodes.values())
            self.updateAll()
        else:
            QtGui.QGraphicsView.keyPressEvent(self, event)
    '''
    Toggle display of drawn items
    '''
    def toggleNodes(self):
        for node in self.nodes.values():
            node.showNode = not node.showNode
            node.update()
            
    def toggleNodeIDs(self):
        for node in self.nodes.values():
            node.showID = not node.showID
            node.update()            

    def toggleLinks(self):
        for link in self.links.values():
            link.showLink = not link.showLink
            link.update()
            
    def toggleLinkIDs(self):
        for link in self.links.values():
            link.showID = not link.showID
            link.update()
            
    def togglePorts(self):
        for link in self.links.values():
            link.showPorts = not link.showPorts
            link.update()
            
    def toggleHosts(self):        
        for node in self.nodes.values():
            if node.layer == 3:
                for l in node.linkList:
                    l.showLink = not l.showLink
                    l.update()
                node.showID = not node.showID
                node.showNode = not node.showNode
                node.update()

    def drawBackground(self, painter, rect):
        '''
        Draw background. For now just some text
        '''
        sceneRect = self.sceneRect()
        textRect = QtCore.QRectF(sceneRect.left() -5, sceneRect.top() + 60,
                                 sceneRect.width() - 4, sceneRect.height() - 4)
        
        message = self.tr("Topology")
        
        font = painter.font()
        font.setPointSize(12)
        painter.setFont(font)
        painter.setPen(QtCore.Qt.darkGray)
        painter.drawText(textRect.translated(20.8, 5.8), message)
        painter.setPen(QtCore.Qt.white)
        painter.setPen(QtGui.QColor(QtCore.Qt.gray).light(130))
        painter.drawText(textRect.translated(20, 5), message)
                
    def wheelEvent(self, event):
        '''
        Zoom
        '''
        self.scaleView(math.pow(2.0, event.delta() / 300.0))
        
    def scaleView(self, scaleFactor):
        factor = self.matrix().scale(scaleFactor, scaleFactor).mapRect(QtCore.QRectF(0, 0, 1, 1)).width()

        if factor < 0.07 or factor > 100:
            return

        self.scale(scaleFactor, scaleFactor)
    
    def mouseReleaseEvent(self, event):
        '''
        Show context menu when right-clicking on empty space on the scene.
        '''
        if not self.itemAt(event.pos()):
            if event.button() == QtCore.Qt.RightButton:
                popup = QtGui.QMenu()
                popup.addAction("Load Layout", self.loadLayout)
                popup.addAction("Save Layout", self.saveLayout)
                m = popup.addMenu("Mininet")
                m.addAction("Add Switch", self.addSwitch)
                m.addAction("Add Host", self.addHost)
                popup.exec_(event.globalPos())
        QtGui.QGraphicsView.mouseReleaseEvent(self, event)
    
    def saveLayout(self):
        '''
        Saves the current node positioning
        '''
        title = "Specify file to store topology layout"
        filename = QtGui.QFileDialog.getSaveFileName(self,title,"gui/layouts")
        f = QtCore.QFile(filename)
        f.open(QtCore.QIODevice.WriteOnly)
        for node in self.nodes.values():
            line = QtCore.QByteArray(str(node.id)+" "+\
                                    str(round(int(node.x()),-1))+" "+\
                                    str(round(int(node.y()),-1))+" \n")
            f.write(line)
        f.close()
        
        layout = str(filename).split("/")
        layout = layout[len(layout)-1]
        self.parent.parent.settings.set_current_topo_layout(layout)
        
    def loadLayout(self):
        '''
        Loads a custom node positioning for this topology
        '''
        title = "Load topology layout from file"
        filename = QtGui.QFileDialog.getOpenFileName(self,title,"gui/layouts")
        f = QtCore.QFile(filename)
        f.open(QtCore.QIODevice.ReadOnly)
        line = f.readLine()
        while not line.isNull():
            nodeid,x,y = str(line).split()
            line = f.readLine()
            if not nodeid in self.nodes:
                print "Layout mismatch (node", nodeid, "exists in conf file but has not been discovered on the network)"
            else:
                self.nodes[nodeid].setX(float(x))
                self.nodes[nodeid].setY(float(y))
        f.close()
        
        layout = str(filename).split("/")
        layout = layout[len(layout)-1]
        self.parent.parent.settings.set_current_topo_layout(layout)
        
        self.updateAll()
        
    def addSwitch(self):
        self.mininet.addNextSwitch()
        
    def addHost(self):
        self.mininet.addNextHost()
        
    def mininetLinkFrom(self, id):
        self.linkfrom = id
        self.linkto = getattr(self, "linkto", None)
        if not self.linkto:
            self.parent.setStatusTip("Adding link from %s" % id)
        else:
            self.parent.setStatusTip("Adding link %s <-> %s"
                                     %(self.linkto, self.linkfrom))
            self.mininet.addLink(self.linkfrom, self.linkto )
            self.linkfrom = None
            self.linkto = None
        
    def mininetLinkTo(self, id):
        self.linkto = id
        self.linkfrom = getattr(self, "linkfrom", None)
        if not self.linkfrom:
            self.parent.setStatusTip("Adding link to %s" % id)
        else:
            self.parent.setStatusTip("Adding link %s <-> %s"
                                     %(self.linkto, self.linkfrom))
            self.mininet.addLink(self.linkfrom, self.linkto )
            self.linkfrom = None
            self.linkto = None
                
    def mininetLinkUp(self, src, dst):
        self.mininet.linkUp(src, dst)
        self.parent.setStatusTip("Brought up link %s <-> %s"
                                     %(src, dst))
    
    def mininetLinkDown(self, src, dst):
        self.mininet.linkDown(src, dst)
        self.parent.setStatusTip("Brought down link %s <-> %s"
                                     %(src, dst))
