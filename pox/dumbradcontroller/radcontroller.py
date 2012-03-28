from pox.core import *
import pox.openflow.libopenflow_01 as openflow
from pox.topology.topology import *
from pox.lib.revent import *
from pox.lib.packet import ethernet
from pox.lib.packet import arp
from pox.openflow.discovery import LinkEvent
from pox.lib.util import dpidToStr
from pox.lib.addresses import *
from collections import deque
from pox.lib.recoco import Timer
from logging import CRITICAL
log = core.getLogger()
log.setLevel(CRITICAL)
class PortDirection (object):
    IN = 0
    OUT = 1
class Link (object):
    def __init__(self, srcdp, destdp):
        self.srcprt = 0
        self.dstprt = 0
        self.srcdp = srcdp
        self.dstdp = destdp
class RADController (EventMixin):
    """ This class implements a reasonably simple controller that does routing over DAGs. Since there are
    instances where we don't have enough information to just use the point to point protocol, when in such a
    situation we resort to outputting on host only ports from every switch. This is reasonable since in cases where
    we flood we don't install routing entries anyways, and any switch without a connection to the controller will not 
    be able to flood anyways. This method also avoids all the messiness of dealing with broadcast situations in DDC, since
    we really just want to deal with point to point communication, and only need the broadcast messages for initial port discovery
    """
    dependsOn = ['topology', 'openflow_discovery', 'openflow']
    def __init__(self):
        core.listenToDependencies(self, self.dependsOn)    
        self.listenTo(core)
        self.listenTo(core.openflow)
        self.port_directions = {}
        self.spanning_tree = []
        self.flood_ports = {}
        self.host_only_ports = {}
        self.connections = {}
        self.dpids = {}
        self.dpid_count = 1
        self.links = {}
        self._topologyTimer = None
        self._freezeTopologyUpdates = False

    def FreezeTopologyUpdates(self):
        self._freezeTopologyUpdates = True

    def ThawToplogyUpdates(self):
        self._freezeTopologyUpdates = False

    def _handle_ConnectionUp(self, event):
        self.dpids[event.connection.dpid] = self.dpid_count
        self.dpid_count = self.dpid_count + 1
        print str.format("New DPID {0}", self.dpid_count)
        #log.debug(str.format('Listening to connection for dpid {0}', self.dpids[event.connection.dpid]))
        self.connections[self.dpids[event.connection.dpid]] = event.connection
        return

    def _handle_ConnectionDown(self, event):
        del self.connections[self.dpids[event.dpid]]
        return

    def SplitIntoChunks(self, array, length):
        for i in xrange(0, len(array), length):
            yield array[i:i+length]

    def CreatePortDirectionActions(self, directions):
        actions = [openflow.ddc_port_direction(port, direction) for (port, direction) in directions.items()]
        return actions

    def _handle_PacketIn(self, event):
        if not core.host_tracker:
            #log.debug('No host tracker cannot route')
            core.quit()
        packet = event.parse()
        if packet.type == ethernet.LLDP_TYPE:
            return
        #log.debug('PacketIn')
        if packet.dst.isMulticast():
            #self.FloodUsingSpanningTree(event)
            self.SimpleFlood(event)
        else:
            self.SimpleFlood(event)
            return
            entry = core.host_tracker.getEntryByMAC(packet.dst)
            if entry:
                target_dpid = entry.dpid
                if target_dpid == event.connection.dpid:
                    """At the end, do the right thing"""
                    port = entry.port
                    #log.debug(str.format('Installing flow to end host dpid {0} port {1}', self.dpids[target_dpid], port))
                    msg = openflow.ofp_flow_mod()
                    msg.match = openflow.ofp_match.from_packet(packet)
                    msg.idle_timeout = 16
                    msg.hard_timeout = 256
                    #msg.actions.append(openflow.ofp_action_vlan_strip())
                    msg.actions.append(openflow.ofp_action_output(port = port))
                    msg.buffer_id = event.ofp.buffer_id
                    event.connection.send(msg)
                else:
                    """This is where we start worrying about telling the switch about all the outports, for now just find one and send along that"""
                    port = 0
                    target_dpid = self.dpids[target_dpid]
                    if target_dpid not in self.port_directions or self.dpids[event.connection.dpid] not in self.port_directions[target_dpid]:
                        #log.debug(str.format("Could not find target in DAG, or DAG is not fully connected yet"))
                        #self.FloodUsingSpanningTree(event)
                        self.SimpleFlood(event)
                    else:
                        for tempport, direction in self.port_directions[target_dpid][self.dpids[event.connection.dpid]].iteritems():
                            if direction == PortDirection.OUT:
                                port = tempport
                                break
                        if port != 0:
                            """Real routing, yay"""
                            #log.debug(str.format('Installing flow using DAG at dpid {0} port {1}', event.connection.dpid, port))
                            msg = openflow.ofp_flow_mod()
                            msg.match = openflow.ofp_match.from_packet(packet)
                            msg.idle_timeout = 16
                            msg.hard_timeout = 256
                            msg.actions.append(openflow.ofp_action_vlan_vid(vlan_vid = target_dpid))
                            msg.actions.append(openflow.ofp_action_output(port = port))
                            msg.buffer_id = event.ofp.buffer_id
                            event.connection.send(msg)
                            #othermsg = openflow.nxt_set_port_state(port = port, state = openflow.nxt_set_port_state.PORT_DOWN)
                            #event.connection.send(othermsg)
                        else:
                            """We don't have all our links up yet"""
                            #log.debug("Could not find an out port from dpid {0} to dpid {1}", event.connection.dpid, target_dpid)
                            #self.FloodUsingSpanningTree(event)
                            self.SimpleFlood(event)
            else:
                #log.debug("host_tracker does not know about host") 
                #self.FloodUsingSpanningTree(event)
                self.SimpleFlood(event)
        return

    def _handle_ComponentRegistered(self, event):
        if core.listenToDependencies(self, self.dependsOn):   
            #log.debug('Now listening to topology, openflow and discovery')
            return EventRemove

    def TakeDownLink(self, key):
        self.FreezeTopologyUpdates()
        if key not in self.links:
            #log.debug('Invalid link')
            return
        link = self.links[key]
        #log.debug('Taking link down')
        assert(link.srcprt != 0 and link.dstprt != 0)
        msg = openflow.nxt_set_port_state(port = link.srcprt, state = openflow.nxt_set_port_state.PORT_DOWN)
        self.connections[self.dpids[link.srcdp]].send(msg)
        msg = openflow.nxt_set_port_state(port = link.dstprt, state = openflow.nxt_set_port_state.PORT_DOWN)
        self.connections[self.dpids[link.dstdp]].send(msg)
        #log.debug('No more link')

    def TakeUpLink(self, key):
        if key not in self.links:
            #log.debug('Invalid link')
            return
        link = self.links[key]
        #log.debug('Taking link up')
        assert(link.srcprt != 0 and link.dstprt != 0)
        msg = openflow.nxt_set_port_state(port = link.srcprt, state = openflow.nxt_set_port_state.PORT_UP)
        self.connections[self.dpids[link.srcdp]].send(msg)
        msg = openflow.nxt_set_port_state(port = link.dstprt, state = openflow.nxt_set_port_state.PORT_UP)
        self.connections[self.dpids[link.dstdp]].send(msg)
        #log.debug('Link restored')

    def ShowHosts(self):
        if not core.host_tracker:
            #log.debug('No host tracker when ShowHosts called')
            core.quit()
        for ip, entry in core.host_tracker.entryByIP.iteritems():
            #log.debug(str.format("{0} => {1}", ip, entry))
            pass
        for ip, entry in core.host_tracker.entryByMAC.iteritems():
            #log.debug(str.format("{0} => {1}", ip, entry))
            pass

    def ComputeSpanningTree(self, switches):
        #log.debug('ComputeSpanningTree')
        trees = {switch.dpid: [switch] for switch in switches}
        links = {}
        for switch in switches:
            for id, port in switch.ports.iteritems():
                if port.number <= openflow.OFPP_MAX:
                    for entity in port.entities:
                        if entity.dpid == switch.dpid:
                            log.error('Found a loop, bug')
                            continue
                        src = min(switch.dpid, entity.dpid)
                        dest = max(switch.dpid, entity.dpid)
                        if (src, dest) not in links:
                            links[(src, dest)] = Link(src, dest)
                        if src == switch.dpid:
                            links[(src, dest)].srcprt = port.number
                        else:
                            links[(src, dest)].dstprt = port.number
        links = links.values()
        spanning_tree = []
        while len(links) > 0:
            link = links.pop()
            if trees[link.srcdp] == trees[link.destdp]:
                continue
            spanning_tree.append(link)
            elts = trees[link.destdp]
            trees[link.srcdp].extend(trees[link.destdp])
            for elt in elts:
                trees[elt.dpid] = trees[link.srcdp]
            if len(trees[link.srcdp]) == len(switches):
                break
        return spanning_tree
    def ComputeDag(self, vertex, switches):
        #log.debug('Computing DAG')
        visited = []
        port_direction = {}
        distances = {self.dpids[switch.dpid]: 255 for switch in switches}
        distances[self.dpids[vertex.dpid]] = 0
        to_visit = deque([vertex])
        while len(to_visit) > 0:
            vertex = to_visit.popleft()
            visited.append(vertex)
            port_direction[self.dpids[vertex.dpid]] = {}
            for id, port in vertex.ports.iteritems():
                if port.number <= openflow.OFPP_MAX:
                    for entity in port.entities:
                        if distances[self.dpids[entity.dpid]] < distances[self.dpids[vertex.dpid]]:
                            assert(distances[self.dpids[vertex.dpid]] == distances[self.dpids[entity.dpid]] + 1)
                            port_direction[self.dpids[vertex.dpid]][port.number] = PortDirection.OUT
                        elif distances[self.dpids[entity.dpid]] > distances[self.dpids[vertex.dpid]]:
                            distances[self.dpids[entity.dpid]] = distances[self.dpids[vertex.dpid]] + 1
                            port_direction[self.dpids[vertex.dpid]][port.number] = PortDirection.IN
                        else:
                            if self.dpids[entity.dpid] > self.dpids[vertex.dpid]:
                                port_direction[self.dpids[vertex.dpid]][port.number] = PortDirection.IN
                            else:
                                port_direction[self.dpids[vertex.dpid]][port.number] = PortDirection.OUT
                        if entity not in visited:
                            to_visit.append(entity)
        return (distances, port_direction)

    def _handle_openflow_discovery_LinkEvent(self, event):
        if self._freezeTopologyUpdates:
            pass
            #return
        ##log.debug(core.topology)
        switches = core.topology.getEntitiesOfType(t=Switch)
        self.links = {}
        if len(switches) == 0:
            return
        for switch in switches:
            self.flood_ports[self.dpids[switch.dpid]] = []
            self.host_only_ports[self.dpids[switch.dpid]] = []
            distance, directions = self.ComputeDag(switch, switches)
            self.port_directions[self.dpids[switch.dpid]] = directions
            for id, port in switch.ports.iteritems():
                if port.number <= openflow.OFPP_MAX:
                    if len(port.entities) == 0:
                        self.flood_ports[self.dpids[switch.dpid]].append(port.number)
                        self.host_only_ports[self.dpids[switch.dpid]].append(port.number)
                    else:
                        for entity in port.entities:
                            if entity.dpid == switch.dpid:
                                log.error('Found a loop, bug')
                                continue
                            src = min(self.dpids[switch.dpid], self.dpids[entity.dpid])
                            dest = max(self.dpids[switch.dpid], self.dpids[entity.dpid])
                            if (src, dest) not in self.links:
                                self.links[(src, dest)] = Link(src, dest)
                            if src == switch.dpid:
                                self.links[(src, dest)].srcprt = port.number
                            else:
                                self.links[(src, dest)].dstprt = port.number
        if self._topologyTimer == None and not self._freezeTopologyUpdates:
            print "Starting update timer"
            self._topologyTimer = Timer(6, self._updateTopology)
        return

    def _handle_topology_Update(self, event):
        if not isinstance(event.event, LinkEvent):
            return

    def _updateTopology(self):
       print "Timer done"
       #log.debug('Timer went off, updating topology')
       self._topologyTimer = None
       if self._freezeTopologyUpdates:
           return
       for (switch, connection) in self.connections.iteritems():
           for other_dpid in self.port_directions.keys():
               if other_dpid != switch and switch in self.port_directions[other_dpid]:
                   ##log.debug(str.format("From {0} to {1}", switch, other_dpid))
                   msg = openflow.nxt_dag_information(dpid = other_dpid, own_dpid = switch)
                   msg.directions.extend(self.CreatePortDirectionActions(self.port_directions[other_dpid][switch]))
                   connection.send(msg)
       #log.debug('Done sending topology updates')

    def FloodUsingSpanningTree(self, event):
        inport = event.port
        connection = event.connection
        dpid = connection.dpid
        #log.debug(str.format('Flooding from dpid {0}', dpid))
        msg = openflow.ofp_packet_out()
        for port in self.flood_ports[dpid]:
            if port != inport:
                msg.actions.append(openflow.ofp_action_output(port = port))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = inport
        connection.send(msg)

    def SimpleFlood(self, event):
        inport = event.port
        packet = event.parse()
        srcdpid = event.connection.dpid
        #log.debug(str.format('Flooding from dpid {0}', self.dpids[srcdpid]))
        for dpid, connect in self.connections.iteritems():
            #log.debug(str.format('Trying to flood from dpid {0} ({1})', self.dpids[connect.dpid], dpid))
            if dpid not in self.host_only_ports:
                continue
            dpid_outports = self.host_only_ports[dpid]
            if dpid == srcdpid:
                try:
                    dpid_outports.remove(inport)
                except ValueError:
                    pass
            msg = openflow.ofp_packet_out()
            msg.buffer_id = -1
            msg.inport = openflow.OFPP_NONE
            msg.actions.extend([openflow.ofp_action_output(port = p) for p in dpid_outports])
            msg.data = event.data
            connect.send(msg)
            #log.debug(str.format('Sending to flood from dpid {0}', connect.dpid))
