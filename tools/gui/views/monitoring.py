'''
Monitoring view for drawn topology

@author Kyriakos Zarifis
@author Rean Griffith
'''
from PyQt4 import QtGui, QtCore
from view import View
#import simplejson as json
import json

class Monitoring_View(View):

    def __init__(self, topoWidget):
        View.__init__(self, topoWidget, "Monitoring")
        
        # Monitoring view buttons
        infoBtn = QtGui.QPushButton('What is Monitoring?')
        
        self.connect(infoBtn, QtCore.SIGNAL('clicked()'), self.showInfo)
       
        self.buttons.append(infoBtn)

        for b in self.buttons:
            b.setCheckable(True)
        
        # maps tuples (dpid, port) to utilization
        self.stats = {}  
        
        self.topologyInterface.monitoring_received_signal.connect( \
            self.got_monitoring_msg )
            
        # Subscribe for linkutils
        msg = {}
        msg["_mux"] = "gui"
        msg ["type"] = "monitoring"
        msg ["command"] = "subscribe"
        msg ["msg_type"] = "linkutils"
        self.topologyInterface.send( msg )    
            
    def get_stats(self, dpid, command):
        queryMsg = {}
        queryMsg["_mux"] = "gui"
        queryMsg["type"] = "monitoring"
        queryMsg["dpid"] = dpid
        queryMsg["command"] = command
        self.topologyInterface.send( queryMsg )
        
    def got_monitoring_msg(self, msg):
        jsonmsg = json.loads(str(msg))
        if jsonmsg["msg_type"] == "linkutils":
            self.update_stats(jsonmsg["utils"])
        else:
            self.show_stats_reply(jsonmsg)

    def get_port_stats( self, dpid ):
        self.get_stats(dpid, "portstats")

    def get_table_stats( self, dpid ):
        self.get_stats(dpid, "tablestats")

    def get_aggregate_stats( self, dpid ):
        self.get_stats(dpid, "aggstats")

    def get_latest_snapshot( self, dpid ):
        self.get_stats(dpid, "latestsnapshot")

    def get_flow_stats( self, dpid ):
        self.get_stats(dpid, "flowstats")

    def get_queue_stats( self, dpid ):
        self.get_stats(dpid, "queuestats")

    def show_stats_reply( self, replyMsg ):
        
        reply = json.loads( replyMsg["data"] )
        self.infoDisplay.grab()
        
        if replyMsg["msg_type"] == "portstats":
            msg = "Query results came back (dpid=0x%x)"%replyMsg["dpid"]
            msg += "\n"+str(len(reply[0]))+" ports:\n"
            self.infoDisplay.append(msg)
            for item in reply[0]:
                port = "\n" + \
                    "Port number: " + str(item['port_no']) + "\n" + \
                    "tx bytes    \t: " + str(item['tx_bytes']) + "\n" + \
                    "rx bytes    \t: " + str(item['rx_bytes']) + "\n" + \
                    "tx packets  \t: " + str(item['tx_packets']) + "\n" + \
                    "rx packets  \t: " + str(item['rx_packets']) + "\n" + \
                    "tx dropped  \t: " + str(item['tx_dropped']) + "\n" + \
                    "rx dropped  \t: " + str(item['rx_dropped']) + "\n" + \
                    "tx errors   \t: " + str(item['tx_errors']) + "\n" + \
                    "rx errors   \t: " + str(item['rx_errors']) + "\n" + \
                    "collisions  \t: " + str(item['collisions']) + "\n" + \
                    "rx over err \t: " + str(item['rx_over_err']) + "\n" + \
                    "rx frame err\t: " + str(item['rx_frame_err'])+ "\n" + \
                    "rx crc err  \t: " + str(item['rx_crc_err']) + "\n"
                self.infoDisplay.append(port)
            
        elif replyMsg["msg_type"] == "tablestats":
            msg = "Query results came back (dpid=0x%x)"%replyMsg["dpid"]
            msg += "\n"+str(len(reply[0]))+" tables:\n"
            self.infoDisplay.append(msg)
            for item in reply[0]:
                table = "\n" + \
                "Table name   \t: " + str(item['name']) + "\n" + \
                "Table id   \t\t: " + str(item['table_id']) + "\n" + \
                "Max entries  \t: " + str(item['max_entries']) + "\n" + \
                "Active count \t: " + str(item['active_count']) + "\n" + \
                "Lookup count \t: " + str(item['lookup_count']) + "\n" + \
                "Matched count\t: " + str(item['matched_count']) + "\n"
                self.infoDisplay.append(table)
                
        elif replyMsg["msg_type"] == "aggstats":
            msg = "Query results came back (dpid=0x%x)"%replyMsg["dpid"]
            msg += "\nAggregate statistics:\n"
            self.infoDisplay.append(msg)
            agg = "\n" + \
            "Packet count \t: " + str(reply[0]['packet_count']) + "\n" + \
            "Byte count   \t: " + str(reply[0]['byte_count']) + "\n" + \
            "Flow count   \t: " + str(reply[0]['flow_count']) + "\n"
            self.infoDisplay.append(agg)
            
        elif replyMsg["msg_type"] == "flowstats":
            msg = "Query results came back (dpid=0x%x)"%replyMsg["dpid"]
            msg += "\n"+str(len(reply[0]))+" flows:"
            self.infoDisplay.append(msg)
            for item in reply[0]:
                msg = "\nMatch : \n"
                #for key in item['match']:
                #    msg += key + "=" + str(item['match'][key]) + " "
                # too many checks, optimize performance... Maybe do the above
                # for every item except MAC/IPs, and treat those separately
                match = item['match']
                msg += "in_port: "+str(match['in_port'])+"  "
                if "dl_src" in match:
                    msg += "dl_src: "+hex(match['dl_src'])+"  "
                if "dl_dst" in match:
                    msg += "dl_dst: "+hex(match['dl_dst'])+"  "
                if "nw_src" in match:
                    msg += "nw_src: "+self.intToDottedIP(int(match['nw_src']))+"  "
                if "nw_dst" in match:
                    msg += "nw_dst: "+self.intToDottedIP(int(match['nw_dst']))+"  "
                if "tp_src" in match:
                    msg += "tp_src: "+str(match['tp_src'])+"  "
                if "tp_dst" in match:
                    msg += "tp_dst: "+str(match['tp_dst'])+"  "
                if "nw_dst_n_wild" in match:
                    msg += "nw_dst_n_wild: "+str(match['nw_dst_n_wild'])+"  "
                if "nw_proto" in match:
                    if match['dl_type'] == 0x806:
                        if match['nw_proto'] == 0x1:
                            msg += "nw_proto: (overwritten)ARP-Request  "
                        elif match['nw_proto'] == 0x2:
                            msg += "nw_proto: (overwritten)ARP-Reply  "
                    elif match['nw_proto'] == 0x1:
                        msg += "nw_proto: ICMP  "
                    else:
                        msg += "nw_proto: "+str(match['nw_proto'])+"  "
                if "dl_type" in match:
                    if match['dl_type'] == 0x800:
                        msg += "dl_type: IP  "
                    elif match['dl_type'] == 0x806:
                        msg += "dl_type: ARP  "
                    else:
                        msg += "dl_type: "+hex(match['dl_type'])+"  "
                if "dl_vlan" in match:
                    msg += "dl_vlan: "+str(match['dl_vlan'])+"  "
                if "dl_vlan_pcp" in match:
                    msg += "dl_vlan_pcp: "+str(match['dl_vlan_pcp'])+"  "
                if "nw_tos" in match:
                    msg += "nw_tos: "+str(match['nw_tos'])+"  "
                
                msg += "\nCounters : \n" + \
                "Packet count: " + str(item['packet_count']) + "  " + \
                "Hard timeout: " + str(item['hard_timeout']) + "  " + \
                "Byte count: " + str(item['byte_count']) + "  " + \
                "Idle timeout: " + str(item['idle_timeout']) + "  " + \
                "Duration nsec: " + str(item['duration_nsec']) + "  " + \
                "Duration sec: " + str(item['duration_sec']) + "  " + \
                "Priority: " + str(item['priority']) + "  " + \
                "Cookie: " + str(item['cookie']) + "  " + \
                "Table id: " + str(item['table_id'])
                msg += "\nActions : \n"
                for action in item['actions']:
                    msg += "Port: "+str(action['port'])
                """NEED TO ADD PARSING FOR OTHER ACTION_TYPES TOO"""
                #action_types = enumerate["output","setvlan",etc...]
                # msg += "Type: "+types[action['type']]) etc
                self.infoDisplay.append(msg)
                
        elif replyMsg["msg_type"] == "queuestats":
            msg = "Query results came back (dpid=0x%x)"%replyMsg["dpid"]
            msg += "\n"+str(len(reply[0]))+" queues:\n"
            self.infoDisplay.append(msg)
            for item in reply[0]:
                queue = "\n" + \
                "Port number : " + str(item['port_no']) + "\n" + \
                "Queue id    : " + str(item['queue_id']) + "\n" + \
                "tx bytes    : " + str(item['tx_bytes']) + "\n" + \
                "tx packets  : " + str(item['tx_packets']) + "\n" + \
                "tx errors   : " + str(item['tx_errors']) + "\n"
                self.infoDisplay.append(queue)
            
        elif replyMsg["msg_type"] == "latestsnapshot":
            msg = "Query results came back (dpid=0x%x)"%replyMsg["dpid"]
            msg += "Latest snapshot:\n"
            self.infoDisplay.append(msg)
            snapshot = "\n" + \
            "Collection epoch : " + str(reply['collection_epoch']) + "\n" + \
            "Epoch delta      : " + str(reply['epoch_delta']) + "\n" + \
            "Time since delta : " + str(reply['time_since_delta']) + "\n" + \
            "Timestamp        : " + str(reply['timestamp']) + "\n" + \
            "Number of flows  : " + str(reply['number_of_flows']) + "\n" + \
            "Bytes in flows   : " + str(reply['bytes_in_flows']) + "\n" + \
            "Packets in flows : " + str(reply['packets_in_flows']) + "\n" + \
            "Total tx bytes   : " + str(reply['total_tx_bytes']) + "\n" + \
            "Total rx bytes   : " + str(reply['total_rx_bytes']) + "\n" + \
            "Total tx packets : " + str(reply['total_tx_packets']) + "\n" + \
            "Total rx packets : " + str(reply['total_rx_packets']) + "\n" + \
            "Total tx packets dropped : " \
                       + str(reply['total_tx_packets_dropped']) + "\n" + \
            "Total rx packets dropped : " \
                       + str(reply['total_rx_packets_dropped']) + "\n" + \
            "Total tx errors  : " + str(reply['total_tx_errors']) + "\n" + \
            "Total rx errors  : " + str(reply['total_rx_errors']) + "\n" + \
            "Delta tx bytes   : " + str(reply['delta_tx_bytes']) + "\n" + \
            "Delta rx bytes   : " + str(reply['delta_rx_bytes']) + "\n" + \
            "Delta tx packets : " + str(reply['delta_tx_packets']) + "\n" + \
            "Delta rx packets : " + str(reply['delta_rx_packets']) + "\n" + \
            "Delta tx packets dropped : " \
                       + str(reply['delta_tx_packets_dropped']) + "\n" + \
            "Delta rx packets dropped : " \
                       + str(reply['delta_rx_packets_dropped']) + "\n" + \
            "Delta tx errors  : " + str(reply['delta_tx_errors']) + "\n" + \
            "Delta rx errors  : " + str(reply['delta_rx_errors']) + "\n"
            
            # Add in port info
            if len(reply['ports']) > 0:
                snapshot += "\nPort info: \n"
                for port_num in reply['ports']:
                    port_info = reply['ports'][port_num]
                    snapshot += "Port number : " + str(port_num) + "\n" + \
                    "Port name : " + \
                         port_info['port_cap']['port_name'] + "\n" + \
                    "Enabled   : " + \
                         str(port_info['port_cap']['port_enabled']) + "\n" + \
                    "Max speed (gbps)  : " + \
                        str(port_info['port_cap']['max_speed']/1e9) + "\n" \
                    "Full duplex       : " + \
                        str(port_info['port_cap']['full_duplex']) + "\n" + \
                    "Total tx bytes    : " + \
                        str(port_info['total_tx_bytes']) + "\n" + \
                    "Total rx bytes    : " + \
                        str(port_info['total_rx_bytes']) + "\n" + \
                    "Total tx packets  : " + \
                        str(port_info['total_tx_packets']) + "\n" + \
                    "Total rx packets  : " + \
                        str(port_info['total_rx_packets']) + "\n" + \
                    "Total tx packets dropped : " + \
                        str(port_info['total_tx_packets_dropped']) + "\n" + \
                    "Total rx packets dropped : " + \
                        str(port_info['total_rx_packets_dropped']) + "\n" + \
                    "Total tx errors : " + \
                        str(port_info['total_tx_errors']) + "\n" + \
                    "Total rx errors : " + \
                        str(port_info['total_rx_errors']) + "\n" + \
                    "Delta tx bytes   : " + \
                        str(port_info['delta_tx_bytes']) + "\n" + \
                    "Delta rx bytes   : " + \
                        str(port_info['delta_rx_bytes']) + "\n" + \
                     "Delta tx packets : " + \
                        str(port_info['delta_tx_packets']) + "\n" + \
                     "Delta rx packets : " + \
                        str(port_info['delta_rx_packets']) + "\n" + \
                     "Delta tx packets dropped : " + \
                        str(port_info['delta_tx_packets_dropped']) + "\n" + \
                     "Delta rx packets dropped : " + \
                        str(port_info['delta_rx_packets_dropped']) + "\n" + \
                     "Delta tx errors : " + \
                        str(port_info['delta_tx_errors']) + "\n" + \
                     "Delta rx errors : " + \
                        str(port_info['delta_rx_errors']) + "\n"
            
            self.infoDisplay.append(snapshot)
        else:
            # Uknown reply
            self.infoDisplay.append( "Query results came back: %s" % \
                                     ( str(replyMsg) ) )
        
    def update_stats(self, utils):
        '''
        Updates link stats from dispatch_server message
        '''
        self.stats = {}
        for util in utils:
            dpid = util["dpid"]
            while len(dpid)<12:
                dpid = "0" + dpid
            self.stats[(dpid, util["port"])] = util["utilization"]
        self.topoWidget.topologyView.updateAllSignal.emit()
        
    def link_color(self, link):
        '''
        Paints links based on their utilizations
        '''
        srcID = link.source.id
        srcPort = link.sport
        dstID = link.dest.id
        dstPort = link.dport

        if not (srcID, srcPort) in self.stats and \
                not (dstID, dstPort) in self.stats:
            return QtCore.Qt.white

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
        if util >= 0.3:
            return QtCore.Qt.yellow
        if util >= 0.0001:
            return QtCore.Qt.green
        return QtCore.Qt.gray

    def link_pattern(self, link):
        return QtCore.Qt.SolidLine
        
    def node_color(self, node):
        return QtGui.QColor(QtCore.Qt.green)
        
    def show_topology_reply( self, topoMsg ):
        if topoMsg.subset_name == "serviceA" or \
                topoMsg.subset_name == "serviceB":
            print( "got topo for service" )
            # Only do something for these two specific services
            self.service_name = topoMsg.subset_name
            self.service_subset.clear()
            # Fill in service nodes
            for item in topoMsg.nodes:
                #print( "adding service item %d" % (item.dpid) )
                self.service_subset.add( item.dpid )
        else:
            print( "got full topo" )
            self.service_subset.clear()

        # Force a re-paint
        self.topoWidget.topologyView.updateAll()
        
    def intToDottedIP(self, intip):
        octet = ''
        for exp in [3,2,1,0]:
            octet = octet + str(intip / ( 256 ** exp )) + "."
            intip = intip % ( 256 ** exp )
        return(octet.rstrip('.'))        
        
    def showInfo(self):
        self.buttons[0].setChecked(True)

        msgBox = QtGui.QMessageBox()
        msgBox.setWindowTitle("Monitoring View")
        msgBox.setText("Monitoring visualizes switch and link health/status "+\
            "information (e.g., switch flow tables, link utilizations, packet"+\
            " drops/errors, etc.)")
        msgBox.exec_()
