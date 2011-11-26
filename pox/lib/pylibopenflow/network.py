"""This module holds the network.

Copyright(C) 2009, Stanford University
Date October 2009
Created by ykk
"""
import random
import pox.lib.pylibopenflow.openflow as openflow

class network:
    """Class holding information about OpenFlow network
    """
    def __init__(self):
        """Initialize
        """
        ##List of switches
        self.switches = []
        ##Dictionary of links
        self.links = {}
        ##Reference to connections
        self.connections = openflow.connections()

    def add_switch(self, sw):
        """Add switch to network
        """
        self.switches.append(sw)
        self.connections.add_connection(sw, sw.connection)

    def add_link(self, link):
        """Add link to network
        """
        try:
            self.links[link.switch1,link.switch2].append(link)
        except KeyError:
            self.links[link.switch1,link.switch2] = []
            self.links[link.switch1,link.switch2].append(link)

class link:
    """Class to hold information about link

    Copyright(C) 2009, Stanford University
    Date November 2009
    Created by ykk
    """
    def __init__(self, switch1, switch2):
        """Initialize link between specified switches
        """
        ##Reference to first switch
        self.switch1 = switch1
        ##Reference to second switch
        self.switch2 = switch2

class switch:
    """Class holding information about OpenFlow switch

    Copyright(C) 2009, Stanford University
    Date October 2009
    Created by ykk
    """
    def __init__(self, miss_send_len=128,
                 sock=None, dpid=None, n_buffers=100, n_tables=1,
                 capability=None):
        """Initialize switch
        """
        ##Socket to controller
        self.sock = sock
        ##Datapath id of switch
        if (dpid != None):
            self.datapath_id = dpid
        else:
            self.datapath_id = random.randrange(1, pow(2,64))
        ##Number of buffers
        self.n_buffers = n_buffers
        ##Number of tables
        self.n_tables= n_tables
        ##Capabilities
        if (isinstance(capability, switch_capabilities)):
            self.capability = capability
        else:
            self.capability = switch_capabilities(miss_send_len)
        ##Valid Actions
        self.valid_actions = 0
        ##List of port
        self.port = []

class switch_capabilities:
    """Class to hold switch capabilities
    """
    def __init__(self, miss_send_len=128):
        """Initialize

        Copyright(C) 2009, Stanford University
        Date October 2009
        Created by ykk
        """
        ##Capabilities support by datapath
        self.flow_stats = True
        self.table_stats = True
        self.port_stats = True
        self.stp = True
        self.multi_phy_tx = True
        self.ip_resam = False
        ##Switch config
        self.send_exp = None
        self.ip_frag = 0
        self.miss_send_len = miss_send_len
        ##Valid actions
        self.act_output = True
        self.act_set_vlan_vid = True
        self.act_set_vlan_pcp = True
        self.act_strip_vlan = True
        self.act_set_dl_src = True
        self.act_set_dl_dst = True
        self.act_set_nw_src = True
        self.act_set_nw_dst = True
        self.act_set_tp_src = True
        self.act_set_tp_dst = True
        self.act_vendor = False

    def get_capability(self, ofmsg):
        """Return value for uint32_t capability field
        """
        value = 0
        if (self.flow_stats):
            value += ofmsg.get_value("OFPC_FLOW_STATS")
        if (self.table_stats):
            value += ofmsg.get_value("OFPC_TABLE_STATS")
        if (self.port_stats):
            value += ofmsg.get_value("OFPC_PORT_STATS")
        if (self.stp):
            value += ofmsg.get_value("OFPC_STP")
        if (self.multi_phy_tx):
            value += ofmsg.get_value("OFPC_MULTI_PHY_TX")
        if (self.ip_resam):
            value += ofmsg.get_value("OFPC_IP_REASM")
        return value

    def get_actions(self, ofmsg):
        """Return value for uint32_t action field
        """
        value = 0
        if (self.act_output):
            value += (1 << (ofmsg.get_value("OFPAT_OUTPUT")+1))
        if (self.act_set_vlan_vid):
            value += (1 << (ofmsg.get_value("OFPAT_SET_VLAN_VID")+1))
        if (self.act_set_vlan_pcp):
            value += (1 << (ofmsg.get_value("OFPAT_SET_VLAN_PCP")+1))
        if (self.act_strip_vlan):
            value += (1 << (ofmsg.get_value("OFPAT_STRIP_VLAN")+1))
        if (self.act_set_dl_src):
            value += (1 << (ofmsg.get_value("OFPAT_SET_DL_SRC")+1))
        if (self.act_set_dl_dst):
            value += (1 << (ofmsg.get_value("OFPAT_SET_DL_DST")+1))
        if (self.act_set_nw_src):
            value += (1 << (ofmsg.get_value("OFPAT_SET_NW_SRC")+1))
        if (self.act_set_nw_dst):
            value += (1 << (ofmsg.get_value("OFPAT_SET_NW_DST")+1))
        if (self.act_set_tp_src):
            value += (1 << (ofmsg.get_value("OFPAT_SET_TP_SRC")+1))
        if (self.act_set_tp_dst):
            value += (1 << (ofmsg.get_value("OFPAT_SET_TP_DST")+1))
        return value

class port:
    """Class to hold information about port
    
    Copyright(C) 2009, Stanford University
    Date October 2009
    Created by ykk
    """
    def __init__(self, port_no, stp=(2 << 8), hw_addr=None, name=""):
        """Initialize
        """
        ##Port properties
        self.port_no = port_no
        if (hw_addr != None):
            self.hw_addr = hw_addr
        else:
            self.hw_addr = random.randrange(1, pow(2,48))
        self.name = name
        ##Port config
        self.port_down = False
        self.no_stp = False
        self.no_recv = False
        self.no_recv_stp = False
        self.no_flood = False
        self.no_fwd = False
        self.no_packet_in = False
        #Port state
        self.link_down = False
        self.stp = stp
