"""This module parses OpenFlow packets.

Unfortunately, this has to be updated manually for each OpenFlow version
and packet type.  Ugly.

(C) Copyright Stanford University
Date October 2009
Created by ykk
"""
class parser:
    """Parser for  OpenFlow packets
    
    (C) Copyright Stanford University
    Date October 2009
    Created by ykk
    """
    def __init__(self, messages):
        """Initialize
        """
        ##Internal reference to OpenFlow messages
        self.__messages = messages

    def describe(self, packet):
        """Parse OpenFlow packet and return string description
        """
        dic = self.__messages.peek_from_front("ofp_header", packet)
        desc = self.header_describe(dic)
        if (dic["type"][0] == self.__messages.get_value("OFPT_HELLO")):
            pass
        elif (dic["type"][0] == self.__messages.get_value("OFPT_SET_CONFIG")):
            desc += "\n\t"+self.switch_config_describe(packet)
        elif (dic["type"][0] == self.__messages.get_value("OFPT_FLOW_MOD")):
            (fmdic, remaining) = self.__messages.unpack_from_front("ofp_flow_mod", packet)
            desc += self.flow_mod_describe(fmdic, "\n\t")
            desc += "\n\twith remaining "+str(len(remaining))+" bytes"
        else:
            desc += "\n\tUnparsed..."
        return desc

    def flow_mod_describe(self, packet, prefix=""):
        """Parse flow mod and return description
        """
        dic = self.__assert_dic(packet, "ofp_flow_mod")
        if (dic == None):
            return ""
        return prefix+\
               "Flow_mod of command "+self.__messages.get_enum_name("ofp_flow_mod_command", dic["command"][0])+\
               " idle/hard timeout:"+str(dic["idle_timeout"][0])+"/"+str(dic["hard_timeout"][0])+\
               self.match_describe(dic, "match.", "\n\t")+\
               prefix+\
               "(priority:"+str(dic["priority"][0])+\
               "/buffer id:"+str(dic["buffer_id"][0])+\
               "/out port:"+str(dic["out_port"][0])+")"

    def match_describe(self, dic, nameprefix="", prefix=""):
        """Return description for ofp match
        """
        return prefix+"match wildcards:%x" % dic[nameprefix+"wildcards"][0]+\
               " inport="+str(dic[nameprefix+"in_port"][0])+\
               prefix+"     "+\
               " ethertype="+str(dic[nameprefix+"dl_type"][0])+\
               " vlan="+str(dic[nameprefix+"dl_vlan"][0])+\
               " "+self.eth_describe(dic[nameprefix+"dl_src"])+"->"+\
               self.eth_describe(dic[nameprefix+"dl_dst"])+\
               prefix+"     "+\
               " ipproto="+str(dic[nameprefix+"nw_proto"][0])+\
               " "+self.ip_describe(dic[nameprefix+"nw_src"][0])+\
               "->"+self.ip_describe(dic[nameprefix+"nw_src"][0])+\
               prefix+"     "+\
               " transport "+str(dic[nameprefix+"tp_src"][0])+\
               "->"+str(dic[nameprefix+"tp_dst"][0])
               
    def switch_config_describe(self, packet):
        """Parse OpenFlow switch config and return description
        """
        dic = self.__assert_dic(packet, "ofp_switch_config")
        if (dic == None):
            return ""
        return "with flag "+str(self.__messages.get_enum_name("ofp_config_flags", dic["flags"][0]))+\
               " and miss send length "+str(dic["miss_send_len"][0])
        
    def header_describe(self, packet):
        """Parse OpenFlow header and return string description
        """
        dic = self.__assert_dic(packet, "ofp_header")
        if (dic == None):
            return ""
        return self.__messages.get_enum_name("ofp_type", dic["type"][0])+" packet "+\
               "(length:"+str(dic["length"][0])+\
               "/xid:"+str(dic["xid"][0])+")"

    def ip_describe(self, value):
        """Return string for ip address
        """
        desc = ""
        for i in range(0,4):
            (value, cv) = divmod(value, 256)
            desc = str(cv).strip() +"." + desc
        return desc
    
    def eth_describe(self, etheraddr):
        """Return string for ethernet address
        """
        desc = ""
        for value in etheraddr:
            desc += ":"+("%x" % value).zfill(2)
        return desc[1:]

    def __assert_dic(self, packet, typename):
        """Assert and ensure dictionary is given
        """
        dic = None
        if (isinstance(packet, str)):
            dic = self.__messages.peek_from_front(typename, packet)
        elif (isinstance(packet, dict)):
            dic = packet
        return dic
