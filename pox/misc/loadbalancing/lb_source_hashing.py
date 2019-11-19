# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from pox.lib.addresses import IPAddr
from pox.openflow.libopenflow_01 import ofp_phy_port
from math import floor

"""
Turns your complex OpenFlow switches into stupid hubs.

There are actually two hubs in here -- a reactive one and a proactive one.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.revent import *
from pox.lib.packet.lldp import management_address
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
import struct
from pox.lib.addresses import *
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer


import time

log = core.getLogger()

FLOW_IDLE_TIMEOUT = 10

class ClientDetail():
    def __init__ (self, sysName, sysIP,sysMac, sysPortName, switchPort): 
      self.sysName=sysName
      self.sysMac=sysMac
      self.sysPortName=sysPortName       
      self.sysIP=sysIP 
      self.switchPort=switchPort

    def get_sysName(self):
        return self.sysName
    
    def get_sysMac(self):
        return self.sysMac
    
    def get_sysPortName(self):
        return self.sysPortName
    
    def get_sysIP(self):
        return self.sysIP
    
    def get_switchPort(self):
        return self.switchPort


'''      
class ClientKey():
    def __init__ (self, machine,live_servers):
      self.clientMachine=machine
      self.lbservers=live_servers
      #for lbkey, lbval in live_servers.iteritems():
      #  self.lbservers[lbkey]=lbval    
      log.debug("new client key created.")  
'''
class Machine():
    def __init__ (self, ip, mac, port):
      self.ip=ip
      self.mac=mac      
      self.port=port

class FlowMatch():
    def __init__ (self, serverMachine, idleTime, hardTime):
      self.serverMachine=serverMachine      
      self.idleTime=idleTime
      self.hardTime=hardTime

class ClientFlow():
    #def __init__ (self, clientEntry, flowMatch):
    def __init__ (self, clientMachine, flowMatch):
      #self.clientkey=clientkey
      self.clientMachine=clientMachine
      self.flowMatch=flowMatch
  
class MyHub():

  ARP_TIMER = 1
  LLDP_TIMER = 1
  TIMER_SET = 0

  #def __init__ (self, connection,service_ip, servers=[], clientip="", mode="active", arpTimer=0, lldpTimer=1):
  def __init__ (self, connection,service_ip, servers=[], mode="active", arpTimer=0, lldpTimer=1):
    #self.listenTo(core.openflow) 
    #core.openflow_discovery.addListeners(self, ) 

    if arpTimer==MyHub.ARP_TIMER and lldpTimer==MyHub.LLDP_TIMER:
        log.debug("You have set arpTimer and lldpTimer parameters to 1. Both parameter cannot be 1, change one parameter to 0 on the launch function.")
        return
    
    self.con = connection
    self.service_ip = IPAddr(service_ip)
    self.service_mac = self.con.eth_addr
                       
    #self.service_mac = EthAddr("08:00:27:50:b2:2c")
    self.servers = [IPAddr(a) for a in servers]
    
    
    #self.clientip=IPAddr(clientip)
    #self.clientip={}
    #now = time.time()
    #self.clientip[connection.dpid][IPAddr(clientip)]={"cTime",now}
    
    
    self.live_servers = {} # IP -> MAC,port
    self.controllerPrt = None
    self.dpid = connection.dpid
    self.clientFlow = {}
    self.clientFlow[connection.dpid] = {}
    
    log.debug("Module started succesfully") 
    self.server_timeout = 60*60 #7
    self.arp_timeout = 7
    self.arpTimer=arpTimer
    self.lldpTimer=lldpTimer
    self.flow_idle_time=10
    self.flow_hard_time=15
    
    #self.arp_timeout = 3
    #self.probe_cycle_time = 5
    #self.outstanding_probes = {}
    self.arpcnt=0
    
    
      
      
  #perform arp only once, when the system starts. 
  #the arp floods all port but the incoming port.
  #after all arp requests are captured, the system
  #uses lldp packets to capture live_server events.
  #this is done to reduce the number of packets sent
  #on the network since arp floods all ports.     
  def arp_request(self, s, protosrc, hwsrc):

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST       #destination mac address => ff:ff:ff:ff:ff:ff
    r.protodst = s                  #destination ip
    #r.hwsrc = self.con.eth_addr     #switch mac address
    r.hwsrc = hwsrc     #switch mac address
    #r.protosrc = self.service_ip    #switch ip
    r.protosrc = protosrc    #switch ip
    e = ethernet(type=ethernet.ARP_TYPE, src=hwsrc, #src=self.con.eth_addr,
                         dst=ETHER_BROADCAST)
    e.set_payload(r)
    log.debug("ARPing for %s", s.toStr())
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    #self.resend_packet(packet_in, of.OFPP_ALL)
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

  def arp_reply(self, packet, inport):
        p=packet.next
        
        r = arp()
        r.hwtype = p.hwtype
        r.prototype = p.prototype
        r.hwlen = p.hwlen
        r.protolen = p.protolen
        r.opcode = arp.REPLY
        r.hwdst = p.hwsrc
        r.protodst = p.protosrc
        r.protosrc = p.protodst
        #r.hwsrc = self.arpTable[dpid][a.protodst].mac
        r.hwsrc = self.service_mac
        e = ethernet(type=packet.type, src=self.service_mac, dst=p.hwsrc)
        e.set_payload(r)
        log.debug("%i %i answering ARP for %s" % (self.dpid, inport, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = inport
        self.con.send(msg)


  def _handle_ConnectionUp (self, event):  
  
    #msg=of.ofp_flow_mod(match=of.ofp_match(),command=of.OFPFC_DELETE)
    #event.connection.send(msg)

    #this is the port for poxbr:65534 at all times.    
    prtCnt = len(self.con.ports)  
    #find controller portnum 
    for i in range(1, prtCnt):         
        prt=self.con.ports[i]
        prtName=prt.name
        prtNum=prt.port_no        
        log.debug("ovs port name: %s - ovs port num: %s: ", prtName, prtNum)
        if prtName == "vpcontroller":
            self.controllerPrt=prtNum
    
    #for s in self.servers:
    #    self.arp_request(s, self.service_ip, self.con.eth_addr)    
    
    self.build_switch_arp_table()   
           

  #Remove dead servers 
  def expired_servers(self):
    
    if len(self.live_servers) == 0:
        return
    
    now = time.time()
    
    for sIP,prop in self.live_servers.items():
        if self.live_servers[sIP]['serverTm'] + self.server_timeout < now:
            log.info('server %s expired %s', sIP, self.live_servers[sIP])
            self.live_servers.pop(sIP)
        else:    
            log.debug("server %s is up : %s", sIP, self.live_servers[sIP])
      
      
  def build_switch_arp_table(self):

    #loop through all servers and teach them the switch mac address  
    for s in self.servers:
        self.arp_request(s, self.service_ip, self.con.eth_addr)
        
    #teach the client the switch mac address
    #self.arp_request(self.clientip, self.service_ip, self.con.eth_addr)
        
        
  #handle lldp packets      
  def lldp_packets(self, packet, inport): 
      log.debug("LLDP packets")
      log.debug("Time: %s", time.time())
      
      lldp_p = packet.payload
      
      sysName = lldp_p.tlvs[3].payload
      sysPortName = lldp_p.tlvs[8].payload
      sysMac = packet.src
      sysIP = IPAddr(lldp_p.tlvs[6].address)
            
      self.add_server(sysIP, sysMac, inport)
      
  def add_server(self, sysIP, sysMac, inport):

    log.debug("checking ip %s in liveservers", sysIP)
    if sysIP not in self.live_servers and sysIP in self.servers:
        addedtime = time.time()        
        self.live_servers[sysIP]={"serverMac" : sysMac, "serverPrt" : inport, "serverTm" : addedtime}                
        log.debug("server added to liveserver %s at %s", sysIP, addedtime)
        #self.arpTimer
        #Timer(self.server_timeout, self.expired_servers_for_lldp, recurring=True)
        return
    elif sysIP in self.live_servers and sysIP in self.servers:
        #update server time
        log.debug("server old record %s", self.live_servers[sysIP])
        now=time.time()
        server=self.live_servers[sysIP]['serverTm']=now
        log.debug("server new record %s", self.live_servers[sysIP])
        return
    elif sysIP not in self.servers:
          log.debug("lb server is invalid %s", sysIP) 
          return         
    else:
        log.debug("server %s already exist in liveserver", sysIP)
        return      

  def drop (self, buffer_id, port):
      # Kill the buffer
      if buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = buffer_id
        #event.ofp.buffer_id = None # Mark is dead
        msg.in_port = port
        self.connection.send(msg)
            
  def sourceHashing(self, cip):
      clientip=cip.toStr().split(".")
    
      #ipx=1
      #while(ipx<=255): 
        #log.debug("*************************************************************************")
        #log.debug("ipx %s", ipx)
      
      #clientip=["192","168","0", str(ipx)]
      clientipOctal = [int(i) for i in clientip] 
      
      clientOctalMul=1      
      for clientOctal in clientipOctal: 
          if clientOctal is not 0:
              clientOctalMul = clientOctalMul*clientOctal
      
      #log.debug("clientOctalMul %s", clientOctalMul)    
      
      serverOctalMul=1
      serverval=1
      iplastOctal={}
      heightsserverip=0
      for serverip,detail in self.live_servers.items():
          serveripstr=serverip.toStr().split(".")
          serveripOctal = [int(i) for i in serveripstr] 
          iplastOctal[serveripOctal[3]]=serverip
          if heightsserverip<serveripOctal[3]:
             heightsserverip=serveripOctal[3]
          
          #loop through all server ip and multiply their octal val
          serverOctalMul=1
          for oct in serveripOctal:
              if oct is not 0:
                  serverOctalMul = serverOctalMul*oct   
              
          serverval=serverval*serverOctalMul          
          #log.debug("serverOctalMul %s", serverOctalMul)
          #log.debug("serverval %s", serverval)
          
      #add the client ip octal and the servers ip octal    
      ipval=clientOctalMul*serverval
      
      #load balancing server cnt
      lbservercnt=len(self.live_servers)
      
      #get the last 3 digits of your client and servers ip octal computed above      
      i=1
      modVal=1
      while i <=  lbservercnt:
          modVal=modVal*10
          i=i+1
      
      ipmod=ipval%1000
      #ipmod=ipval%modVal
      
      if ipmod ==0:
        ipmod=1
      
      #if octal is greater than 255, loop until is less/equal to 255
      if ipmod > 255:
          while (ipmod>255):
              ipmod=ipmod/lbservercnt
        
      #1, 64, 128, 254   
      #log.debug("ipmod %s", ipmod)
      
      #sort the server ip list in ascending order
      iplastOctalsorted={}
      iplastOctalsorted=sorted(iplastOctal.keys())
      #for i in iplastOctalsorted:
        #print for visual confirmation.        
        #log.debug("server ip key: %s - server ip: %s", i, iplastOctal[i].toStr())
              
        
      '''      
      255/lbservercnt=85
      1,85,170,255
      '''
      lbserverkey=0
      if len(iplastOctalsorted) > 0:
          lowip=1 
          heighip=iplastOctalsorted[0]
          i=0
          while(True):
            #if the computed octal falls under an ip range, that is your lb server ip to be used for source hashing.  
            if lowip<=ipmod and ipmod<=heighip:
                lbserverkey=heighip
                #log.debug("ipx %s : ipmod %s : Server %s", ipx, ipmod, iplastOctal[lbserverkey].toStr())
                #log.debug("%s : %s : %s", ipx, ipmod, iplastOctal[lbserverkey].toStr())
                #log.debug("ipx %s : ipmod %s : Server %s", ipx, ipmod, iplastOctal[lbserverkey].toStr())
                #log.debug("server handler request %s", iplastOctal[lbserverkey].toStr())                
                return iplastOctal[lbserverkey]                
                #break;
            else:
               if i+1 >= len(iplastOctalsorted):
                   #log.debug("ipx %s : ipmod %s : Server %s", ipx, ipmod, iplastOctal[lbserverkey].toStr())
                   #log.debug("%s : %s : %s", ipx, ipmod, iplastOctal[iplastOctalsorted[i]]  )
                   #log.debug("ipx %s : ipmod %s : Server %s", ipx, ipmod, iplastOctal[lbserverkey].toStr())
                   #log.debug("server handler request %s", iplastOctal[lbserverkey].toStr())
                   return iplastOctal[iplastOctalsorted[i]]           
                   #break;        
               lowip= int(iplastOctal[iplastOctalsorted[i]].toStr().split(".")[3])              
               heighip=iplastOctalsorted[i+1]
            i=i+1
            
      #ipx=ipx+1        
      #for l,v in iplastOctalsorted[i].items():
    
    
      log.debug("end source hasing")
    
    
  def _handle_PacketIn (self, event):
    
    inport = event.port
    packet = event.parsed
    packet_in = event.ofp
    
    now = time.time()
    log.debug("current time is: %s", now)
    
    #check is lldp packet
    if packet.type == ethernet.LLDP_TYPE and self.arpTimer != MyHub.ARP_TIMER:
        log.debug("capturing lldp packet")
        self.lldp_packets(packet, inport)        
        if MyHub.TIMER_SET == 0 and self.lldpTimer==MyHub.LLDP_TIMER:
            MyHub.TIMER_SET = 1
            Timer(self.server_timeout, self.expired_servers, recurring=True)
            
        #self.drop(event.ofp.buffer_id,event.port)
    #elif packet.type == arp.PROTO_TYPE_IP:  # ethernet.ARP_TYPE:    
    elif isinstance(packet.next, arp) and self.lldpTimer != MyHub.LLDP_TIMER: 
        #a.prototype == arp.PROTO_TYPE_IP
        #if packet.dst.is_multicast:
        p=packet.next
        if p.opcode == arp.REQUEST and p.protosrc in self.live_servers:  
            log.debug("capturing arp request packet for:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            log.debug("Arp request from ip: %s", p.protosrc.toStr())
            self.arp_reply(packet, inport)
            return
        
        #you received an arp reply, update the liveserver time for the current server ip
        if p.opcode == arp.REPLY:        
            log.debug("capturing arp reply packet for:99999999999999999999999999999999999")
            log.debug("src ip %s src mac %s", p.protosrc, p.hwsrc)
            log.debug("dst ip %s dst mac %s", p.protodst, p.hwdst)
            #function arp_request performs arp requests on all network machines every x time. 
            #the reply is captured here and added to self.live_servers on function add_server()
            self.add_server(p.protosrc, p.hwsrc, inport)      
            if MyHub.TIMER_SET == 0 and self.arpTimer == MyHub.ARP_TIMER:
                MyHub.TIMER_SET = 1                
                #this function will issue arp request as a loop
                Timer(self.arp_timeout, self.build_switch_arp_table, recurring=True)
                #this function will check for stale servers and remove old servers. 
                #Timer(self.server_timeout, self.expired_servers, recurring=True)
                
            log.debug("Arp reply ip: %s", p.protosrc.toStr())
            if p.protosrc == IPAddr("192.168.0.2"):
                log.debug("stop")
                
                #for sIP,prop in self.live_servers.items():        
                #    if p.protodst == self.live_servers[sIP]['serverTm'] :
                #      latestServer = self.live_servers[sIP]['serverTm']
                
                        
                if self.live_servers.get(p.protodst) is not None:
                    lbs = self.live_servers[p.protodst]
                    lbsprt=lbs['serverPrt']
                else:
                    lbs=self.service_ip
                    lbsprt=of.OFPP_LOCAL
                    
                if lbs is not None:
                
                    #handlerservermac=self.live_servers[lbs]['serverMac'] 
                    
                                    
                    msg = of.ofp_packet_out()
                    #msg.data = event.ofp
                    #msg.data = event.parsed.payload                    
                    msg.data = packet_in                        
                    action = of.ofp_action_output(port = lbsprt)
                    msg.actions.append(action)
                    #msg.in_port = of.OFPP_NONE
                    msg.in_port = inport
                    event.connection.send(msg) 
                    log.debug("sending %s mac to %s", p.protosrc, p.protodst)
                    
            log.debug("end arp reply")
        
    #tcp packet
    elif packet.type == ethernet.IP_TYPE and packet.next.protocol == packet.next.TCP_PROTOCOL:        
        dstip=packet.next.dstip
        dstmac=packet.dst
        dstport=packet.next.next.dstport
        srcip=packet.next.srcip
        srcmac=packet.src
        
        #tcp packet response
        #if dstip != self.service_ip and self.clientFlowEntry is not None and len(self.live_servers) > 0: 
        if dstip != self.service_ip and len(self.live_servers) > 0 and dstip not in self.live_servers:

            packet = event.parsed
            
            if len(self.clientFlow[self.con.dpid]) == 0:
                log.debug("**********************Did not know how to handle this request.**********************")
                return;
                
            
            clientIP=packet.next.dstip            
            if self.clientFlow[self.con.dpid][clientIP] is None:
                log.debug("**********************Client flow was removed and cannot continue**********************")
                return
            
            
            clientMac=self.clientFlow[self.con.dpid][clientIP].clientMachine.mac
            clientport=self.clientFlow[self.con.dpid][clientIP].clientMachine.port
                   
            actions = []
            actions.append(of.ofp_action_dl_addr.set_src(self.con.eth_addr))
            actions.append(of.ofp_action_dl_addr.set_dst(clientMac))
            #actions.append(of.ofp_action_nw_addr.set_dst(serverMachine.ip.toStr())
            actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
            actions.append(of.ofp_action_output(port = 3))
            match = of.ofp_match.from_packet(packet, inport)
            
            '''
              actions.append(of.ofp_action_dl_addr.set_src(self.mac))
              actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
              actions.append(of.ofp_action_output(port = entry.client_port))
              match = of.ofp_match.from_packet(packet, inport)
            '''
            
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=FLOW_IDLE_TIMEOUT*6*6,
                                  hard_timeout=of.OFP_FLOW_PERMANENT,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            self.con.send(msg)            
            
            log.debug("Responding from server*********************************")
            #log.debug("action settings:")
            #log.debug("self.mac %s", self.service_mac)
            #log.debug("self.service_ip %s", self.service_ip)
            #log.debug("entry.client_port %s", 2)
            #log.debug("inport %s", inport)
            #log.debug("event.ofp %s", event.ofp)
            #log.debug("incomming packet: %s", packet)
            #log.debug("match %s", match)
            #log.debug("msg %s", msg)
            
            log.debug("222222222222222222222222222222222222222")
            
        #tcp packet request
        
        #elif dstip == self.service_ip and self.clientFlowEntry is not None and len(self.live_servers) > 0: 
        elif dstip == self.service_ip and len(self.live_servers) > 0:
            
            packet = event.parsed
            now = time.time()
            latestServer = now-60*60
            
            '''
            for sIP,prop in self.live_servers.items():        
                if latestServer > self.live_servers[sIP]['serverTm'] :
                    latestServer = self.live_servers[sIP]['serverTm']
                    handlerserver = sIP
                    
               
                DEBUG:forwarding.MyHub:ovs port name: enp2s0 - ovs port num: 1: 
                DEBUG:forwarding.MyHub:ovs port name: vpclient - ovs port num: 2: 
                DEBUG:forwarding.MyHub:ovs port name: vpcontroller - ovs port num: 3: 
                DEBUG:forwarding.MyHub:ovs port name: vpserver1 - ovs port num: 4: 
                DEBUG:forwarding.MyHub:ovs port name: vpserver3 - ovs port num: 5: 
                DEBUG:forwarding.MyHub:ovs port name: vpserver2 - ovs port num: 6: 
            '''
            
            clientip=packet.payload.srcip
            clientmac=packet.src
            clientport=inport
            clientMachine=Machine(clientip, clientmac, clientport)
            
            
            #there are no flow entries at all saved
            if len(self.clientFlow[self.dpid]) == 0:                
                sIP=self.sourceHashing(clientip)
                sIPDetails=self.live_servers[sIP]       
                servermac=sIPDetails['serverMac'] 
                serverPort=sIPDetails['serverPrt']
                idleTime=self.flow_idle_time
                hardTime=self.flow_hard_time                                
                serverMachine=Machine(sIP, servermac, serverPort)                
                flowMatch=FlowMatch(serverMachine, idleTime, hardTime)                
                self.clientFlow[self.con.dpid][clientip]= ClientFlow(clientMachine, flowMatch)
                log.debug("lb server handling request %s - 66666666666666666666666666666666666666666666666666666", sIP.toStr())
                #(self.clientFlow[self.con.dpid][IPAddr("192.168.0.6")]).
            
            
            elif len(self.clientFlow[self.dpid]) > 0:
                
                #if the client placed request and the flow entry is in the clientFlow table.
                key=self.clientFlow[self.con.dpid].get(clientip)
                if key is not None:
                    clientFlow=self.clientFlow[self.con.dpid][clientip]
                    if clientFlow is not None:
                        flowMatch=clientFlow.flowMatch
                        if flowMatch is not None:
                            serverMachine=flowMatch.serverMachine
                            sIP=serverMachine.ip
                            sIPDetails=self.live_servers[sIP]      
                            servermac=serverMachine.mac 
                            serverPort=serverMachine.port
                            log.debug("lb server handling request %s - 77777777777777777777777777777776666666666666666666666", sIP.toStr())
                else:
                    log.debug("empty key. insert to list.")                        
                    sIP=self.sourceHashing(clientip)
                    sIPDetails=self.live_servers[sIP]       
                    servermac=sIPDetails['serverMac'] 
                    serverPort=sIPDetails['serverPrt']
                    idleTime=self.flow_idle_time
                    hardTime=self.flow_hard_time                                
                    serverMachine=Machine(sIP, servermac, serverPort)                
                    flowMatch=FlowMatch(serverMachine, idleTime, hardTime)                
                    self.clientFlow[self.con.dpid][clientip]= ClientFlow(clientMachine, flowMatch)
                    log.debug("lb server handling request %s - 88888888888888888888888888888886666666666666666666666", sIP.toStr())
                 
                 #there are no flow entries saved for the client
                 

            log.debug("IP packets !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

            packet = event.parsed
            
            actions = []
            actions.append(of.ofp_action_dl_addr.set_dst(serverMachine.mac.toStr())) #dst server to handle request: mac
            actions.append(of.ofp_action_nw_addr.set_dst(serverMachine.ip.toStr()))    #dst server to handle request: ip
            actions.append(of.ofp_action_output(port = serverMachine.port))  #dst server to handle request:sw prt
            match = of.ofp_match.from_packet(packet, inport)                #inport => event.port

             
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=flowMatch.idleTime*6*6,
                                  hard_timeout=of.OFP_FLOW_PERMANENT,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            self.con.send(msg)
                             
            log.debug("Request from server+++++++++++++++++++++++++++++++++++")
            #log.debug("action settings:")
            #log.debug("mac %s", servermac.toStr())
            
            #log.debug("entry.server %s", sIP.toStr())
            #log.debug("inport %s", inport)
            #log.debug("port %s", serverPort)      
            #log.debug("event.ofp %s", event.ofp)
            #log.debug("incomming packet: %s", packet)
            #log.debug("match %s", match)
            #log.debug("msg %s", msg)
                    
            log.debug("33333333333333333333333333333333333333")      
        
    else:
        log.debug("another type of traffic")     
        

          
    #log.debug("Be a reactive hub by flooding every incoming packet!!!!!!!!!!!!!!!!!!!!!")
    #msg = of.ofp_packet_out()
    #msg.data = event.ofp
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    #event.connection.send(msg)


def launch (reactive = False):
      
  def start_myhub (event):
      log.debug("Controlling %s" % (event.connection,))
      #MyHub(event.connection)
                                                                                                                  #mode="learning"
      core.registerNew(MyHub, event.connection, service_ip="192.168.0.11", servers=["192.168.0.64","192.168.0.128","192.168.0.192","192.168.0.254"], mode="active", arpTimer=1, lldpTimer=0)
      #core.registerNew(MyHub, event.connection, service_ip="192.168.0.11", servers=["192.168.0.1","192.168.0.64","192.168.0.128","192.168.0.254"], clientip="192.168.0.6", mode="active", arpTimer=1, lldpTimer=0)
      #core.registerNew(MyHub, event.connection, service_ip="192.168.0.11", servers=["192.168.0.7","192.168.0.13"], clientip="192.168.0.6", mode="active", arpTimer=1, lldpTimer=0)
      #core.MyHub.con = event.connection
      event.connection.addListeners(core.MyHub)
      
  core.openflow.addListenerByName("ConnectionUp", start_myhub)
  
  


