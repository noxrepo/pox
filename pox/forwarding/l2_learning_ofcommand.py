from time import time

from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.tcp           import tcp
from pox.lib.packet.udp           import udp
from pox.lib.packet.vlan          import vlan
from pox.lib.packet.ipv4          import ipv4
from pox.lib.packet.icmp          import icmp
from pox.lib.packet.ethernet      import ethernet

from pox.core import core
from pox.lib.revent import *
from pox.lib.addresses import EthAddr

log = core.getLogger()

import pox.openflow.ofcommand as ofcommand

class dumb_l2_switch (EventMixin):
  def __init__ (self):
    log.info("Starting")
    self.listenTo(core)
    self.st = {}
    
  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
        
  def _handle_PacketIn (self, event):
    """Packet entry method.
    Drop LLDP packets (or we get confused) and attempt learning and forwarding
    """
    con = event.connection
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parse()
    buffer_id = event.ofp.buffer_id
    
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return
  
    if not con in self.st:
      log.info('registering new switch ' + str(dpid))
      self.st[con] = {}
  
    # don't forward lldp packets
    if packet.type == ethernet.LLDP_TYPE:
      return
  
    # learn MAC on incoming port
    self.do_l2_learning(con, inport, packet)
    # forward packet
    self.forward_l2_packet(con, inport, packet, packet.arr, buffer_id)
      
  def do_l2_learning(self, con, inport, packet):
    """Given a packet, learn the source and peg to a switch/inport 
    """
    # learn MAC on incoming port
    srcaddr = EthAddr(packet.src)
    #if ord(srcaddr[0]) & 1:
    #  return
    if self.st[con].has_key(srcaddr.toStr()):   # change to raw?
      # we had already heard from this switch
      dst = self.st[con][srcaddr.toStr()]            # raw?
      if dst[0] != inport:
        # but from a different port
        log.info('MAC has moved from '+str(dst)+'to'+str(inport))
      else:
        return
    else:
      log.info('learned MAC '+srcaddr.toStr()+' on Switch %s, Port %d'% (con.dpid,inport))
      
    # learn or update timestamp of entry
    self.st[con][srcaddr.toStr()] = (inport, time(), packet)           # raw?
  
    # Replace any old entry for (switch,mac).
    #mac = mac_to_int(packet.src)
  
  def forward_l2_packet(self, con, inport, packet, buf, bufid):   
    """If we've learned the destination MAC set up a flow and
    send only out of its inport.  Else, flood.
    """
    dstaddr = EthAddr(packet.dst)
    #if not ord(dstaddr[0]) & 1 and  # what did this do?
    if self.st[con].has_key(dstaddr.toStr()):   # raw?
      prt = self.st[con][dstaddr.toStr()]                          # raw?
      if  prt[0] == inport:
        log.warning('**warning** learned port = inport')
        ofcommand.floodPacket(con, inport, packet, buf, bufid)
  
      else:
        # We know the outport, set up a flow
        log.info('installing flow for ' + str(packet))
        match = ofcommand.extractMatch(packet)
        actions = [ofcommand.Output(prt[0])]
        ofcommand.addFlowEntry(con, inport, match, actions, bufid)
        # Separate bufid, make addFlowEntry() only ADD the entry
        # send/wait for Barrier
        # sendBufferedPacket(bufid)
    else:    
      # haven't learned destination MAC. Flood 
      ofcommand.floodPacket(con, inport, packet, buf, bufid)
      
      
    
    
    
    
    
    
    
    
    
'''
add arp cache timeout?
# Timeout for cached MAC entries
CACHE_TIMEOUT = 5

def timer_callback():
  """Responsible for timing out cache entries. Called every 1 second.
  """ 
  global st
  curtime = time()
  for con in st.keys():
    for entry in st[con].keys():
      if (curtime - st[con][entry][1]) > CACHE_TIMEOUT:
        con.msg('timing out entry '+mac_to_str(entry)+" -> "+str(st[con][entry][0])+' on switch ' + str(con))
        st[con].pop(entry)
'''
