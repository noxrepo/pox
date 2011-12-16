# Copyright 2011 Kyriakos Zarifis
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

################################################################################
# API NOTES:
#
# Command:
# Classes that inherit Command are the actual packets that are sent to switches
# in order to instruct them to perform some actions. For some, there are helper
# functions that build AND send suck a packet to a switch. A user can either:
# 1) create a Command object, edit it and then send it, using sendCommand(), or
# 2) for common operations, directly call a helper method that sends a Command.
# For example:
#       command = ofcommand.FloodPacketCommand(inport, packet, buf, bufid)
#       ...
#       ofcommand.sendCommand(con, command)
# is equal to:
#       ofcommand.floodPacket(con, inport, packet, buf, bufid)
#
#
# Action:
# Classes that inherit Action are used with Commands that add/edit/modify flows.
###########################################################################

import struct
import pox.openflow.libopenflow_01 as of
from pox.openflow import *

from pox.lib.packet.tcp       import tcp
from pox.lib.packet.udp       import udp
from pox.lib.packet.vlan      import vlan
from pox.lib.packet.ipv4      import ipv4
from pox.lib.packet.icmp      import icmp
from pox.lib.packet.ethernet  import ethernet

MAX_BUFID = 4294967295
FLOW_TIMEOUT = 5

class Command():
  """Base class for commands(packets) sent to OF switches by the controller
  """
  def __init__(self):
    #self.header = ofp_header()
    # This is the raw data that should be sent to the switch:
    self.packedCommand = ""

# Packet Sending API    
class PacketOutCommand(Command):
  """Base class for packet used to tell a switch to send out a packet
  """
  def __init__(self):
    self.packet_out = of.ofp_packet_out()
    self.action = of.ofp_action_output()
      
class SendPacketCommand(PacketOutCommand): 
  """Packet telling a switch to send a packet out a port
  """
  
class MulticastPacketCommand(PacketOutCommand): 
  """Packet telling a switch to send a packet out a set of its ports
  """

class FloodPacketCommand(PacketOutCommand):
  """Packet telling a switch to flood a packet_out
  """
  def __init__(self, inport, packet, buf, bufid=None):
    PacketOutCommand.__init__(self)
    self.action.len = 8
    self.action.port = of.OFPP_FLOOD
    
    self.packet_out.in_port = inport
    self.packet_out.actions_len = len(self.action.pack())
    
    self.packet_out.actions.append(self.action)
    self.packet_out.header.length = self.packet_out.actions_len + 16
    
    if bufid >= 0 and bufid < MAX_BUFID: #check
      self.packet_out.buffer_id = bufid
      self.packedCommand = self.packet_out.pack()
    else:
      self.packet_out.header.length += len(buf)
      self.packedCommand = self.packet_out.pack() + buf.tostring()
    
def sendPacket(con, inport, packet, buf, bufid=None):
  """Send a packet out a single port on a switch
  """
  # TODO: there is no `outport` variable defined here... o
  #       what does is it supposed to refer to?
  sendCommand(con, SendPacketCommand(inport, outport, packet, buf, bufid))
  print con, "sent packet"
  
def multicastPacket(con, inport, outports, packet, buf, bufid=None):
  """Flood a packet on a switch
  """
  sendCommand(con, MulticastPacketCommand(inport, outports, packet, buf, bufid))
  print con, "multicasted packet"
  
def floodPacket(con, inport, packet, buf, bufid=None):
  """Flood a packet on a switch
  """
  sendCommand(con, FloodPacketCommand(inport, packet, buf, bufid))
  print con, "flooded packet"
  
  
# Flow Table Modification API
class Action():
  """Base class for a flow entry action
  """
  def __init__(self):
    self.type = 0
    self.len = 0
  
class Output(Action):
  def __init__(self, outport):
    super(Output,self).__init__()
    self.type = of.OFPAT_OUTPUT
    self.len = 8
    self.port = outport
    self.max_len = 0
    
  def toOfpAction(self):
    ofpAction = of.ofp_action_output()
    ofpAction.type = self.type
    ofpAction.len = self.len
    ofpAction.port = self.port
    ofpAction.max_len = self.max_len
    return ofpAction
#Add rest of actions here...

class FlowModCommand(Command):
  """Base class for packet used to tell a switch to modify its flow table
    (add/delete flow entry)
  """
  def __init__(self, bufid):
    super(FlowModCommand, self).__init__()    
    if bufid == None: bufid = MAX_BUFID
    self.flow_mod = of.ofp_flow_mod()
   

class AddFlowEntryCommand(FlowModCommand):
  """Packet used to tell a switch to add an entry to its flow table
  """
  def __init__(self, flowEntry, bufid):
    super(AddFlowEntryCommand, self).__init__(bufid)    
      
    self.flow_mod.buffer_id = bufid
    self.flow_mod.idle_timeout = FLOW_TIMEOUT
    self.flow_mod.hard_timeout = of.OFP_FLOW_PERMANENT
    self.flow_mod.command = of.OFPFC_ADD
    self.flow_mod.header.length = len(self.flow_mod)
    
    self.flow_mod.match = flowEntry.match.ofp_match
    
    self.flow_mod.actions = []
    for action in flowEntry.actions:
      self.flow_mod.actions.append(action.toOfpAction())
      self.flow_mod.header.length += action.len
    
    self.packedCommand = self.flow_mod.pack()
    #print self.flow_mod.show()
    
def modifyFlow(con, inport, packet, buf, bufid=None):
  """Modify a switch's flow table
  """
  command = FlowModCommand(inport, packet, buf, bufid)
  sendCommand(con, command)
  
def addFlowEntry(con, inport, match, actions, bufid=None):
  """Add a new flow entry in a switch's flow table
  """
  flowEntry = FlowEntry(match, actions)
  flowEntry.match.setInport(inport)
  command = AddFlowEntryCommand(flowEntry, bufid)
  sendCommand(con, command)
  
def sendCommand(con, command):
  """Send a Command to a switch
  """
  if not isinstance(command, Command):
    print "Attempted to call sendCommand() with object of type different than Command'"
    return
  con.sock.send(command.packedCommand)
    
           
class FlowEntry():
  """Represents a flow entry in the flow table of a switch
  """
  def __init__(self, match=None, actions=None):
    if(match):
      self.match = match
    else:
      self.match  = Match()
    # list containing ordered Action objects
    self.actions = []
    for action in actions:
      self.addAction(action)
  
  def setMatch(self, match):
    pass
  
  def getMatch(self):
    return self.match
  
  def addAction(self, action):
    if not isinstance(action, Action):
      print "attempted to attempt action that is not of type Action"
      return
    self.actions.append(action)
      
class Match():
  """Wrapper around ofp_match
  """
  def __init__(self, match=None):
    if(match):
      self.ofp_match = match
      #self.initWildcards()
    else:
      self.ofp_match = of.ofp_match()
  
  def setInport(self, inport):
    self.ofp_match.in_port = inport
    self.ofp_match.wildcards ^= of.OFPFW_IN_PORT

# Move to packet_utils
def extractMatch(ethernet):
    """
    Extracts and returns flow attributes from the given 'ethernet' packet.
    The caller is responsible for setting IN_PORT itself.
    """
    match = of.ofp_match()
    match.wildcards = of.OFPFW_ALL
    #match.dl_src = ethernet.src.tolist()
    #match.dl_dst = ethernet.dst.tolist()
    match.dl_src = bytearray(ethernet.src)
    match.dl_dst = bytearray(ethernet.dst)
    match.dl_type = ethernet.type
    p = ethernet.next

    if isinstance(p, vlan):
        match.dl_vlan = p.id
        match.dl_vlan_pcp = p.pcp
        p = p.next
    else:
        match.dl_vlan = 0xffff # XXX should be written OFP_VLAN_NONE

    if isinstance(p, ipv4):
        match.nw_src = p.srcip
        match.nw_dst = p.dstip
        match.nw_proto = p.protocol
        p = p.next

        if isinstance(p, udp) or isinstance(p, tcp):
            match.tp_src = p.srcport
            match.tp_dst = p.dstport
        else:
            if isinstance(p, icmp):
                match.tp_src = p.type
                match.tp_dst = p.code                
    return Match(match)
