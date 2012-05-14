# Copyright 2011 James McCauley
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

"""
Various NOM utility functions
"""
from pox.core import core
from pox.topology.topology import Switch, Host
import json

def saveNOM(target="nom"):
  jsonNOM = buildjsonNOM()
  f = open(target, 'w')
  json.dump(jsonNOM, f)
  
def loadNOM(source="nom"):
  f = open(source, 'r')
  jsonNOM = json.load(f)
  return jsonNOM

def buildjsonNOM():
  # Create a JSON message describing the NOM
  jsonNOM = {}
  switches = []
  # make sure core.topology is running
  for sw in core.topology.getEntitiesOfType(Switch):
    rules = []
    for rule in sw.flow_table.entries:
      match = {}
      match['nw_proto'] = rule.match.nw_proto
      match['wildcards'] = rule.match.wildcards
      match['dl_type'] = rule.match.dl_type
      if rule.match.dl_src:
        match['dl_src'] = rule.match.dl_src.toInt()
      if rule.match.dl_dst:
        match['dl_dst'] = rule.match.dl_dst.toInt()
      if rule.match.nw_src:
        match['nw_src'] = rule.match.nw_src.toUnsigned()
      if rule.match.nw_src:
       match['nw_dst'] = rule.match.nw_dst.toUnsigned()
      match['in_port'] = rule.match.in_port
      match['tp_src'] = rule.match.tp_src
      match['tp_dst'] = rule.match.tp_dst
      match['dl_vlan'] = rule.match.dl_vlan
      match['dl_vlan_pcp'] = rule.match.dl_vlan_pcp
      match['nw_tos'] = rule.match.nw_tos
      
      actions = []
      for a in rule.actions:
        actions.append({"type":a.type, "port":a.port})
        
      rules.append({"match": match, "actions":actions}) 
    switches.append({"dpid":sw.dpid, "rules":rules})
  
  jsonNOM["switches"] = switches
  hosts = []
  for host in core.topology.getEntitiesOfType(Host):
    pass
    #hosts.append(host.mac) NOT IMPLEMENTED (missing host tracker functionality)
  jsonNOM["hosts"] = hosts
  return jsonNOM