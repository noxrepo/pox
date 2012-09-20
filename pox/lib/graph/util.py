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
from pox.lib.graph.nom import Switch, Host, Link
#from pox.lib.addresses import *
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
  # make sure core.topology is running

  # Add Switches
  switches = []
  for sw in core.topology.getEntitiesOfType(Switch):
    rules = []
    for rule in sw.flow_table.entries:
      match = {}
      encode_match(rule.match, match)

      actions = []
      for a in rule.actions:
        actions.append({"type":a.type, "port":a.port})

      rules.append({"match": match, "actions":actions})
    switches.append({"dpid":sw.dpid, "rules":rules})

  jsonNOM["switches"] = switches

  # Add Hosts
  hosts = []
  for host in core.topology.getEntitiesOfType(Host):
    hosts.append({"mac":host.mac.toStr()})
  jsonNOM["hosts"] = hosts

  # Add Links
  links = []
  for link in core.topology.getEntitiesOfType(Link):
    links.append({"node1":link.node1, "port1":link.port1,\
                  "node2":link.node2,"port2":link.port2})
  jsonNOM["links"] = links
  return jsonNOM


def encode_host(host):
  pass

def encode_match(match, dictionary):
  dictionary['nw_proto'] = match.nw_proto
  dictionary['wildcards'] = match.wildcards
  dictionary['dl_type'] = match.dl_type
  if match.dl_src:
    dictionary['dl_src'] = match.dl_src.toInt()
  if match.dl_dst:
    dictionary['dl_dst'] = match.dl_dst.toInt()
  if match.nw_src:
    dictionary['nw_src'] = match.nw_src.toUnsigned()
  if match.nw_src:
    dictionary['nw_dst'] = match.nw_dst.toUnsigned()
  dictionary['in_port'] = match.in_port
  dictionary['tp_src'] = match.tp_src
  dictionary['tp_dst'] = match.tp_dst
  dictionary['dl_vlan'] = match.dl_vlan
  dictionary['dl_vlan_pcp'] = match.dl_vlan_pcp
  dictionary['nw_tos'] = match.nw_tos

class NOMEncoder(json.JSONEncoder):
  jsontypes = (dict, list, tuple, str, unicode, int, long, float, True,
                 False, None)

  def default(self, obj, visited=None, level=None):
    # Convert objects to a dictionary of their representation
    if not visited:
      visited = []
    if id(obj) in visited and not type(obj) in self.jsontypes:
      return
    else:
      visited.append(id(obj))
    d = {'__class__':obj.__class__.__name__,'__module__':obj.__module__,}
    # We have to special case ofp_match, since it has some crazy bearded
    # wizard magic with private member variables
    if d['__class__'] == 'ofp_match':
      encode_match(obj, d)
    else:
      for k, v in obj.__dict__.items():
        if k[0] == '_':
          continue
        f = [x for x in visited if isinstance(x, type(v)) and not type(v) in self.jsontypes]
        if id(v) not in f:
          d[k] = v if (type(v) in self.jsontypes or v == None) else self.default(v, visited)
          visited.append(id(v))
    return d

import importlib

class NOMDecoder(json.JSONDecoder):

  def __init__(self):
    json.JSONDecoder.__init__(self, object_hook=self.dict_to_object)

  def dict_to_object(self, d):
    if '__class__' in d:
      class_name = d.pop('__class__')
      module_name = d.pop('__module__')
      module = importlib.import_module(module_name)
      class_ = getattr(module, class_name)
      #print 'CLASS:', class_
      args = dict( (key.encode('ascii'), value) for key, value in d.items())
      #print 'INSTANCE ARGS:', args
      inst = class_(**args)
    else:
      inst = d
    return inst
