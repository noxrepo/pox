# Copyright 2011,2012 James McCauley
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

"""
Various stuff for converting between OpenFlow and JSON-friendly
data structures.

Lots of stuff could be improved and the naming is pretty awful.
"""

from pox.lib.util import fields_of,is_scalar
import pox.openflow.libopenflow_01 as of

def _fix_of_int (n):
  if isinstance(n, str):
    return getattr(of, n, None)
  return n

from pox.lib.packet import ethernet, ipv4
from pox.lib.packet.packet_utils import ethtype_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr

def _fix_ethertype (n):
  if isinstance(n, str):
    try:
      if n.startswith("802.3/"):
        n = n.split("/",1)[1]
      v = int(n, 16)
      return v
    except:
      pass
    if not n.endswith("_TYPE"):
      n += "_TYPE"
    return getattr(ethernet, n)
  return n

def _fix_proto (n):
  if isinstance(n, str):
    if not n.endswith("_PROTOCOL"):
      n += "_PROTOCOL"
    return getattr(ipv4, n)
  return n

from pox.lib.addresses import parse_cidr, EthAddr

def _fix_eth (n):
  if n is None: return None
  return EthAddr(n)

def _fix_ip (n):
  if n is None: return n
  return parse_cidr(n, infer = False)

import socket

def _fix_port (n):
  if isinstance(n, str):
    return socket.getservbyname(n)
  return n

def dict_to_match (jm):
  m = of.ofp_match()
  m.in_port = _fix_of_int(jm.get('in_port'))
  m.dl_src = _fix_eth(jm.get('dl_src'))
  m.dl_dst = _fix_eth(jm.get('dl_dst'))
  if 'dl_vlan'     in jm: m.dl_vlan     = jm['dl_vlan']
  if 'dl_vlan_pcp' in jm: m.dl_vlan_pcp = jm['dl_vlan_pcp']
  m.dl_type = _fix_ethertype(jm.get('dl_type'))
  if 'nw_tos'      in jm: m.nw_tos      = jm['nw_tos']
  m.nw_proto = _fix_proto(jm.get('nw_proto'))
  m.nw_src = _fix_ip(jm.get('nw_src'))
  m.nw_dst = _fix_ip(jm.get('nw_dst'))
  m.tp_src = _fix_port(jm.get('tp_src'))
  m.tp_dst = _fix_port(jm.get('tp_dst'))
  #print jm,"\n",m
  return m

def _unfix_null (v):
  return v
def _unfix_port (v):
  return of.ofp_port_map.get(v, v)
def _unfix_ip (v):
  v = v()
  if v[1] == 0:
    if v[0] is None: return None
    return str(v[0])
  return "%s/%i" % v
def _unfix_str (v):
  return str(v)
def _unfix_ethertype (v):
  if v <= 0x05dc:
    return v
  #NOTE: This may just result in a hex string.  In that case, we might
  #      want to just use a number.
  return ethtype_to_str(v)

_unfix_map = {k:_unfix_null for k in of.ofp_match_data.keys()}
_unfix_map['in_port'] = _unfix_port
_unfix_map['dl_src'] = _unfix_str
_unfix_map['dl_dst'] = _unfix_str
_unfix_map['dl_type'] = _unfix_ethertype
_unfix_map['get_nw_src'] = _unfix_ip
_unfix_map['get_nw_dst'] = _unfix_ip

def match_to_dict (m):
  d = {}
  #TODO: Use symbolic names
  for k,func in _unfix_map.items():
    v = getattr(m, k)
    if v is None: continue
    if k.startswith('get_'): k = k[4:]
    v = func(v)
    if v is None: continue
    d[k] = v
  return d


def action_to_dict (a):
  d = {}
  d['type'] = of.ofp_action_type_map.get(a.type, a.type)
  for k,v in fields_of(a).items():
    if k in ['type','length']: continue
    if k == "port":
      v = of.ofp_port_map.get(v,v)
    d[k] = v
  return d


def dict_to_action (d):
  d = d.copy()
  if 'port' in d:
    d['port'] = _fix_of_int(d['port'])

  t = d['type'].upper()
  del d['type']
  if not t.startswith("OFPAT_"): t = "OFPAT_" + t
  t = of.ofp_action_type_rev_map[t]
  cls = of._action_type_to_class[t]
  a = cls(**d)
  return a


def flow_stats_to_list (flowstats):
  """
  Takes a list of flow stats
  """
  stats = []
  for stat in flowstats:
    s = {}
    stats.append(s)
    for k,v in fields_of(stat).items():
      if k == 'length': continue
      if k.startswith('pad'): continue
      if k == 'match': v = match_to_dict(v)
      elif k == 'actions':
        v = [action_to_dict(a) for a in v]
      s[k] = v
  return stats


def switch_desc_to_dict (desc):
  """
  Takes ofp_desc_stats response
  """
  r = {}
  for k in ['mfr_desc','hw_desc','sw_desc','serial_num','dp_desc']:
    r[k] = getattr(desc, k)
  return r


def dict_to_flow_mod (flow):
  match = flow.get('match')
  if match is None:
    match = of.ofp_match()
  else:
    match = dict_to_match(match)

  actions = flow.get('actions', [])
  if not isinstance(actions, list): actions = [actions]
  actions = [dict_to_action(a) for a in actions]
  if 'output' in flow:
    a = of.ofp_action_output(port=_fix_of_int(flow['output']))
    po.actions.append(a)

  fm = of.ofp_flow_mod(match = match)
  fm.actions = actions

  for k in ['cookie','idle_timeout','hard_timeout','priority']:
    if k in flow:
      setattr(fm, k, flow[k])

  return fm


import pox.lib.packet as packetlib
valid_packet_types = {}
def _init ():
  candidates = [x for x in dir(packetlib) if x.isalpha()]
  good = set()
  for c in candidates:
    if c.lower() not in candidates: continue
    if c.upper() not in candidates: continue
    valid_packet_types[c.lower()] = getattr(packetlib, c.lower())
_init()

def dict_to_packet (d, parent=None):
  if isinstance(d, list):
    d = b''.join(chr(x) for x in data)
  if isinstance(d, str):
    return d

  payload = d.get('payload')
  d = d.copy()

  assert d['class'] in valid_packet_types
  cls = valid_packet_types[d['class']]
  example = cls()
  del d['class']

  for k,v in d.items():
    assert not k.startswith('_')
    assert hasattr(example, k)
    assert k not in ['prev','next','raw','parsed']

  o = cls(prev=parent,**d)

  if payload is not None:
    o.payload = dict_to_packet(payload, o)

  return o


from pox.lib.packet.packet_base import packet_base

def fix_parsed (m):
  """
  Translate parsed packet data to dicts and stuff
  """
  if m is None:
    return {"type":"raw","data":[]}
  if isinstance(m, str):
    return {"type":"raw","data":[ord(b) for b in m]}
  assert isinstance(m, packet_base)
  if not m.parsed:
    u = fix_parsed(m.raw)
    u['unparsed_type'] = m.__class__.__name__
    return u
  r = {}
  for k,v in fields_of(m, primitives_only = False).items():
    if is_scalar(v):
      r[k] = v
    elif isinstance(v, (IPAddr, EthAddr)):
      r[k] = str(v)
  if hasattr(m, "payload"):
    r['payload'] = fix_parsed(m.payload)
  if 'raw' in r:
    #r['raw'] = [ord(b) for b in m['raw']]
    del r['raw']
  if 'next' in r: del r['next']
  r['type'] = m.__class__.__name__
  return r


def dict_to_packet_out (d):
  """
  Converts dict to packet_out
  Also, special key "output" is an output port.
  """
  po = of.ofp_packet_out()
  po.buffer_id = d.get('buffer_id', -1)
  po.in_port = _fix_of_int(d.get('in_port', of.OFPP_NONE))
  actions = d.get('actions', [])
  actions = [dict_to_action(a) for a in actions]
  po.actions = actions
  if 'output' in d:
    a = of.ofp_action_output(port=_fix_of_int(d['output']))
    po.actions.append(a)

  if 'data' in d:
    data = dict_to_packet(d['data'])
    if hasattr(data, 'pack'):
      data = data.pack()
    po.data = data

  return po


def list_switches (ofnexus = None):
  if ofnexus is None:
    from pox.core import core
    ofnexus = core.openflow

  r = []
  for dpid,con in ofnexus._connections.items():
    ports = []
    for p in con.ports.values():
      pdict = {
        'port_no':p.port_no,
        'hw_addr':str(p.hw_addr),
        'name':p.name}
      for bit,name in of.ofp_port_config_map.items():
        if p.config & bit:
          pdict[name.split('OFPPC_', 1)[-1].lower()] = True
      for bit,name in of.ofp_port_state_map.items():
        if p.state & bit:
          pdict[name.split('OFPPS_', 1)[-1].lower()] = True
      ports.append(pdict)
    ports.sort(key=lambda item:item['port_no'])

    rr = {
          'dpid':dpidToStr(dpid),
          'n_tables':con.features.n_tables,
          'ports':ports}
    r.append(rr)

  r.sort(key=lambda item:item['dpid'])
  return r
