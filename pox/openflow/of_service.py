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
This is a messenger service for interacting with OpenFlow.

There are lots of things that aren't implemented.  Please add!

There's now a simple webservice based on this.  If you add
functionality here, you might want to see about adding it to
the webservice too.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.messenger import *
import sys
import traceback
from pox.openflow.of_json import *
from pox.lib.util import dpidToStr,strToDPID


log = core.getLogger()

def _type_str (m):
  return of.ofp_type_map.get(m.header_type, str(m.header_type))


def _ofp_entry (event):
  ofp = event.ofp
  if isinstance(ofp, list):
    ofp = ofp[0];
  m = { 'xid' : ofp.xid,
        'dpid' : dpidToStr(event.connection.dpid),
        'type_str' : _type_str(ofp),
        'header_type' : ofp.header_type,
      }
  return m


class OFBot (ChannelBot):
  def _init (self, extra):
    self.enable_packet_ins = False
    self.oflisteners = core.openflow.addListeners(self)

  def _destroyed (self):
    core.openflow.removeListeners(self.oflisteners)

  def _handle_ConnectionUp (self, event):
    #self.send(_ofp_entry(event))
    m = { 'type_str' : 'ConnectionUp', 'dpid' : dpidToStr(event.dpid) }
    self.send(m)

  def _handle_ConnectionDown (self, event):
    m = { 'type_str' : 'ConnectionDown', 'dpid' : dpidToStr(event.dpid) }
    self.send(m)

  def _handle_BarrierIn (self, event):
    self.send(_ofp_entry(event))

  def _handle_ErrorIn (self, event):
    m = { 'type' : event.ofp.type, 'code' : event.ofp.code,
          'msg' : event.asString(),
        }
    m.update(_ofp_entry(event))
    self.send(m)

  def _handle_SwitchDescReceived (self, event):
    m = _ofp_entry(event)
    m['switch_desc'] = switch_desc_to_dict(event.stats)
    self.send(m)

  def _handle_FlowStatsReceived (self, event):
    m = _ofp_entry(event)
    m['flow_stats'] = flow_stats_to_list(event.stats)
    self.send(m)

  def _handle_PacketIn (self, event):
    if not self.enable_packet_ins: return
    if len(self.channel._members) == 0: return
    m = { 'buffer_id' : event.ofp.buffer_id,
          'total_len' : event.ofp._total_len,
          'in_port' : event.ofp.in_port,
          'reason' : event.ofp.reason,
          #'data' : event.data,
        }
    m['payload'] = fix_parsed(event.parsed)
    m.update(_ofp_entry(event))

#    import json
#    try:
#      json.dumps(m,indent=2)
#    except:
#      print json.dumps(m,encoding="latin1",indent=2)

    self.send(m)


  def _exec_cmd_packet_out (self, event):
    try:
      msg = event.msg
      dpid = strToDPID(msg['dpid'])
      con = core.openflow.getConnection(dpid)
      if con is None:
        raise RuntimeError("No such switch")
      po = dict_to_packet_out(msg)
      con.send(po)

    except:
      log.exception("Exception in packet_out")
      self.reply(event,
                 exception="%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]),
                 traceback=traceback.format_exc())

  def _exec_cmd_get_flow_stats (self, event):
    try:
      msg = event.msg
      dpid = strToDPID(msg['dpid'])
      con = core.openflow.getConnection(dpid)
      if con is None:
        raise RuntimeError("No such switch")

      match = event.msg.get('match')
      table_id = event.msg.get('table_id', 0xff)
      out_port = event.msg.get('out_port', of.OFPP_NONE)

      sr = of.ofp_stats_request()
      sr.body = of.ofp_flow_stats_request()
      if match is None:
        match = of.ofp_match()
      else:
        match = dict_to_match(match)
      sr.body.match = match
      sr.body.table_id = table_id
      sr.body.out_port = out_port
      con.send(sr)
      self.reply(event,**{'type':'set_table','xid':sr.xid})

    except:
      #log.exception("Exception in get_flow_stats")
      log.debug("Exception in get_flow_stats - %s:%s",
                sys.exc_info()[0].__name__,
                sys.exc_info()[1])
      self.reply(event,
                 exception="%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]),
                 traceback=traceback.format_exc())

  def _exec_cmd_set_table (self, event):
    try:
      msg = event.msg
      dpid = strToDPID(msg['dpid'])
      con = core.openflow.getConnection(dpid)
      if con is None:
        raise RuntimeError("No such switch")

      xid = of.generate_xid()

      fm = of.ofp_flow_mod()
      fm.xid = xid
      fm.command = of.OFPFC_DELETE
      con.send(fm)
      bar = of.ofp_barrier_request()
      bar.xid = xid
      con.send(bar)

      for flow in msg.get('flows',[]):
        fm = dict_to_flow_mod(flow)
        fm.xid = xid

        con.send(fm)
        #con.send(of.ofp_barrier_request(xid=xid))
      con.send(of.ofp_barrier_request(xid=xid))

      self.reply(event,**{'type':'set_table','xid':xid})

    except:
      #log.exception("Exception in set_table")
      log.debug("Exception in set_table - %s:%s",
                sys.exc_info()[0].__name__,
                sys.exc_info()[1])
      self.reply(event,
                 exception="%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]),
                 traceback=traceback.format_exc())

  #TODO: You should actually be able to configure packet in messages...
  #      for example, enabling raw data of the whole packet, and
  #      raw of individual parts.
  def _exec_packetins_True (self, event):
    self.enable_packet_ins = True

  def _exec_packetins_False (self, event):
    self.enable_packet_ins = False

  def _exec_cmd_list_switches (self, event):
    r = list_switches()
    self.send(switch_list = r)


def launch (nexus = "MessengerNexus"):
  def _launch ():
    # Make invitable
    core.MessengerNexus.default_bot.add_bot(OFBot)

    # Just stick one in a channel
    OFBot("of_01")

    # For now, just register something arbitrary so that we can use
    # this for dependencies
    core.register(nexus + "_of_service", object())

  core.call_when_ready(_launch, [nexus, "openflow"])
