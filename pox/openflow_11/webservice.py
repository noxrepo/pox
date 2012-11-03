# Copyright 2012 James McCauley
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
A simple JSON-RPC-ish web service for interacting with OpenFlow.

This is not incredibly robust or performant or anything.  It's a demo.
It's derived from the of_service messenger service, so see it for some
more details.  Also, if you add features to this, please think about
adding them to the messenger service too.

Current commands include:
  set_table
    Sets the flow table on a switch.
    dpid - a string dpid
    flows - a list of flow entries
  get_switch_desc
    Gets switch details.
    dpid - a string dpid
  get_flow_stats
    Get list of flows on table.
    dpid - a string dpid
    match - match structure (optional, defaults to match all)
    table_id - table for flows (defaults to all)
    out_port - filter by out port (defaults to all)
  get_switches
    Get list of switches and their basic info.

Example - Make a hub:
curl -i -X POST -d '{"method":"set_table","params":{"dpid":
 "00-00-00-00-00-01","flows":[{"actions":[{"type":"OFPAT_OUTPUT",
 "port":"OFPP_ALL"}],"match":{}}]}}' http://127.0.0.1:8000/OF/
"""

import sys
from pox.lib.util import dpidToStr, strToDPID, fields_of
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.of_json import *
from pox.web.jsonrpc import JSONRPCHandler, make_error
import threading

log = core.getLogger()


class OFConRequest (object):
  """
  Superclass for requests that send commands to a connection and
  wait for responses.
  """
  def __init__ (self, con, *args, **kw):
    self._response = None
    self._sync = threading.Event()
    self._aborted = False
    self._listeners = None
    self._con = con
    #self._init(*args, **kw)
    core.callLater(self._do_init, args, kw)

  def _do_init (self, args, kw):
    self._listeners = self._con.addListeners(self)
    self._init(*args, **kw)

  def _init (self, *args, **kw):
    #log.warn("UNIMPLEMENTED REQUEST INIT")
    pass

  def get_response (self):
    if not self._sync.wait(5):
      # Whoops; timeout!
      self._aborted = True
      self._finish()
      raise RuntimeError("Operation timed out")
    return self._response

  def _finish (self, value = None):
    if self._response is None:
      self._response = value
    self._sync.set()
    self._con.removeListeners(self._listeners)

  def _result (self, key, value):
    self._finish({'result':{key:value,'dpid':dpidToStr(self._con.dpid)}})


class OFSwitchDescRequest (OFConRequest):
  def _init (self):
    sr = of.ofp_stats_request()
    sr.type = of.OFPST_DESC
    self._con.send(sr)
    self.xid = sr.xid

  def _handle_SwitchDescReceived (self, event):
    if event.ofp.xid != self.xid: return
    r = switch_desc_to_dict(event.stats)
    self._result('switchdesc', r)

  def _handle_ErrorIn (self, event):
    if event.ofp.xid != self.xid: return
    self._finish(make_error("OpenFlow Error", data=event.asString()))


class OFFlowStatsRequest (OFConRequest):
  def _init (self, match=None, table_id=0xff, out_port=of.OFPP_NONE):
    sr = of.ofp_stats_request()
    sr.body = of.ofp_flow_stats_request()
    if match is None:
      match = of.ofp_match()
    else:
      match = dict_to_match(match)
    sr.body.match = match
    sr.body.table_id = table_id
    sr.body.out_port = out_port
    self._con.send(sr)
    self.xid = sr.xid

  def _handle_FlowStatsReceived (self, event):
    if event.ofp[0].xid != self.xid: return
    stats = flow_stats_to_list(event.stats)

    self._result('flowstats', stats)

  def _handle_ErrorIn (self, event):
    if event.ofp.xid != self.xid: return
    self._finish(make_error("OpenFlow Error", data=event.asString()))


class OFSetTableRequest (OFConRequest):

  def clear_table (self, xid = None):
    fm = of.ofp_flow_mod()
    fm.xid = xid
    fm.command = of.OFPFC_DELETE
    self._con.send(fm)
    bar = of.ofp_barrier_request()
    bar.xid = xid
    self._con.send(bar)
    #TODO: Watch for errors on these

  def _init (self, flows = []):
    self.done = False

    xid = of.generate_xid()
    self.xid = xid
    self.clear_table(xid=xid)

    self.count = 1 + len(flows)

    for flow in flows:
      fm = dict_to_flow_mod(flow)
      fm.xid = xid

      self._con.send(fm)
      self._con.send(of.ofp_barrier_request(xid=xid))

  def _handle_BarrierIn (self, event):
    if event.ofp.xid != self.xid: return
    if self.done: return
    self.count -= 1
    if self.count <= 0:
      self._result('flowmod', True)
      self.done = True

  def _handle_ErrorIn (self, event):
    if event.ofp.xid != self.xid: return
    if self.done: return
    self.clear_table()
    self.done = True
    self._finish(make_error("OpenFlow Error", data=event.asString()))


class OFRequestHandler (JSONRPCHandler):

  def _exec_set_table (self, dpid, flows):
    dpid = strToDPID(dpid)
    con = core.openflow.getConnection(dpid)
    if con is None:
      return make_error("No such switch")

    return OFSetTableRequest(con, flows).get_response()

  def _exec_get_switch_desc (self, dpid):
    dpid = strToDPID(dpid)
    con = core.openflow.getConnection(dpid)
    if con is None:
      return make_error("No such switch")

    return OFSwitchDescRequest(con).get_response()

  def _exec_get_flow_stats (self, dpid, *args, **kw):
    dpid = strToDPID(dpid)
    con = core.openflow.getConnection(dpid)
    if con is None:
      return make_error("No such switch")

    return OFFlowStatsRequest(con, *args, **kw).get_response()

  def _exec_get_switches (self):
    return {'result':list_switches()}



def launch (username='', password=''):
  def _launch ():
    cfg = {}
    if len(username) and len(password):
      cfg['auth'] = lambda u, p: (u == username) and (p == password)
    core.WebServer.set_handler("/OF/",OFRequestHandler,cfg,True)

  core.call_when_ready(_launch, ["WebServer","openflow"],
                       name = "openflow.webservice")
