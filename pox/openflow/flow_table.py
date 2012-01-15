#!/usr/bin/env python
"""
Implementation of an OpenFlow flow table

@author: Colin Scott (cs@cs.berkeley.edu)

"""
from collections import namedtuple
from libopenflow_01 import *

# FlowTable Entries (immutable):
#   match - ofp_match (13-tuple)
#   counters - hash from name -> count. May be stale
#   actions - ordered list of ofp_action_*s to apply for matching packets
class TableEntry (namedtuple('TableEntry', 'priority cookie idle_timeout hard_timeout match counters actions')):
  def __new__(cls, priority=OFP_DEFAULT_PRIORITY, cookie = 0, idle_timeout=0, hard_timeout=0, match=ofp_match(), counters={}, actions=[]):
    return super(TableEntry,cls).__new__(cls, priority, cookie, idle_timeout, hard_timeout, match, counters, actions)

  @staticmethod
  def from_flow_mod(flow_mod):
    priority = flow_mod.priority
    cookie = flow_mod.cookie
    match = flow_mod.match
    counters = {
    }

    actions = flow_mod.actions
    # TODO: More metadata? e.g., out_port, priority, flags
    return TableEntry(priority, cookie, flow_mod.idle_timeout, flow_mod.hard_timeout, match, counters, actions)

  def to_flow_mod(self, **kw):
    return ofp_flow_mod(priority = self.priority, cookie = self.cookie, match = self.match,
                        idle_timeout = self.idle_timeout, hard_timeout = self.hard_timeout,
                        actions = self.actions, **kw)

class FlowTable (object):
  """
  General model of a flow table. Maintains a list of flow entries, and finds
  matching entries for fields and other entries.
  """
  def __init__(self):
    # For now we represent the table as a multidimensional array.
    #
    # [ (cookie, match, counters, actions),
    #   (cookie, match, counters, actions),
    #    ...                        ]
    # 
    # Implies O(N) lookup for now. TODO: fix
    self._table = []

  def process_flow_removed(self, flow_removed):
    """ process a flow removed event -- remove the matching flow from the table. """
    for flow in self._table:
      if(flow_removed.match == flow.match and flow_removed.cookie == flow.cookie):
        self._table.remove(flow)
        return

  def add_entry(self, entry):
    if not isinstance(entry, TableEntry):
      raise "Not an Entry type"

    matching_entries = self.matching_entries(entry.match, entry.priority, True)
    if matching_entries:
      pass # TODO: do something

    self._table.append(entry)

  def entries_for_port(self, port_no):
    entries = []
    for entry in self._table:
      actions = entry.actions
      if len(actions) > 0:
        last_action = actions[-1]
        if type(last_action) == ofp_action_output:
          outgoing_port = last_action.port.port_no
          if outgoing_port == port_no:
            entries.apend(entry)
    return entries

  def matching_entries(self, match, priority=0, strict=False):
    if(strict):
      return [ entry for entry in self._table if entry.match == match and entry.priority = priority ]
    else:
      return [ entry for entry in self._table if match.match_with_wildcards(entry.match) ]

class SwitchFlowTable(FlowTable):
  """ 
  Model a flow table for our switch implementation. Handles the behavior in response
  to the OF messages send to the switch 
  """

  def process_flow_mod(self, flow_mod):
    """ Process a flow mod sent to the switch """
    if flow_mod.command == OFPFC_ADD:
      entry = TableEntry.from_flow_mod(flow_mod)
      self.add_entry(entry)
    else:
      # TODO: implement section 4.6 of OpenFlow 1.0 specification:
      #  elif flow_mod.command == OFPC_DELETE, etc.
      #       alternatively, define a handler hash
      raise "Command not yet implemented "+command


class TableSyncStrategy:
  """" Keeps the topology-level FlowTable in sync with the connection """
  def __init__(self, connection, connect_merge_policy):
    self.switch = switch
    self.connection = connection
    self.connect_merge_policy = connect_merge_policy
    self._syncConnection(True)

  def _syncConnection(initial_connect):
    if(self.connect_merge_policy == OVERWRITE_SWITCH):
      connection.send(of.ofp_flow_mod(match=of.ofp_match(), command=of.OFPFC_DELETE))
      barrier = of.ofp_barrier_request()
      def finish_clear (event):
        if event.xid == barrier.xid:
          self.install_flows(flow_table)
          return EventHaltAndRemove
        else:
          return EventContinue
      connection.addListener(BarrierIn, finish_connecting)
      connection.send(barrier)
    elif(self.connect_merge_policy == OVERWRITE_CONTROLLER):
      def flow_stats_received(event):
        self.update_table_from_stats(event.stats)
        return EventHaltAndRemove
      connection.addListener(FlowStatsReceived, overwrite_stats)
      connection.send(of.ofp_flow_stats_request())

  def update_table_from_stats(self, stats):
    for flow in stats.flows:
      table.for_cookie[flow.cookie] = flow

  def install_all_flows(self, flow_table):
    for entry in flow_table.entries:
      self.connection.send(entry.to_flow_mod(command = OFP_FLOW_ADD))

    barrier = of.ofp_barrier_request()
    def finish_install (event):
      if event.xid == barrier.xid:
        self.install_flows(flow_table)
        return EventHaltAndRemove
      else:
        return EventContinue
    connection.addListener(BarrierIn, finish_install)
    connection.send(barrier)

  def switch_connectionUp(connection, initial_connect):
    self.connection = connection
    self._syncConnection(False)

  def switch_connectionDown():
    self.connection = None

if __name__ == '__main__':
  import unittest
  import sys
  import os.path
  sys.path.append(os.path.dirname(__file__) + "/../..")
  from libopenflow_01 import *


  class TableEntryTest(unittest.TestCase):
    def test_create(self):
      e = TableEntry(priority=5, cookie=0xDEADBEEF, match=ofp_match(), counters={}, actions=[ofp_action_output(port=1)])
      self.assertEqual(e.priority, 5)
      self.assertEqual(e.cookie, 0xDEADBEEF)
      self.assertEqual(e.actions, [ ofp_action_output(port=1) ])

    def test_from_flow_mod(self):
      e = TableEntry.from_flow_mod(ofp_flow_mod(priority=5, cookie=0x31415926, actions=[ofp_action_output(port=5)]))
      self.assertEqual(e.priority, 5)
      self.assertEqual(e.cookie, 0x31415926)
      self.assertEqual(e.actions, [ ofp_action_output(port=5) ])

    def test_to_flow_mod(self):
      e = TableEntry(priority=5,cookie=0xDEADBEEF, match=ofp_match(), actions=[ofp_action_output(port=1)])
      f = e.to_flow_mod(command = OFPFC_ADD)
      self.assertEqual(f.priority, 5)
      self.assertEqual(e.cookie, 0xDEADBEEF)
      self.assertEqual(e.actions, [ ofp_action_output(port=1)])

  class SwitchFlowTableTest(unittest.TestCase):
    def test_process_flow_mod(self):
      """ test that simple insertion of a flow works"""
      t = SwitchFlowTable()
      t.process_flow_mod(ofp_flow_mod(priority=5, cookie=0x31415926, actions=[ofp_action_output(port=5)]))
      self.assertEqual(len(t._table), 1)
      e = t._table[0]
      self.assertEqual(e.priority, 5)
      self.assertEqual(e.cookie, 0x31415926)
      self.assertEqual(e.actions, [ ofp_action_output(port=5)])

    def test_process_flow_removed(self):
      """ test that simple removal of a flow works"""
      t = FlowTable()
      t.add_entry(TableEntry(priority=5, cookie=0x31415926, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01")), actions=[ofp_action_output(port=5)]))
      t.add_entry(TableEntry(priority=5, cookie=0x31415927, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:02")), actions=[ofp_action_output(port=6)]))
      self.assertEqual(len(t._table), 2)
      # remove the first flow
      t.process_flow_removed(ofp_flow_removed(priority=5, cookie=0x31415926, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01"))))
      self.assertEqual(len(t._table), 1)
      self.assertEqual(t._table[0].cookie, 0x31415927)
      # removing a non-matching-flow => NOOP
      for non_matching in [ 
          { 'cookie': 0x31415926, 'match':ofp_match(dl_src=EthAddr("00:00:00:00:00:01")) }, # already gone
          { 'cookie': 0x31415928, 'match':ofp_match(dl_src=EthAddr("00:00:00:00:00:02")) }, # cookie doesn't fit
          { 'cookie': 0x31415927, 'match':ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src=IPAddr("1.2.3.4")) }, # extra match field
          ]:
        t.process_flow_removed(ofp_flow_removed(**non_matching))
        self.assertEqual(len(t._table), 1)
        self.assertEqual(t._table[0].cookie, 0x31415927)

  unittest.main()

