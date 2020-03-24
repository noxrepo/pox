#!/usr/bin/env python
#
# Copyright 2011-2012 James McCauley
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
OpenFlow stuff for topology
"""
import time

import unittest
import sys
import os.path
import itertools

sys.path.append(os.path.dirname(__file__) + "/../../..")
from pox.openflow.libopenflow_01 import *
#from pox.openflow.flow_table import *
from pox.openflow import *
from pox.openflow.topology import *

class MockSwitch(EventMixin):
  _eventMixin_events = [FlowRemoved, BarrierIn, SwitchConnectionUp, SwitchConnectionDown ]
  def __init__(self):
    EventMixin.__init__(self)
    self.connected = True
    self._xid_generator = itertools.count(1).__next__
    self.sent = []

  def send(self, msg):
    #print "Hey: %s" % msg
    self.sent.append(msg)

  @property
  def last(self):
    return self.sent[-1]

class MockConnection(EventMixin):
  def __init__(self):
    self.dpid =1


class OFSyncFlowTableTest(unittest.TestCase):
  def setUp(self):
    self.s = MockSwitch()
    self.conn = MockConnection()
    self.t = OFSyncFlowTable(self.s)

  def test_reconnect_pending(self):
    t = self.t
    s = self.s

    seen_ft_events = []
    t.addListener(FlowTableModification, lambda event: seen_ft_events.append(event))

    entry = TableEntry(priority=5, cookie=0x31415926, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01")), actions=[ofp_action_output(port=5)])
    t.install(entry)

    # entry is pending
    self.assertEqual(t.num_pending, 1)
    self.assertEqual(len(t), 0)

    self.assertEqual(len(s.sent), 2)
    self.assertTrue(isinstance(s.sent[-2], ofp_flow_mod))
    self.assertTrue(isinstance(s.sent[-1], ofp_barrier_request))

    # oops switch disconnected
    s.raiseEvent(SwitchConnectionDown(s))
    # reconnect
    s.raiseEvent(SwitchConnectionUp(s, self.conn))

    # our guy should clear and reinstall the flows
    self.assertEqual(len(s.sent), 6)
    self.assertTrue(isinstance(s.sent[-4], ofp_flow_mod) and s.sent[-4].command == OFPFC_DELETE and s.sent[-4].match == ofp_match())
    self.assertTrue(isinstance(s.sent[-3], ofp_barrier_request))
    self.assertTrue(isinstance(s.sent[-2], ofp_flow_mod) and s.sent[-2].command == OFPFC_ADD and s.sent[-2].match == entry.match)
    self.assertTrue(isinstance(s.sent[-1], ofp_barrier_request))

  def test_install_remove(self):
    t = self.t
    s = self.s

    seen_ft_events = []
    t.addListener(FlowTableModification, lambda event: seen_ft_events.append(event))

    entry = TableEntry(priority=5, cookie=0x31415926, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01")), actions=[ofp_action_output(port=5)])
    t.install(entry)

    # entry is pending
    self.assertEqual(t.num_pending, 1)
    self.assertEqual(len(t), 0)
    self.assertEqual(len(s.sent), 2)
    self.assertTrue(isinstance(s.sent[-2], ofp_flow_mod))
    self.assertTrue(isinstance(s.sent[-1], ofp_barrier_request))
    self.assertEqual(len(seen_ft_events), 0)

    # send a barrier in -> now entry should be installed
    s.raiseEvent(BarrierIn(self.conn, ofp_barrier_reply(xid=s.sent[-1].xid)))
    self.assertEqual(len(t), 1)
    self.assertEqual(t.entries[0], entry)
    self.assertEqual(t.num_pending, 0)
    self.assertEqual(len(seen_ft_events), 1)
    self.assertTrue(isinstance(seen_ft_events[0], FlowTableModification) and seen_ft_events[-1].added == [entry])

    # schedule for removal
    t.remove_strict(entry)
    self.assertEqual(len(t), 1)
    self.assertEqual(t.entries[0], entry)
    self.assertEqual(t.num_pending, 1)
    self.assertTrue(isinstance(s.sent[-2], ofp_flow_mod) and s.sent[-2].command == OFPFC_DELETE_STRICT)
    self.assertTrue(isinstance(s.sent[-1], ofp_barrier_request))

    # send a barrier in -> now entry should be removed
    s.raiseEvent(BarrierIn(self.conn, ofp_barrier_reply(xid=s.sent[-1].xid)))
    self.assertEqual(len(t), 0)
    self.assertEqual(t.num_pending, 0)
    self.assertEqual(len(seen_ft_events), 2)
    self.assertTrue(isinstance(seen_ft_events[-1], FlowTableModification) and seen_ft_events[-1].removed == [entry])

  def test_handle_FlowRemoved(self):
    """ test that simple removal of a flow works"""
    t = self.t
    t.flow_table.add_entry(TableEntry(priority=5, cookie=0x31415926, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01")), actions=[ofp_action_output(port=5)]))
    t.flow_table.add_entry(TableEntry(priority=5, cookie=0x31415927, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:02")), actions=[ofp_action_output(port=6)]))
    self.assertEqual(len(t), 2)
    # remove the first flow
    t._handle_FlowRemoved(FlowRemoved(self.conn, ofp_flow_removed(priority=5, cookie=0x31415926, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01")))))
    self.assertEqual(len(t), 1)
    self.assertEqual(t.entries[0].cookie, 0x31415927)
    # removing a non-matching-flow => NOOP
    for non_matching in [
        { 'cookie': 0x31415926, 'match':ofp_match(dl_src=EthAddr("00:00:00:00:00:01")) }, # already gone
        { 'cookie': 0x31415928, 'match':ofp_match(dl_src=EthAddr("00:00:00:00:00:02")) }, # cookie doesn't fit
        { 'cookie': 0x31415927, 'match':ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src=IPAddr("1.2.3.4")) }, # extra match field
        ]:
      t._handle_FlowRemoved(FlowRemoved(self.conn, ofp_flow_removed(**non_matching)))
      self.assertEqual(len(t), 1)
      self.assertEqual(t.entries[0].cookie, 0x31415927)


if __name__ == '__main__':
  unittest.main()


