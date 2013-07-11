#!/usr/bin/env python
#
# Copyright 2011-2012 Andreas Wundsam
# Copyright 2011-2012 Colin Scott
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

from collections import namedtuple

import time

import unittest
import sys
import os.path
import itertools

sys.path.append(os.path.dirname(__file__) + "/../../..")
from pox.openflow.libopenflow_01 import *
from pox.openflow.flow_table import *
from pox.openflow import *
from pox.openflow.topology import *

class TableEntryTest(unittest.TestCase):
  def test_create(self):
    e = TableEntry(priority=5, cookie=0xDEADBEEF, match=ofp_match(), actions=[ofp_action_output(port=1)])
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

  def test_is_expired(self):
    e = TableEntry(now=0, idle_timeout=5, hard_timeout=10)
    self.assertEqual(e.idle_timeout, 5)
    self.assertEqual(e.hard_timeout, 10)
    self.assertFalse(e.is_expired(now=1))
    self.assertFalse(e.is_expired(now=5))
    self.assertTrue(e.is_expired(now=7))
    e.touch_packet(12, now=5)
    self.assertEqual(e.byte_count, 12)
    self.assertEqual(e.packet_count, 1)
    self.assertFalse(e.is_expired(now=1))
    self.assertFalse(e.is_expired(now=7))
    self.assertFalse(e.is_expired(now=10))
    e.touch_packet(12, now=9)
    self.assertTrue(e.is_expired(now=11))

    e2 = TableEntry(now=0, idle_timeout=0, hard_timeout=10)
    self.assertFalse(e2.is_expired(now=1))
    self.assertFalse(e2.is_expired(now=9))
    self.assertTrue(e2.is_expired(now=11))

class FlowTableTest(unittest.TestCase):
  def test_remove_matching_entries(self):
    """ test that simple removal of a flow works"""
    def table():
      t = FlowTable()
      t.add_entry(TableEntry(priority=6, cookie=0x1, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01"),nw_src="1.2.3.4"), actions=[ofp_action_output(port=5)]))
      t.add_entry(TableEntry(priority=5, cookie=0x2, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src="1.2.3.0/24"), actions=[ofp_action_output(port=6)]))
      t.add_entry(TableEntry(priority=1, cookie=0x3, match=ofp_match(), actions=[]))
      return t

    for (match, priority, strict, remaining) in (
          (ofp_match(), 0, False, []), #non-strict wildcard removes everything
          (ofp_match(), 0, True, [1,2,3]), # strict wildcard with wrong prio removes nothing
          (ofp_match(), 1, True, [1,2]), # strict wildcard with right prio removes only flow 3
          (ofp_match(nw_src="1.2.3.0/24"), 1, False, [3]), # non-strict subnet removes 1+2
          (ofp_match(nw_src="1.2.3.0/24"), 6, True, [1,2,3]), # does not match dl_src => noop
          (ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src="1.2.3.0/24"), 5, True, [1,3]), # exactly matches #2
          ):
      t=table()
      t.remove_matching_entries(match, priority=priority, strict=strict)
      self.assertEqual([e.cookie for e in t._table], remaining)

  def test_remove_expired_entries(self):
    """ test that flow can get expired as time passes """
    t = FlowTable()
    for (cookie, idle, hard) in ( (1, 5, 20), (2, 5, 20), (3, 0, 20), (4, 0, 0) ):
      t.add_entry(TableEntry(now=0, cookie=cookie, idle_timeout=idle, hard_timeout=hard))

    for (time, touch, remaining) in (
            (1, [], [1,2,3,4]), # at time 1, everyone's happy
            (3, [2], [1,2,3,4]), # at time 3, flow 2 gets touched
            (6, [], [2,3,4]), # at time 6, flow 1 expires
            (9, [], [3,4]), # at time 9, flow 2 expires
            (21, [], [4]), # at time 21, flow 3 expires
            (99999999, [], [4]), # 4 would still live at the end of days
            ):
      [e.touch_packet(1, now=time) for e in t.entries if e.cookie in touch]
      t.remove_expired_entries(now=time)
      self.assertEqual(sorted([e.cookie for e in t.entries]), remaining)

  # def test_check_for_overlap_entries(self):




if __name__ == '__main__':
  unittest.main()

