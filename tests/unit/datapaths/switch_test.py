#!/usr/bin/env python
#
# Copyright 2011-2012 Andreas Wundsam
# Copyright 2011-2012 Colin Scott
# Copyright 2011-2013 James McCauley
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

import unittest
import sys
import os.path
from copy import copy

sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.openflow.libopenflow_01 import *
from pox.openflow.flow_table import FlowTable
from pox.datapaths.switch import *

class MockConnection(object):
  def __init__(self, do_packing):
    self.received = []
    self.do_packing = do_packing

  @property
  def last(self):
    return self.received[-1]

  def set_message_handler(self, handler):
    self.on_message_received = handler

  def to_switch(self, msg):
    self.on_message_received(self, msg)

  # from switch
  def send(self, msg):
    if type(msg) is not bytes:
      if self.do_packing and hasattr(msg, 'pack'):
          dummy = msg.pack()
    self.received.append(msg)


class SwitchImplTest (unittest.TestCase):
  _do_packing = False

  def setUp(self):
    self.conn = MockConnection(self._do_packing)
    self.switch = SoftwareSwitch(1, name="sw1")
    self.switch.set_connection(self.conn)
    self.packet = ethernet(
        src=EthAddr("00:00:00:00:00:01"),
        dst=EthAddr("00:00:00:00:00:02"),
        payload=ipv4(srcip=IPAddr("1.2.3.4"),
        dstip=IPAddr("1.2.3.5"),
        payload=udp(srcport=1234, dstport=53, payload=b"haha")))

  def test_hello(self):
    c = self.conn
    c.to_switch(ofp_hello(xid=123))
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_hello),
          "should have received hello but got %s" % c.last)

  def test_echo_request(self):
    c = self.conn
    c.to_switch(ofp_echo_request(xid=123))
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_echo_reply) and c.last.xid == 123,
          "should have received echo reply but got %s" % c.last)

  def test_barrier(self):
    c = self.conn
    c.to_switch(ofp_barrier_request(xid=123))
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_barrier_reply)
        and c.last.xid == 123,
        "should have received echo reply but got %s" % c.last)

  def test_flow_mod(self):
    c = self.conn
    s = self.switch
    c.to_switch(ofp_flow_mod(xid=124, priority=1,
        match=ofp_match(in_port=1, nw_src="1.2.3.4")))
    self.assertEqual(len(c.received), 0)
    self.assertEqual(len(s.table), 1)
    e = s.table.entries[0]
    self.assertEqual(e.priority,1)
    self.assertEqual(e.match, ofp_match(in_port=1, nw_src="1.2.3.4"))

  def test_packet_out(self):
    c = self.conn
    s = self.switch
    received = []
    s.addListener(DpPacketOut, lambda event: received.append(event))

    packet = self.packet
    c.to_switch(ofp_packet_out(data=packet,
        actions=[ofp_action_output(port=2)]))
    self.assertEqual(len(c.received), 0)
    self.assertEqual(len(received), 1)
    event = received[0]
    self.assertEqual(event.port.port_no,2)
    self.assertEqual(event.packet.pack(), packet.pack())

  def test_send_packet_in(self):
    c = self.conn
    s = self.switch
    s.send_packet_in(in_port=1, buffer_id=123, packet=self.packet,
        reason=OFPR_NO_MATCH)
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_packet_in) and c.last.xid == 0,
        "should have received packet_in but got %s" % c.last)
    self.assertEqual(c.last.in_port,1)
    self.assertEqual(c.last.buffer_id,123)
    self.assertEqual(c.last.data, self.packet.pack())

  def test_rx_packet(self):
    c = self.conn
    s = self.switch
    received = []
    s.addListener(DpPacketOut, lambda event: received.append(event))
    # no flow entries -> should result in a packet_in
    s.rx_packet(self.packet, in_port=1)
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_packet_in),
        "should have received packet_in but got %s" % c.last)
    self.assertTrue(c.last.buffer_id > 0)

    # let's send a flow_mod with a buffer id
    c.to_switch(ofp_flow_mod(xid=124, buffer_id=c.last.buffer_id, priority=1,
                             match=ofp_match(in_port=1, nw_src="1.2.3.4"),
                             actions = [ ofp_action_output(port=3) ]
                             ))

    # that should have send the packet out port 3
    self.assertEqual(len(received), 1)
    event = received[0]
    self.assertEqual(event.port.port_no,3)
    self.assertEqual(event.packet, self.packet)

    # now the next packet should go through on the fast path
    c.received = []
    received = []
    s.rx_packet(self.packet, in_port=1)
    self.assertEqual(len(c.received), 0)

    self.assertEqual(len(received), 1)
    event = received[0]
    self.assertEqual(event.port.port_no,3)
    self.assertEqual(event.packet, self.packet)

  def test_delete_port(self):
    c = self.conn
    s = self.switch
    original_num_ports = len(self.switch.ports)
    p = list(self.switch.ports.values())[0]
    s.delete_port(p)
    new_num_ports = len(self.switch.ports)
    self.assertTrue(new_num_ports == original_num_ports - 1,
                    "Should have removed the port")
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_port_status),
          "should have received port_status but got %s" % c.last)
    self.assertTrue(c.last.reason == OFPPR_DELETE)

  def test_add_port(self):
    c = self.conn
    s = self.switch
    port_count = len(self.switch.ports)
    old_port = s.delete_port(1)
    self.assertTrue(port_count - 1 == len(self.switch.ports),
                    "Should have removed port")
    self.assertFalse(old_port.port_no in self.switch.ports,
                     "Should have removedport")
    s.add_port(old_port)
    self.assertTrue(old_port.port_no in self.switch.ports,
                    "Should have added port")
    self.assertEqual(len(c.received), 2)
    self.assertTrue(isinstance(c.last, ofp_port_status),
          "should have received port_status but got %s" % c.last)
    self.assertTrue(c.last.reason == OFPPR_ADD)

  def test_port_mod_failed(self):
    c = self.conn

    # test wrong port
    msg = ofp_port_mod()
    msg.port_no = 1234
    c.to_switch(msg)
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_error))
    self.assertTrue(c.last.type == OFPET_PORT_MOD_FAILED)
    self.assertTrue(c.last.code == OFPPMFC_BAD_PORT)

    # test wrong hw_addr
    msg.port_no = 1
    msg.hw_addr = EthAddr("11:22:33:44:55:66")
    c.to_switch(msg)
    self.assertEqual(len(c.received), 2)
    self.assertTrue(isinstance(c.last, ofp_error))
    self.assertTrue(c.last.type == OFPET_PORT_MOD_FAILED)
    self.assertTrue(c.last.code == OFPPMFC_BAD_HW_ADDR)

  def test_port_mod_link_down(self):
    c = self.conn
    s = self.switch

    # test wrong port
    msg = ofp_port_mod()
    msg.port_no = 1
    msg.hw_addr = s.ports[1].hw_addr
    msg.mask = OFPPC_PORT_DOWN
    msg.config = OFPPC_PORT_DOWN
    c.to_switch(msg)
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_port_status))


# Do tests with packing independently to make it easier to spot
# packing-related bugs.  (Maybe?)
class PackingTest (SwitchImplTest):
  _do_packing = True


#class SwitchFlowTableTest(unittest.TestCase):
class ProcessFlowModTest(unittest.TestCase):
  _do_packing = False

  def setUp(self):
    self.conn = MockConnection(self._do_packing)
    self.switch = SoftwareSwitch(1, name="sw1")
    self.switch.set_connection(self.conn)
    self.packet = ethernet(
        src=EthAddr("00:00:00:00:00:01"),
        dst=EthAddr("00:00:00:00:00:02"),
        payload=ipv4(srcip=IPAddr("1.2.3.4"),
        dstip=IPAddr("1.2.3.5"),
        payload=udp(srcport=1234, dstport=53, payload=b"haha")))

  def test_process_flow_mod_add(self):
    """ test that simple insertion of a flow works"""
    c = self.conn
    s = self.switch
    t = s.table

    # test wrong port
    msg = ofp_flow_mod(priority=5, cookie=0x31415926, actions=[ofp_action_output(port=5)])
    c.to_switch(msg)

    self.assertEqual(len(t.entries), 1)
    e = t.entries[0]
    self.assertEqual(e.priority, 5)
    self.assertEqual(e.cookie, 0x31415926)
    self.assertEqual(e.actions, [ ofp_action_output(port=5)])

  def test_process_flow_mod_modify(self):
    """ test that simple removal of a flow works"""
    c = self.conn
    s = self.switch

    def table():
      t = FlowTable()
      t.add_entry(TableEntry(priority=6, cookie=0x1, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01"),nw_src="1.2.3.4"), actions=[ofp_action_output(port=5)]))
      t.add_entry(TableEntry(priority=5, cookie=0x2, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src="1.2.3.0/24"), actions=[ofp_action_output(port=6)]))
      t.add_entry(TableEntry(priority=1, cookie=0x3, match=ofp_match(), actions=[]))
      return t

    s.table = table()
    t = s.table
    msg = ofp_flow_mod(command = OFPFC_MODIFY, match=ofp_match(), actions = [ofp_action_output(port=1)])
    c.to_switch(msg)
    self.assertEquals([e.cookie for e in t.entries if e.actions == [ofp_action_output(port=1)] ], [1,2,3])
    self.assertEquals(len(t.entries), 3)

    s.table = table()
    t = s.table
    msg = ofp_flow_mod(command = OFPFC_MODIFY, match=ofp_match(nw_src="1.2.0.0/16"), actions = [ofp_action_output(port=8)])
    c.to_switch(msg)
    self.assertEquals([e.cookie for e in t.entries if e.actions == [ofp_action_output(port=8)] ], [1,2])
    self.assertEquals(len(t.entries), 3)

    # non-matching OFPFC_MODIFY acts as add
    s.table = table()
    t = s.table
    msg = ofp_flow_mod(cookie=5, command = OFPFC_MODIFY, match=ofp_match(nw_src="2.2.0.0/16"), actions = [ofp_action_output(port=8)])
    c.to_switch(msg)
    self.assertEquals(len(t.entries), 4)
    self.assertEquals([e.cookie for e in t.entries if e.actions == [ofp_action_output(port=8)] ], [5])

  def test_process_flow_mod_modify_strict(self):
    """ test that simple removal of a flow works"""
    c = self.conn
    s = self.switch

    def table():
      t = FlowTable()
      t.add_entry(TableEntry(priority=6, cookie=0x1, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:01"),nw_src="1.2.3.4"), actions=[ofp_action_output(port=5)]))
      t.add_entry(TableEntry(priority=5, cookie=0x2, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src="1.2.3.0/24"), actions=[ofp_action_output(port=6)]))
      t.add_entry(TableEntry(priority=1, cookie=0x3, match=ofp_match(), actions=[]))
      return t

    s.table = table()
    t = s.table
    msg = ofp_flow_mod(command = OFPFC_MODIFY_STRICT, priority=1, match=ofp_match(), actions = [ofp_action_output(port=1)])
    c.to_switch(msg)
    self.assertEquals([e.cookie for e in t.entries if e.actions == [ofp_action_output(port=1)] ], [3])
    self.assertEquals(len(t.entries), 3)

    s.table = table()
    t = s.table
    msg = ofp_flow_mod(command = OFPFC_MODIFY_STRICT, priority=5, match=ofp_match(dl_src=EthAddr("00:00:00:00:00:02"), nw_src="1.2.3.0/24"), actions = [ofp_action_output(port=8)])
    c.to_switch(msg)
    self.assertEquals([e.cookie for e in t.entries if e.actions == [ofp_action_output(port=8)] ], [2])
    self.assertEquals(len(t.entries), 3)




if __name__ == '__main__':
  unittest.main()
