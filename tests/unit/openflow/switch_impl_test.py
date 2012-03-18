#!/usr/bin/env python

import unittest
import sys
import os.path
from copy import copy

sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.openflow.libopenflow_01 import *
from pox.openflow.switch_impl import *

class MockConnection(object):
  def __init__(self):
    self.ofp_handlers = {}
    self.received = []

  @property
  def last(self):
    return self.received[-1]

  def to_switch(self, msg):
    self.ofp_handlers[msg.header_type](msg)

  # from switch
  def send(self, msg):
    self.received.append(msg)

class SwitchImplTest(unittest.TestCase):

  def setUp(self):
    self.conn = MockConnection()
    self.switch = SwitchImpl(1, name="sw1")
    self.switch.set_connection(self.conn)
    self.packet = ethernet(src=EthAddr("00:00:00:00:00:01"), dst=EthAddr("00:00:00:00:00:02"),
            payload=ipv4(srcip=IPAddr("1.2.3.4"), dstip=IPAddr("1.2.3.5"),
                payload=udp(srcport=1234, dstport=53, payload="haha")))
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
    self.assertTrue(isinstance(c.last, ofp_barrier_reply) and c.last.xid == 123,
          "should have received echo reply but got %s" % c.last)


  def test_flow_mod(self):
    c = self.conn
    s = self.switch
    c.to_switch(ofp_flow_mod(xid=124, priority=1, match=ofp_match(in_port=1, nw_src="1.2.3.4")))
    self.assertEqual(len(c.received), 0)
    self.assertEqual(len(s.table), 1)
    e = s.table.entries[0]
    self.assertEqual(e.priority,1)
    self.assertEqual(e.match, ofp_match(in_port=1, nw_src="1.2.3.4"))

  def test_packet_out(self):
    c = self.conn
    s = self.switch
    received = []
    s.addListener(DpPacketOut, lambda(event): received.append(event))

    packet = self.packet
    c.to_switch(ofp_packet_out(data=packet, actions=[ofp_action_output(port=2)]))
    self.assertEqual(len(c.received), 0)
    self.assertEqual(len(received), 1)
    event = received[0]
    self.assertEqual(event.port.port_no,2)
    self.assertEqual(event.packet.pack(), packet.pack())

  def test_send_packet_in(self):
    c = self.conn
    s = self.switch
    s.send_packet_in(in_port=1, buffer_id=123, packet=self.packet, xid=314, reason=OFPR_NO_MATCH)
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_packet_in) and c.last.xid == 314,
          "should have received packet_in but got %s" % c.last)
    self.assertEqual(c.last.in_port,1)
    self.assertEqual(c.last.buffer_id,123)
    self.assertEqual(c.last.data, self.packet.pack())

  def test_process_packet(self):
    c = self.conn
    s = self.switch
    received = []
    s.addListener(DpPacketOut, lambda(event): received.append(event))
    # no flow entries -> should result in a packet_in
    s.process_packet(self.packet, in_port=1)
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
    s.process_packet(self.packet, in_port=1)
    self.assertEqual(len(c.received), 0)

    self.assertEqual(len(received), 1)
    event = received[0]
    self.assertEqual(event.port.port_no,3)
    self.assertEqual(event.packet, self.packet)
    
  def test_take_port_down(self):
    c = self.conn
    s = self.switch
    original_num_ports = len(self.switch.ports)
    p = self.switch.ports.values()[0]
    s.take_port_down(p)
    new_num_ports = len(self.switch.ports)
    self.assertTrue(new_num_ports == original_num_ports - 1, "Should have removed the port")
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_port_status),
          "should have received port_status but got %s" % c.last)
    self.assertTrue(c.last.reason == OFPPR_DELETE)
  
  def test_bring_port_up(self):
    c = self.conn
    s = self.switch
    original_num_ports = len(self.switch.ports)
    p = ofp_phy_port(port_no=1234)
    s.bring_port_up(p)
    new_num_ports = len(self.switch.ports)
    self.assertTrue(new_num_ports == original_num_ports + 1, "Should have added the port")
    self.assertEqual(len(c.received), 1)
    self.assertTrue(isinstance(c.last, ofp_port_status),
          "should have received port_status but got %s" % c.last)
    self.assertTrue(c.last.reason == OFPPR_ADD)

if __name__ == '__main__':
  unittest.main()
