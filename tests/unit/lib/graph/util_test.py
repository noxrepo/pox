#!/usr/bin/env python

import itertools
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), *itertools.repeat("..", 3)))

from pox.lib.graph.nom import *
from pox.lib.graph.util import *
from pox.openflow.topology import *
from pox.openflow.flow_table import *
from pox.openflow import *
import json

class EncoderTest(unittest.TestCase):
  def test_encode_host(self):
    """ test that hosts can be json encoded """
    host = Host("c4:2c:03:0c:15:33", "10.0.0.11")
    host.setLocation(1, 2)
    
    myEncoder = NOMEncoder(encoding="ISO-8859-1")
    encoded_host = myEncoder.encode(host)

  def test_decode_host(self):
    encoded_host = "{\
\"__module__\": \"pox.lib.graph.nom\", \"macstr\": \"c4:2c:03:0c:15:33\",\
\"ip\": {\"_value\": 184549386, \"__module__\": \"pox.lib.addresses\",\
\"__class__\": \"IPAddr\"},\
\"__class__\": \"Host\", \"_num\": 1,\
\"mac\": {\"_value\": \"\u00c4,\u0003f\u00153\",\
\"__module__\": \"pox.lib.addresses\", \"__class__\": \"EthAddr\"},\
\"location\": [1, 2]}"
    
    myDecoder = NOMDecoder()
    host = myDecoder.decode(encoded_host)
    assert (host.macstr=="c4:2c:03:0c:15:33")
    assert (host.ip.toStr()=="10.0.0.11")
    assert (host.location==[1,2])
  
  def test_encode_of_switch(self):
    """ test that switches can be json encoded """
    switch = OpenFlowSwitch(1512)
    #tableEntries = []
    #tableEntries.append(TableEntry(priority=5, cookie=0xDEADBEEF, match=ofp_match(), actions=[ofp_action_output(port=1)]))
    #tableEntries.append(TableEntry.from_flow_mod(ofp_flow_mod(priority=5, cookie=0x31415926, actions=[ofp_action_output(port=5)])))
    #switch.flow_table.entries = tableEntries
    
    myEncoder = NOMEncoder()
    encoded_switch = myEncoder.encode(switch)
    assert "\"dpid\": 1512" in encoded_switch
    
  def test_decode_of_switch(self):
    """ test that switches can be decoded """
    encoded_switch = "{\
\"__module__\": \"pox.openflow.topology\", \"dpid\": 1513, \"__class__\": \"OpenFlowSwitch\",\
\"capabilities\": 0, \"flow_table\": {\"__module__\": \"pox.openflow.flow_table\",\
\"__class__\": \"NOMFlowTable\",\
\"switch\": {\"__module__\": \"pox.openflow.topology\", \"__class__\": \"OpenFlowSwitch\",\
\"dpid\": 1512}, \"flow_table\": {\"__module__\": \"pox.openflow.flow_table\",\
\"__class__\": \"FlowTable\"} }}"
    '''
    encoded_switch = "{\
\"__module__\": \"pox.openflow.topology\",\"__class__\": \"OpenFlowSwitch\",\
\'dpid\': 1, \'capabilities\': 135,\
\'flow_table\': {\"__module__\": \"pox.openflow.flow_table\"}}"
    '''
    
    myDecoder = NOMDecoder()
    switch = myDecoder.decode(encoded_switch)
    assert (switch.dpid==1513)
    assert (isinstance(switch.flow_table, NOMFlowTable))
    
  def test_encode_link(self):
    """ test that links can be json encoded """
    link = Link(1, 2, 4, 1)
    myEncoder = NOMEncoder()
    encoded_link = myEncoder.encode(link)
    assert "\"node1\": 1" in encoded_link
    assert "\"port1\": 2" in encoded_link
    assert "\"node2\": 4" in encoded_link
    assert "\"port2\": 1" in encoded_link
    
  def test_decode_link(self):
    """ test that links can be decoded """
    encoded_link = "{\"__module__\": \"pox.lib.graph.nom\",\
\"__class__\": \"Link\", \"node1\": 1, \"port1\": 2, \"node2\": 4, \"port2\": 1}"
    
    myDecoder = NOMDecoder()
    link = myDecoder.decode(encoded_link)
    assert (link.node1==1)
    assert (link.port1==2)
    assert (link.node2==4)
    assert (link.port2==1)
    