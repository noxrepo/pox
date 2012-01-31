#!/usr/bin/env python

import unittest
import sys
import os.path
from copy import copy

sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.openflow.libopenflow_01 import *
from pox.openflow.switch_impl import *

class ofp_match_test(unittest.TestCase):
  def test_bit_wildcards(self):
    """ some checking of the bit-level wildcard magic in ofp_match"""
    m = ofp_match()

    # all match entries should start out as wildcarded
    for k,v in ofp_match_data.iteritems():
         self.assertEquals(getattr(m, k), None)
         self.assertEquals(m.wildcards & v[1], v[1])

    # try setting and unsetting specific bit-level match entries
    for change in [ ("in_port", 1, OFPFW_IN_PORT), ("dl_vlan", 2, OFPFW_DL_VLAN), ("tp_dst", 22, OFPFW_TP_DST) ]:
      setattr(m, change[0], change[1])
      self.assertEquals(getattr(m, change[0]), change[1], "Attr %s should have been set to %s" % change[0:2])
      self.assertEquals(m.wildcards & change[2], 0, "with %s set to %s, wildcard bit %x should get unset" % change)
      setattr(m, change[0], None)
      self.assertEquals(m.wildcards & change[2], change[2], "with %s reset from %s, wildcard bit %x should be set again" % change)

  def test_ip_wildcard_magic(self):
    """ ofp_match: check IP wildcard magic"""

    # do this for both nw_src and nw_dst
    for (attr, bitmask, shift) in ( ("nw_src", OFPFW_NW_SRC_MASK, OFPFW_NW_SRC_SHIFT), ( "nw_dst", OFPFW_NW_DST_MASK, OFPFW_NW_DST_SHIFT) ):
      m = ofp_match()
      self.assertEquals(getattr(m, "get_"+attr)(), (None, 0), "get_%s for unset %s should return (None,0)" % (attr, attr))

      self.assertTrue( ((m.wildcards & bitmask) >> shift) >= 32)

      # set a bunch of ip addresses with or without networks
      for ipnet in ( "10.0.0.0/8", "172.16.1.0/16", "192.168.24.0/24", "1.2.3.4/30", "212.11.225.3"):
        parts = ipnet.split("/")
        ip = parts[0]
        bits = int(parts[1]) if len(parts)>1 else 32
        # set the IP address
        setattr(m, attr, ipnet)

        # gets converted to just the ip address during query
        self.assertEqual(getattr(m, attr), ip)

        # the get_#{attr} method gives a tuple of (ip, cidr-bits)
        self.assertEqual( getattr(m, "get_"+attr)(), (ip, bits))

        # the appropriate bits in the wildcard should be set
        self.assertEqual( (m.wildcards & bitmask) >> shift, 32-bits)

      # reset to 0.0.0.0/0 results in full wildcard
      setattr(m, attr, "0.0.0.0/0")
      self.assertEquals(getattr(m, "get_"+attr)(), (None, 0), "get_%s for unset %s should return (None,0)" % (attr, attr))
      self.assertTrue( ((m.wildcards & bitmask) >> shift) >= 32)

  def test_match_with_wildcards(self):
    """ ofp_match: test the matches_with_wildcards method """
    def create(wildcards=(), **kw):
      m = ofp_match(in_port=1, dl_type=0, dl_src=EthAddr("00:00:00:00:00:01"), dl_dst=EthAddr("00:00:00:00:00:02"), dl_vlan=5, nw_proto=6, nw_src="10.0.0.1", nw_dst="11.0.0.1", tp_src = 12345, tp_dst=80)

      if isinstance(wildcards, str):
        wildcards = [wildcards]

      for w in wildcards:
        setattr(m, w, None)

      for (k,v) in kw.iteritems():
        m.__setattr__(k,v)
      return m

    def assertMatch(ref, other, msg=""):
      self.assertTrue(ref.matches_with_wildcards(other), "%s - %s should match %s " % (msg, ref.show(), other.show()))

    def assertNoMatch(ref, other, msg=""):
      self.assertFalse(ref.matches_with_wildcards(other), "%s - %s should NOT match %s " % (msg, ref.show(), other.show()))

    ref = create()

    # same instances match
    assertMatch(ref, ref)
    # equal instances match
    assertMatch(ref, create())

    # ofp_match with additional wildcard bits set match the ref, but not the other way round
    for wildcards in ( [ "in_port" ], [ "dl_vlan" ], [ "dl_src", "dl_dst" ] ):
      wilder = create(wildcards=wildcards)
      assertMatch(wilder, ref)
      assertNoMatch(ref, wilder)

    # when fields are wildcarded, we can change around the actual values and it will still match
    for changes in ( { "in_port": 15 }, { "dl_src": "12:34:56:78:90:ab", "dl_vlan": 7 }, { "tp_dst" : 22 } ):
      wild = create()
      concrete = create()
      for (k,v) in changes.iteritems():
        setattr(wild, k, None)
        setattr(concrete, k, v)
      assertMatch(wild, concrete)
      assertNoMatch(concrete, wild)

    # play around with nw src addresses
    assertMatch(create(nw_src="10.0.0.0/24"), ref)
    assertMatch(create(nw_src="10.0.0.0/24"), create(nw_src="10.0.0.0/25"))
    assertNoMatch(create(nw_src="10.0.0.0/25"), create(nw_src="10.0.0.0/24"))
    assertMatch(create(nw_src="10.0.0.0/25"), create(nw_src="10.0.0.127"))
    assertNoMatch(create(nw_src="10.0.0.0/25"), create(nw_src="10.0.0.128"))

class ofp_command_test(unittest.TestCase):
  def assert_header(self, pack, ofp_type, length, xid):
    def num(start, length):
      val = 0
      for i in range(start, start+length):
        val <<= 8
        val += ord(pack[i])
      return val

    self.assertEquals(num(0,1), 1)
    self.assertEquals(num(1,1), ofp_type)
    self.assertEquals(num(2,2), length)
    self.assertEquals(num(4,4), xid)

  def pack_unpack(self, o, xid, ofp_type):
    pack = o.pack()
    self.assertEqual(len(o), len(pack))
    unpacked = type(o)()
    unpacked.unpack(pack)
    self.assertEqual(o, unpacked)
    self.assert_header(pack, OFPT_PACKET_OUT, len(o), xid)


out = ofp_action_output
class ofp_packet_out_test(ofp_command_test):
  def test_pack_unpack(self):
    xid_gen = itertools.count()
    packet = ethernet(src=EthAddr("00:00:00:00:00:01"), dst=EthAddr("00:00:00:00:00:02"),
            payload=ipv4(srcip=IPAddr("1.2.3.4"), dstip=IPAddr("1.2.3.5"),
                payload=udp(srcport=1234, dstport=53, payload="haha"))).pack()

    for actions in ([], [out(port=2)], [out(port=2), out(port=3)], [ out(port=OFPP_FLOOD) ] ):
      for attrs in ( { 'data': packet }, { 'buffer_id': 5 } ):
        xid = xid_gen.next()
        o = ofp_packet_out(xid=xid, actions=actions, **attrs)
        self.pack_unpack(o, xid, OFPT_PACKET_OUT)

if __name__ == '__main__':
  unittest.main()
