#!/usr/bin/env python
#
# Copyright 2011-2012 Andreas Wundsam
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

import unittest
import sys
import os.path
from copy import copy
sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.openflow.libopenflow_01 import *
from pox.datapaths.switch import *

def extract_num(buf, start, length):
  """ extracts a number from a raw byte string. Assumes network byteorder  """
  # note: purposefully does /not/ use struct.unpack, because that is used by the code we validate
  val = 0
  for i in range(start, start+length):
    val <<= 8
    val += buf[i]
  return val

class ofp_match_test(unittest.TestCase):
  def test_bit_wildcards(self):
    """ some checking of the bit-level wildcard magic in ofp_match"""
    m = ofp_match()

    # all match entries should start out as wildcarded
    for k,v in ofp_match_data.items():
         self.assertEquals(getattr(m, k), None, "Attr %s should be wildcarded and reported as None" % k)
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
      for ipnet in ( "10.0.0.0/8", "172.16.0.0/16", "192.168.24.0/24", "1.2.3.4/30", "212.11.225.3"):
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

      for (k,v) in kw.items():
        m.__setattr__(k,v)
      return m

    def assertMatch(ref, other, msg=""):
      self.assertTrue(ref.matches_with_wildcards(other), "%s - %s should match %s " % (msg, ref.show(), other.show()))

    def assertNoMatch(ref, other, msg=""):
      self.assertFalse(ref.matches_with_wildcards(other), "%s - %s should NOT match %s " % (msg, ref.show(), other.show()))

    ref = create()
    #print ref

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
      for (k,v) in changes.items():
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
  # custom map of POX class to header type, for validation
  ofp_type = {
    ofp_features_reply: OFPT_FEATURES_REPLY,
    ofp_set_config: OFPT_SET_CONFIG,
    ofp_flow_mod: OFPT_FLOW_MOD,
    ofp_port_mod: OFPT_PORT_MOD,
    ofp_queue_get_config_request: OFPT_QUEUE_GET_CONFIG_REQUEST,
    ofp_queue_get_config_reply: OFPT_QUEUE_GET_CONFIG_REPLY,
    ofp_stats_request: OFPT_STATS_REQUEST,
    ofp_stats_reply: OFPT_STATS_REPLY,
    ofp_packet_out: OFPT_PACKET_OUT,
    ofp_barrier_reply: OFPT_BARRIER_REPLY,
    ofp_barrier_request: OFPT_BARRIER_REQUEST,
    ofp_packet_in: OFPT_PACKET_IN,
    ofp_flow_removed: OFPT_FLOW_REMOVED,
    ofp_port_status: OFPT_PORT_STATUS,
    ofp_error: OFPT_ERROR,
    ofp_hello: OFPT_HELLO,
    ofp_echo_request: OFPT_ECHO_REQUEST,
    ofp_echo_reply: OFPT_ECHO_REPLY,
    ofp_vendor_generic: OFPT_VENDOR,
    ofp_features_request: OFPT_FEATURES_REQUEST,
    ofp_get_config_request: OFPT_GET_CONFIG_REQUEST,
    ofp_get_config_reply: OFPT_GET_CONFIG_REPLY,
    ofp_set_config: OFPT_SET_CONFIG
    }

  def assert_packed_header(self, pack, ofp_type, length, xid):
    """ check openflow header fields in packed byte array """
    def assert_num(name, start, length, expected):
      val = extract_num(pack, start, length)
      self.assertEquals(val, expected, "packed header check: %s for ofp type %s should be %d (is %d)" % (name, ofp_type_map[ofp_type], expected, val))

    assert_num("OpenFlow version", 0, 1, 1)
    assert_num("header_type", 1, 1, ofp_type)
    assert_num("length in header", 2, 2, length)
    assert_num("xid", 4, 4, xid)

  def _test_pack_unpack(self, o, xid, ofp_type=None):
    """ check that packing and unpacking an ofp object works, and that lengths etc. are correct """
    show = lambda o: o.show() if hasattr(o, "show") else str(show)

    if not ofp_type:
      ofp_type = self.ofp_type[type(o)]

    self.assertTrue(o._assert(), "pack_unpack for %s -- original object should _assert to true"%show(o))
    # show the object to make sure that works
    o.show()
    # pack object
    pack = o.pack()
    # byte array length should equal calculated length
    self.assertEqual(len(o), len(pack), "pack_unpack for %s -- len(object)=%d != len(packed)=%d" % (type(o), len(o), len(pack)))
    # check header fields in packed byte array
    self.assert_packed_header(pack, ofp_type, len(o), xid)
    # now unpack
    unpacked = type(o)()
    unpacked.unpack(pack)
    self.assertEqual(o, unpacked, "pack_unpacked -- original != unpacked\n===Original:\n%s\n===Repacked:%s\n" % (show(o), show(unpacked)))
    return unpacked

  def test_header_pack_unpack(self):
    for kw in ( { "header_type": OFPT_PACKET_OUT, "xid": 1 },
                { "header_type": OFPT_FLOW_MOD, "xid": 2 }):
      # Can't directly pack a header, since it has no length...
      class H (ofp_header):
        def __len__ (self):
          return 8
      o = H(**kw)
      self._test_pack_unpack(o, kw["xid"], kw["header_type"])

  def test_pack_all_comands_simple(self):
    xid_gen = xid_generator()
    for cls in ( ofp_features_reply,
                   ofp_set_config,
                   ofp_get_config_reply,
                   ofp_flow_mod,
                   ofp_port_mod,
                   ofp_queue_get_config_request,
                   ofp_queue_get_config_reply,
                   ofp_stats_request,
                   ofp_stats_reply,
                   ofp_packet_out,
                   ofp_barrier_reply,
                   ofp_barrier_request,
                   ofp_packet_in,
                   ofp_flow_removed,
                   ofp_port_status,
                   ofp_error,
                   ofp_hello,
                   ofp_echo_request,
                   ofp_echo_reply,
                   ofp_features_request,
                   ofp_get_config_request,
                   ofp_get_config_reply,
                   ofp_set_config ):
      xid = xid_gen()
      args = {}

      # Customize initializer
      if cls is ofp_stats_reply:
        args['body'] = ofp_desc_stats(sw_desc="POX")
      elif cls is ofp_stats_request:
        args['body'] = ofp_vendor_stats_generic(vendor=0xcafe)

      o = cls(xid=xid, **args)
      self._test_pack_unpack(o, xid)

  out = ofp_action_output
  dl_addr = ofp_action_dl_addr
  some_actions = ([], [out(port=2)], [out(port=2), out(port=3)], [ out(port=OFPP_FLOOD) ], [ dl_addr.set_dst(EthAddr("00:"*5 + "01")), out(port=1) ])


  def test_pack_custom_packet_out(self):
    xid_gen = xid_generator()
    packet = ethernet(src=EthAddr("00:00:00:00:00:01"), dst=EthAddr("00:00:00:00:00:02"),
            payload=ipv4(srcip=IPAddr("1.2.3.4"), dstip=IPAddr("1.2.3.5"),
                payload=udp(srcport=1234, dstport=53, payload=b"haha"))).pack()

    for actions in self.some_actions:
      for attrs in ( { 'data': packet }, { 'buffer_id': 5 } ):
        xid = xid_gen()
        o = ofp_packet_out(xid=xid, actions=actions, **attrs)
        self._test_pack_unpack(o, xid, OFPT_PACKET_OUT)

  def test_pack_flow_mod_openflow_dl_type_wildcards(self):
    """ Openflow 1.1 spec clarifies that wildcards should not be set when the protocol in
        question is not matched i.e., dl_type != 0x800 -> no wildcards for IP.
        Test this here """
    def show_wildcards(w):
      parts = [ k.lower()[len("OFPFW_"):] for (k,v) in ofp_flow_wildcards_rev_map.items() if v & w == v ]
      nw_src_bits = (w & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
      nw_src_bits = (w & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
      if(nw_src_bits > 0): parts.append("nw_src(/%d)" % (32 - nw_src_bits))

      nw_dst_bits = (w & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
      if(nw_dst_bits > 0): parts.append("nw_dst(/%d)" % (32 - nw_dst_bits))
      return "|".join(parts)

    def test_wildcards(match, expected):
      (packed,) = struct.unpack_from("!L", match.pack(flow_mod=True))
      self.assertEquals(packed, expected, "packed: %s <> expected: %s" % (show_wildcards(packed), show_wildcards(expected)))

    # no dl type specified -> wildcards for nw/dl are cleared
    test_wildcards(ofp_match(), OFPFW_ALL & ~ (OFPFW_NW_TOS | OFPFW_NW_PROTO | OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK | OFPFW_TP_SRC | OFPFW_TP_DST))
    all_normalized = (OFPFW_ALL & ~ (OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK)) | \
            OFPFW_NW_SRC_ALL | OFPFW_NW_DST_ALL

    # dl type = ARP -> certain wildcards live
    test_wildcards(ofp_match(dl_type=0x806), all_normalized & ~ (OFPFW_NW_TOS | OFPFW_TP_SRC | OFPFW_TP_DST | OFPFW_DL_TYPE))
    # dl type = IP -> more wildcards live
    test_wildcards(ofp_match(dl_type=0x800), all_normalized & ~ (OFPFW_TP_SRC | OFPFW_TP_DST | OFPFW_DL_TYPE))
    # dl type = IP, nw_proto=UDP -> alll wildcards live
    test_wildcards(ofp_match(dl_type=0x800,nw_proto=6), all_normalized & ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO))


  def test_pack_custom_flow_mod(self):
    out = ofp_action_output
    xid_gen = xid_generator()

    for match in ( ofp_match(),
        ofp_match(in_port=1, dl_type=0x88cc, dl_src=EthAddr("00:00:00:00:00:01"), dl_dst=EthAddr("00:00:00:00:00:02")),
        ofp_match(in_port=1, dl_type=0x0806, dl_src=EthAddr("00:00:00:00:00:01"), dl_dst=EthAddr("00:00:00:00:00:02"), nw_src="10.0.0.1", nw_dst="11.0.0.1"),
        ofp_match(in_port=1, dl_type=0x0800, dl_src=EthAddr("00:00:00:00:00:01"), dl_dst=EthAddr("00:00:00:00:00:02"), dl_vlan=5, nw_proto=6, nw_src="10.0.0.1", nw_dst="11.0.0.1", tp_src = 12345, tp_dst=80)):
      for actions in self.some_actions:
        for command in ( OFPFC_ADD, OFPFC_DELETE, OFPFC_DELETE_STRICT, OFPFC_MODIFY_STRICT, OFPFC_MODIFY_STRICT ):
          for attrs in ( {}, { 'buffer_id' : 123 }, { 'idle_timeout': 5, 'hard_timeout': 10 } ):
            xid = xid_gen()
            o = ofp_flow_mod(xid=xid, command=command, match = match, actions=actions, **attrs)
            unpacked = self._test_pack_unpack(o, xid, OFPT_FLOW_MOD)

            self.assertEqual(unpacked.match, match)
            self.assertEqual(unpacked.command, command)
            self.assertEqual(unpacked.actions, actions)
            for (check_attr,val) in attrs.items():
              self.assertEqual(getattr(unpacked, check_attr), val)

class ofp_action_test(unittest.TestCase):
  def assert_packed_action(self, cls, packed, a_type, length):
    self.assertEqual(extract_num(packed, 0,2), a_type, "Action %s: expected type %d (but is %d)" % (cls, a_type, extract_num(packed, 0,2)))
    self.assertEqual(extract_num(packed, 2,2), length, "Action %s: expected length %d (but is %d)" % (cls, length, extract_num(packed, 2,2)))

  def test_pack_all_actions_simple(self):
    def c(cls, a_type, kw, length):
      action = cls(**kw)
      packed = action.pack()
      self.assertEqual(len(action), len(packed))
      self.assert_packed_action(cls, packed, a_type, length)
      unpacked = cls()
      unpacked.unpack(packed)
      self.assertEqual(action, unpacked)
      for (k, v) in kw.items():
        self.assertEqual(getattr(unpacked, k), v)
      return packed


    c(ofp_action_output, OFPAT_OUTPUT, { 'port': 23 }, 8 )
    c(ofp_action_enqueue, OFPAT_ENQUEUE, { 'port': 23, 'queue_id': 1 }, 16 )
    c(ofp_action_vlan_vid, OFPAT_SET_VLAN_VID, { 'vlan_vid' : 123}, 8 )
    c(ofp_action_vlan_pcp, OFPAT_SET_VLAN_PCP, { 'vlan_pcp' : 123}, 8 )
    p = c(ofp_action_dl_addr.set_dst, OFPAT_SET_DL_DST, { 'dl_addr' : EthAddr("01:02:03:04:05:06").toRaw() }, 16 )
    self.assertEquals(extract_num(p, 4,6), 0x010203040506)
    p = c(ofp_action_dl_addr.set_src, OFPAT_SET_DL_SRC, { 'dl_addr' : EthAddr("ff:ee:dd:cc:bb:aa").toRaw() }, 16 )
    self.assertEquals(extract_num(p, 4,6), 0xffeeddccbbaa, "Ethernet in packed is %x, but should be ff:ee:dd:cc:bb:aa" % extract_num(p, 4, 6))
    p = c(ofp_action_nw_addr.set_dst, OFPAT_SET_NW_DST, { 'nw_addr' : IPAddr("1.2.3.4") }, 8 )
    self.assertEquals(extract_num(p, 4,4), 0x01020304)
    p = c(ofp_action_nw_addr.set_src, OFPAT_SET_NW_SRC, { 'nw_addr' : IPAddr("127.0.0.1") }, 8 )
    self.assertEquals(extract_num(p, 4,4), 0x7f000001)
    c(ofp_action_nw_tos, OFPAT_SET_NW_TOS, { 'nw_tos' : 4 }, 8)
    p = c(ofp_action_tp_port.set_dst, OFPAT_SET_TP_DST, { 'tp_port' : 80 }, 8)
    self.assertEquals(extract_num(p, 4,2), 80)
    p = c(ofp_action_tp_port.set_src, OFPAT_SET_TP_SRC, { 'tp_port' : 22987 }, 8)
    self.assertEquals(extract_num(p, 4,2), 22987)
#    c(ofp_action_push_mpls, OFPAT_PUSH_MPLS, {'ethertype':0x8847}, 8)
#    c(ofp_action_pop_mpls, OFPAT_POP_MPLS, {'ethertype':0x0800}, 8)
#    c(ofp_action_mpls_dec_ttl, OFPAT_DEC_MPLS_TTL, {}, 8)
#    c(ofp_action_mpls_label, OFPAT_SET_MPLS_LABEL, {'mpls_label': 0xa1f}, 8)
#    c(ofp_action_mpls_tc, OFPAT_SET_MPLS_TC, {'mpls_tc': 0xac}, 8)
#    c(ofp_action_mpls_ttl, OFPAT_SET_MPLS_TTL, {'mpls_ttl': 0xaf}, 8)

if __name__ == '__main__':
  unittest.main()
