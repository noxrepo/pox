#!/usr/bin/env python

import unittest
import sys
import os.path
from copy import copy

sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.openflow.libopenflow_01 import *

def match(**kw):
  m = ofp_match(wildcards=0, in_port=1, dl_type=0, dl_src=EthAddr("00:00:00:00:00:01"), dl_dst=EthAddr("00:00:00:00:00:02"), dl_vlan=5, nw_proto=6, nw_src="10.0.0.1", nw_dst="11.0.0.1", tp_src = 12345, tp_dst=80)
  assert(m.wildcards == 0)
  for (k,v) in kw.iteritems():
    m.__setattr__(k,v)
  return m

class ofp_match_test(unittest.TestCase):
  def test_match_with_wildcards(self):
    ref = match()
    self.assertTrue(ref.matches_with_wildcards(ref))

    for wildcards in ( OFPFW_IN_PORT, OFPFW_DL_VLAN, OFPFW_DL_SRC | OFPFW_DL_DST ):
      c =match(wildcards=wildcards)
      self.assertTrue(c.matches_with_wildcards(ref), "ref %s should match %s"% (c.show(), ref.show()))

    c = match(wildcards=OFPFW_IN_PORT)
    ref = match(in_port=15)
    self.assertTrue(c.matches_with_wildcards(ref), "ref %s should match %s"% (c.show(), ref.show()))

if __name__ == '__main__':
  unittest.main()
