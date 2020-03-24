# Copyright 2012 Colin Scott
# Copyright 2012,2013 James McCauley
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
from pox.lib.addresses import *
from copy import copy

try:
  import nose
  _fail_decorator = nose.tools.raises(RuntimeError)
except:
  _fail_decorator = unittest.expectedFailure


class MockEthAddrTest(unittest.TestCase):
  def test_basic(self):
    self.assertEqual("00:11:22:33:44:55", str(EthAddr("00:11:22:33:44:55")),
        "str(eth) doesn't match original string")

  def test_oui_lookup (self):
    e = EthAddr("00-10-fa-c2-bf-d5")
    s = e.to_str(resolve_names=True)
    self.assertEqual(s, "Apple Inc:c2:bf:d5")

#  def test_int_ctor(self):
#    int_val = EthAddr("00:00:00:00:01:00").toInt()
#    self.assertEqual(int_val, 1<<8)
#    with_int_ctor = EthAddr(int_val)
#    self.assertEqual(int_val, with_int_ctor.toInt())
#    self.assertEqual(str(with_int_ctor), "00:00:00:00:01:00")

class MockIPAddrTest (unittest.TestCase):
  def test_in_network (self):
    self.assertTrue(IPAddr("192.168.1.1").inNetwork("192.168.1.0/24"))

  def test_multicast (self):
    self.assertTrue(str(IPAddr("224.0.0.9").multicast_ethernet_address)
        == "01:00:5e:00:00:09")

  @_fail_decorator
  def test_bad_cidr_fail (self):
    parse_cidr("192.168.1.0/16", infer=False, allow_host=False)

  def test_bad_cidr_succeed (self):
    a,b=parse_cidr("192.168.1.0/255.255.255.0", infer=False, allow_host=False)
    self.assertEqual(a,IPAddr("192.168.1.0"))
    self.assertEqual(b,24)

  def test_byte_order (self):
    self.assertEqual(IPAddr(IPAddr('1.2.3.4').toSigned()).raw,
        b'\x01\x02\x03\x04')

#TODO: Clean up these IPv6 tests
class IPv6Tests (unittest.TestCase):
  def test_basics_part1 (self):
    """
    Basic IPv6 address tests (part 1)
    """
    a = IPAddr6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    assert str(a) == '2001:db8:85a3::8a2e:370:7334','minimal repr'
    assert a.to_str(zero_drop=False) == \
        '2001:0db8:85a3::8a2e:0370:7334', 'no zero drop'
    assert a.to_str(section_drop=False) == \
        '2001:db8:85a3:0:0:8a2e:370:7334', 'no section drop'
    assert a.to_str(section_drop=False, zero_drop=False) == \
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'full length'
    assert str(IPAddr6('0:0:0:0:0:0:0:1')) == '::1', 'loopback'
    assert str(IPAddr6('0:0:0:0:0:0:0:0')) == '::', 'unspecified'
    assert str(IPAddr6('2001:db8:0:0:0:0:2:1')) == '2001:db8::2:1'
    assert str(IPAddr6('2001:db8:0000:1:1:1:1:1')) == '2001:db8:0:1:1:1:1:1'
    assert str(IPAddr6('2001:db8:0:0:1:0:0:1')) == '2001:db8::1:0:0:1'
    assert str(IPAddr6('1:0:0:2:0:0:0:3')) == '1:0:0:2::3'

  def test_part2 (self):
    """
    Basic IPv6 address tests (part 2)
    """
    h = b'\xfe\x80\x00\x00\x00\x00\x00\x00\xba\x8d\x12\xff\xfe\x2a\xdd\x6e'
    a = IPAddr6.from_raw(h)
    assert str(a) == 'fe80::ba8d:12ff:fe2a:dd6e'
    assert a.raw == h

    assert a.num == 0xfe80000000000000ba8d12fffe2add6e
    assert IPAddr6.from_num(a.num) == a

    assert a.is_multicast is False
    assert IPAddr6("FF02:0:0:0:0:0:0:1").is_multicast

    assert IPAddr6('2001:db8:1:2::').set_mac('00:1D:BA:06:37:64') \
        == '2001:db8:1:2:021d:baff:fe06:3764'

    assert IPAddr6('0:0:0:0:0:FFFF:222.1.41.90') == '::ffff:222.1.41.90'
    assert IPAddr6('::ffff:C0A8:5') == '::ffff:192.168.0.5'
    assert IPAddr6('::ffff:192.168.0.5') == '::ffff:c0a8:5'
