# Copyright 2012 Colin Scott
# Copyright 2012 James McCauley
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

class MockEthAddrTest(unittest.TestCase):
  def test_basic(self):
    self.assertEqual("00:11:22:33:44:55", str(EthAddr("00:11:22:33:44:55")), "str(eth) doesn't match original string")

#  def test_int_ctor(self):
#    int_val = EthAddr("00:00:00:00:01:00").toInt()
#    self.assertEqual(int_val, 1<<8)
#    with_int_ctor = EthAddr(int_val)
#    self.assertEqual(int_val, with_int_ctor.toInt())
#    self.assertEqual(str(with_int_ctor), "00:00:00:00:01:00")

class MockIPAddrTest (unittest.TestCase):
  def test_in_network (self):
    self.assertTrue(IPAddr("192.168.1.1").inNetwork("192.168.1.0/24"))

