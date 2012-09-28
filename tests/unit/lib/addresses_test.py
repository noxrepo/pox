# Copyright 2012 Colin Scott
# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.


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

