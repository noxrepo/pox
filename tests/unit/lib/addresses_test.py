'''
Created on Apr 7, 2012

@author: cs
'''

import unittest
import sys
import os.path
from pox.lib.addresses import *
from copy import copy

class MockEthAddrTest(unittest.TestCase):
  def test_basic(self):
    self.assertEqual("00:11:22:33:44:55", EthAddr("00:11:22:33:44:55").toStr(), "toString doesn't match original string")
    
  def test_int_ctor(self):
    int_val = EthAddr("00:00:00:00:01:00").toInt()
    self.assertEqual(int_val, 1<<8)
    with_int_ctor = EthAddr(int_val) 
    self.assertEqual(int_val, with_int_ctor.toInt())
    self.assertEqual(str(with_int_ctor), "00:00:00:00:01:00")