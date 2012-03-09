#!/usr/bin/env python

import unittest
import sys
import os.path
from copy import copy

sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.lib.mock_socket import MockSocket

class MockSocketTest(unittest.TestCase):
  def setUp(self):
    pass

  def test_simple_send(self):
    (a, b) = MockSocket.pair()
    a.send("Hallo")
    self.assertEquals(b.recv(), "Hallo")
    b.send("Servus")
    self.assertEquals(a.recv(), "Servus")

  def test_ready_to_recv(self):
    (a, b) = MockSocket.pair()
    a.send("Hallo")
    self.assertFalse(a.ready_to_recv())
    self.assertTrue(b.ready_to_recv())
    self.assertEquals(b.recv(), "Hallo")
    self.assertFalse(b.ready_to_recv())

    self.assertFalse(a.ready_to_recv())
    b.send("Servus")
    self.assertTrue(a.ready_to_recv())
    self.assertEquals(a.recv(), "Servus")
    self.assertFalse(a.ready_to_recv())

  def test_on_ready_to_recv(self):
    self.seen_size = -1
    self.called = 0
    def ready(socket, size):
      self.called += 1
      self.seen_size = size

    (a, b) = MockSocket.pair()
    b.set_on_ready_to_recv(ready)
    self.assertEquals(self.called, 0)
    a.send("Hallo")
    self.assertEquals(self.called, 1)
    self.assertEquals(self.seen_size, 5)

    # check that it doesn't get called on the other sockets data
    b.send("Huhu")
    self.assertEquals(self.called, 1)

  def test_empty_recv(self):
    """ test_empty_recv: Check that empty reads on socket return ""
       Note that this is actually non-sockety behavior and should probably be changed. This
       test documents it as intended for now, though
    """
    (a, b) = MockSocket.pair()
    self.assertEquals(a.recv(), "")

if __name__ == '__main__':
  unittest.main()
