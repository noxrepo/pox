#!/usr/bin/env python
### auto generate sha1: 26c6550c27d0274b9338b2b85891aeaf01146ed8

import itertools
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), *itertools.repeat("..", 3)))

from pox.lib.mock_socket import MockSocket
from pox.lib.ioworker.io_worker import IOWorker, RecocoIOLoop
from nose.tools import eq_

class IOWorkerTest(unittest.TestCase):
  def test_basic_send(self):
    i = IOWorker()
    i.send("foo")
    self.assertTrue(i._ready_to_send)
    self.assertEqual(i.send_buf, "foo")
    i._consume_send_buf(3)
    self.assertFalse(i._ready_to_send)

  def test_basic_receive(self):
    i = IOWorker()
    self.data = None
    def d(worker):
      self.data = worker.peek_receive_buf()
    i.set_receive_handler(d)
    i._push_receive_data("bar")
    self.assertEqual(self.data, "bar")
    # d does not consume the data
    i._push_receive_data("hepp")
    self.assertEqual(self.data, "barhepp")

  def test_receive_consume(self):
    i = IOWorker()
    self.data = None
    def consume(worker):
      self.data = worker.peek_receive_buf()
      worker.consume_receive_buf(len(self.data))
    i.set_receive_handler(consume)
    i._push_receive_data("bar")
    self.assertEqual(self.data, "bar")
    # data has been consumed
    i._push_receive_data("hepp")
    self.assertEqual(self.data, "hepp")


class RecocoIOLoopTest(unittest.TestCase):
  def test_basic(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    loop.create_worker_for_socket(left)

  def test_stop(self):
    loop = RecocoIOLoop()
    loop.stop()

  def test_run_read(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.create_worker_for_socket(left)

    # callback for ioworker to record receiving
    self.received = None
    def r(worker):
      self.received = worker.peek_receive_buf()
    worker.set_receive_handler(r)

    # 'start' the run (dark generator magic here). Does not actually execute run, but 'yield' a generator
    g = loop.run()
    # g.next() will call it, and get as far as the 'yield select'
    select = g.next()

    # send data on other socket half
    right.send("hallo")

    # now we emulate the return value of the select ([rlist],[wlist], [elist])
    g.send(([worker], [], []))

    # that should result in the socket being red the data being handed
    # to the ioworker, the callback being called. Everybody happy.
    self.assertEquals(self.received, "hallo")

  def test_run_close(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.create_worker_for_socket(left)

    self.assertFalse(worker in loop._workers,  "Should not add to _workers yet, until we start up the loop")
    self.assertTrue(loop._pending_commands.qsize() == 1, "Should have added pending create() command")
    worker.close()
    # This causes the worker to be scheduled to be closed -- it also 
    # calls pinger.ping(). However, the Select task won't receive the ping
    # Until after this method has completed! Thus, we only test whether
    # worker has been added to the pending close queue
    self.assertTrue(loop._pending_commands.qsize() == 2, "Should have added pending close() command")

  def test_run_write(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.create_worker_for_socket(left)

    worker.send("heppo")
    # 'start' the run (dark generator magic here). Does not actually execute run, but 'yield' a generator
    g = loop.run()
    # g.next() will call it, and get as far as the 'yield select'
    select = g.next()

    # now we emulate the return value of the select ([rlist],[wlist], [elist])
    g.send(([], [worker], []))

    # that should result in the stuff being sent on the socket
    self.assertEqual(right.recv(), "heppo")

