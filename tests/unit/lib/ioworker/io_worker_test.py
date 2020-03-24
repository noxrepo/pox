#!/usr/bin/env python
#
# Copyright 2011-2012 Andreas Wundsam
# Copyright 2011-2012 Colin Scott
# Copyright 2011-2013 James McCauley
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

import itertools
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__),
    *itertools.repeat("..", 3)))

from pox.lib.mock_socket import MockSocket
from pox.lib.ioworker import IOWorker, RecocoIOLoop
from nose.tools import eq_

class IOWorkerTest(unittest.TestCase):
  def test_basic_send(self):
    i = IOWorker()
    i.send(b"foo")
    self.assertTrue(i._ready_to_send)
    self.assertEqual(i.send_buf, b"foo")
    i._consume_send_buf(3)
    self.assertFalse(i._ready_to_send)

  def test_basic_receive(self):
    i = IOWorker()
    self.data = None
    def d(worker):
      self.data = worker.peek()
    i.rx_handler = d
    i._push_receive_data(b"bar")
    self.assertEqual(self.data, b"bar")
    # d does not consume the data
    i._push_receive_data(b"hepp")
    self.assertEqual(self.data, b"barhepp")

  def test_receive_consume(self):
    i = IOWorker()
    self.data = None
    def consume(worker):
      self.data = worker.peek()
      worker.consume_receive_buf(len(self.data))
    i.rx_handler = consume
    i._push_receive_data(b"bar")
    self.assertEqual(self.data, b"bar")
    # data has been consumed
    i._push_receive_data(b"hepp")
    self.assertEqual(self.data, b"hepp")


class RecocoIOLoopTest(unittest.TestCase):
  def test_basic(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    loop.new_worker(left)

  def test_stop(self):
    loop = RecocoIOLoop()
    loop.stop()

  def test_run_read(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.new_worker(left)

    # callback for ioworker to record receiving
    self.received = None
    def r(worker):
      self.received = worker.peek()
    worker.rx_handler = r

    # 'start' the run (dark generator magic here).
    # Does not actually execute run, but 'yield' a generator
    g = loop.run()
    # g.next() will call it, and get as far as the 'yield select'
    select = next(g)

    # send data on other socket half
    right.send(b"hallo")

    # now we emulate the return value of the select ([rlist],[wlist], [elist])
    g.send(([worker], [], []))

    # that should result in the socket being red the data being handed
    # to the ioworker, the callback being called. Everybody happy.
    self.assertEqual(self.received, b"hallo")

  def test_run_close(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.new_worker(left)

    self.assertFalse(worker in loop._workers,
        "Should not add to _workers yet, until we start up the loop")
    self.assertTrue(len(loop._pending_commands) == 1,
        "Should have added pending create() command")
    worker.close()
    # This causes the worker to be scheduled to be closed -- it also
    # calls pinger.ping(). However, the Select task won't receive the ping
    # Until after this method has completed! Thus, we only test whether
    # worker has been added to the pending close queue
    self.assertTrue(len(loop._pending_commands) == 2,
        "Should have added pending close() command")

  def test_run_write(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.new_worker(left)

    worker.send(b"heppo")
    # 'start' the run (dark generator magic here).
    # Does not actually execute run, but 'yield' a generator
    g = loop.run()
    # g.next() will call it, and get as far as the 'yield select'
    select = next(g)

    # now we emulate the return value of the select ([rlist],[wlist], [elist])
    g.send(([], [worker], []))

    # that should result in the stuff being sent on the socket
    self.assertEqual(right.recv(), b"heppo")
