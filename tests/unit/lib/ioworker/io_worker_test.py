#!/usr/bin/env python
### auto generate sha1: 26c6550c27d0274b9338b2b85891aeaf01146ed8

import itertools
import json
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), *itertools.repeat("..", 3)))

from pox.lib.mock_socket import MockSocket
from pox.lib.ioworker.io_worker import IOWorker, RecocoIOLoop, LineIOWorker, JSONIOWorker
from nose.tools import eq_

class MockIOWorker:
  def set_receive_handler(self, handler):
    self.handler = handler
    self.buf = ""
    self.sends = []

  def send(self, data):
    self.sends.append(data)

  def receive(self, data):
    self.buf += data
    self.handler(self)

  def peek_receive_buf(self):
    return self.buf

  def consume_receive_buf(self, l):
    assert(len(self.buf)>=l)
    self.buf = self.buf[l:]


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

class LineIOWorkerTest(unittest.TestCase):
  def test_send(self):
    m = MockIOWorker()
    l = LineIOWorker(m)
    l.send_line("Hallo")
    l.send_line("This is a test")
    self.assertEqual(m.sends, [ "Hallo\n", "This is a test\n" ])

  def test_receive_line_end(self):
    for line_end in ('\r\n', '\n', '\r'):
      rec_lines = []
      on_line_received = lambda self, line: rec_lines.append(line)

      m = MockIOWorker()
      l = LineIOWorker(m)
      l.on_line_received = on_line_received
      # as long as line is not completed, no calls to received
      m.receive("test")
      self.assertEquals(rec_lines, [])
      # line completed, junk at the end not send
      m.receive("end{}somemore".format(line_end))
      self.assertEquals(rec_lines, ["testend"])
      # 2nd line completed, and a 3rd empty line
      m.receive("more{}{}".format(line_end, line_end))
      self.assertEquals(rec_lines, ["testend", "somemoremore", ""])
      # a 4th empty line by itself
      m.receive(line_end)
      self.assertEquals(rec_lines, ["testend", "somemoremore", "", ""])

class JSONIOWorkerTest(unittest.TestCase):
  data = {'hello': 'this is a test\nwith some tricks', 'array': ['an', 1, 'array' ] }
  data2 = ['another message', None, ["just", "to", "annoy", "people"]]
  floodlight_data = {"name":"role","value":"MASTER","fingerPrint":"role=MASTER","type":"ASYNC","time":{"seconds":1347830756,"microSeconds":474865},"xid":1,"messageClass":"StateChange"}
  floodlight_json_str = r'{"name":"role","value":"MASTER","fingerPrint":"role=MASTER","type":"ASYNC","time":{"seconds":1347830756,"microSeconds":474865},"xid":1,"messageClass":"StateChange"}'


  def test_send(self):
    _eq = self.assertEquals

    m = MockIOWorker()
    j = JSONIOWorker(m)
    j.send(self.data)

    _eq(1, len(m.sends))
    _eq(self.data, json.loads(m.sends[0]))
    j.send(self.data2)
    _eq(2, len(m.sends))
    _eq(self.data2, json.loads(m.sends[1]))
    j.send(self.floodlight_data)
    _eq(3, len(m.sends))
    _eq(self.floodlight_data, json.loads(m.sends[2]))
    # some integrity check on the whole byte array representation
    all = "".join(m.sends)
    _eq(3, all.count('\n'))
    _eq(True, all.endswith('\n'))

  def test_receive(self):
    _eq = self.assertEquals

    class JSONReceiver(object):
      def __init__(self):
        self.recs = []
        self.rec_count = 0

      def __call__(self, worker, json):
        self.recs.append(json)
        self.rec_count += 1

    m = MockIOWorker()
    j = JSONIOWorker(m)
    receiver = JSONReceiver()
    j.on_json_received = receiver

    # no newline -> not received yet
    m.receive(self.floodlight_json_str)
    _eq(0, receiver.rec_count)
    m.receive('\n')
    _eq(1, receiver.rec_count)
    _eq(receiver.recs.pop(0), self.floodlight_data)
    # 2 messages at the same time
    m.receive("%s\n%s\n" %  (json.dumps(self.data), json.dumps(self.data2)))
    _eq(3, receiver.rec_count)
    _eq(receiver.recs.pop(0), self.data)
    _eq(receiver.recs.pop(0), self.data2)


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
    worker = loop.new_worker(left)

    # callback for ioworker to record receiving
    self.received = None
    def r(worker):
      self.received = worker.peek()
    worker.rx_handler = r

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
    worker = loop.new_worker(left)

    self.assertFalse(worker in loop._workers,  "Should not add to _workers yet, until we start up the loop")
    self.assertTrue(len(loop._pending_commands) == 1, "Should have added pending create() command")
    worker.close()
    # This causes the worker to be scheduled to be closed -- it also 
    # calls pinger.ping(). However, the Select task won't receive the ping
    # Until after this method has completed! Thus, we only test whether
    # worker has been added to the pending close queue
    self.assertTrue(len(loop._pending_commands) == 2, "Should have added pending close() command")

  def test_run_write(self):
    loop = RecocoIOLoop()
    (left, right) = MockSocket.pair()
    worker = loop.new_worker(left)

    worker.send("heppo")
    # 'start' the run (dark generator magic here). Does not actually execute run, but 'yield' a generator
    g = loop.run()
    # g.next() will call it, and get as far as the 'yield select'
    select = g.next()

    # now we emulate the return value of the select ([rlist],[wlist], [elist])
    g.send(([], [worker], []))

    # that should result in the stuff being sent on the socket
    self.assertEqual(right.recv(), "heppo")

