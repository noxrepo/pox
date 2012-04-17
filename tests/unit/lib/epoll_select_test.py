#!/usr/bin/env python

import unittest
import sys
import os.path
import SocketServer
import threading
import socket
import signal

from copy import copy

sys.path.append(os.path.dirname(__file__) + "/../../..")

from pox.lib.epoll_select import EpollSelect

class TCPEcho(SocketServer.StreamRequestHandler):
  def handle(self):
    data = self.rfile.readline()
    print "got data: %s" % data
    self.wfile.write(data)

class ForkingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
  def start(self):
    self.pid = os.fork()
    if self.pid == 0:
      # child
      self.serve_forever()

  def stop(self):
    os.kill(self.pid, signal.SIGKILL)

def sort_fdlists(rl,wl,xl) :
  key = lambda(x): x.fileno() if hasattr(x, "fileno") else x

  return (
            sorted(rl, key=key),
            sorted(wl, key=key),
            sorted(xl, key=key)
        )

class EpollSelectTest(unittest.TestCase):
  def setUp(self):
    self.es = EpollSelect()
    self.server = ForkingTCPServer(("localhost", 0), TCPEcho)
    self.ip, self.port = self.server.server_address
    self.server.start()

  def tearDown(self):
    self.es.close()
    self.server.stop()

  def test_create(self):
    pass

  def test_read_one_socket(self):
    c = socket.create_connection( (self.ip, self.port))
    ret  = self.es.select([c], [], [c], 0.1)
    self.assertEqual(([],[],[]), ret)
    # socket is ready to send?
    ret  = self.es.select([c], [c], [c], 0.1)
    self.assertEqual(([],[c],[]), ret)
    # send stuff
    c.send("Hallo\n")
    # now we have something to read, right?
    ret  = self.es.select([c], [], [c], 0.5)
    self.assertEqual(([c],[],[]), ret)

  def test_write_more_sockets(self):
    c1 = socket.create_connection( (self.ip, self.port))
    c2 = socket.create_connection( (self.ip, self.port))
    c3 = socket.create_connection( (self.ip, self.port))
    # note don't throw away the socket -- else it will be garbage collected
    raw = c3.fileno()
    seq = [ [c1], [c2], [c1,c2], [c1,c2, raw], [c1], [raw]]

    check = lambda a,b: self.assertEqual(sort_fdlists(*a), sort_fdlists(*b))

    #just the writes
    for sockets in seq:
     check(([],sockets,[]),self.es.select(sockets, sockets, sockets, 0))

    # writes and reads in different order
    for sockets in seq:
      check( ([],[],[]), self.es.select(sockets, [], sockets, 0))
      check( ([],sockets,[]), self.es.select(sockets, sockets, sockets, 0))

if __name__ == '__main__':
  unittest.main()
