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

from pox.lib.addresses import *
import pox.lib.packet as pkt

from struct import pack
import time


class SocketWedge (object):
  def __init__ (self, socket):
    self._socket = socket

  def send (self, string, *args, **kw):
    r = self._socket.send(string, *args, **kw)
    self._send_out(string, r)
    return r

  def recv (self, bufsize, *args, **kw):
    r = self._socket.recv(bufsize, *args, **kw)
    self._recv_out(r)
    return r

  def __getattr__ (self, n):
    return getattr(self._socket, n)


class CaptureSocket (SocketWedge):
  from struct import pack
  import time
  def __init__ (self, socket, outstream):
    super(CaptureSocket, self).__init__(socket)
    remote = socket.getpeername()
    local = socket.getsockname()

    def create_packet (e1,e2,i1,i2,t1,t2):
      e = pkt.ethernet(
          src = e1,
          dst = e2,
          type = pkt.ethernet.IP_TYPE)
      i = pkt.ipv4(
          srcip = i1,
          dstip = i2,
          protocol = pkt.ipv4.TCP_PROTOCOL)
      t = pkt.tcp(
          srcport = t1,
          dstport = t2,
          off = 5,
          win = 1)
      t.ACK = True
      i.payload = t
      e.payload = i
      return e


    self._c_to_s = create_packet(
      EthAddr("\x02" + "\x00" * 5),
      EthAddr("\x02" + "\x11" * 5),
      IPAddr(local[0]),
      IPAddr(remote[0]),
      6633, # Always use this to make sure Wireshark gets it
      remote[1])

    self._s_to_c = create_packet(
      EthAddr("\x02" + "\x11" * 5),
      EthAddr("\x02" + "\x00" * 5),
      IPAddr(remote[0]),
      IPAddr(local[0]),
      remote[1],
      6633) # Always use this to make sure Wireshark gets it

    self._out = outstream
    outstream.write(pack("IHHiIII",
      0xa1b2c3d4,    # Magic
      2,4,           # Version
      time.timezone, # TZ offset
      0,             # Accuracy of timestamps (apparently 0 is OK)
      0x7fffFFff,    # Snaplen
      1              # Ethernet
      ))

  def _write (self, outgoing, buf):
    if len(buf) == 0: return
    e = self._c_to_s if outgoing else self._s_to_c
    e2 = self._c_to_s if not outgoing else self._s_to_c
    l = len(buf)
    e.payload.payload.payload = buf
    buf = e.pack()

    t = time.time()
    ut = t - int(t)
    t = int(t)
    ut = int(ut * 1000000)
    self._out.write(pack("IIII",
      t,ut,          # Timestamp
      len(buf),      # Saved size
      len(buf),      # Original size
      ))

    self._out.write(buf)
    self._out.flush()

    e.next.next.seq += l
    e2.next.next.ack += l

  def _recv_out (self, buf):
    self._write(False, buf)

  def _send_out (self, buf, r):
    self._write(True, buf[:r])




if __name__ == "__main__":
  """
  Test with:
  nc -v -v -l 9933
  """
  import socket
  sock = socket.create_connection(("127.0.0.1",9933))
  s = CaptureSocket(sock, file("test.pcap", "w"))
  while True:
    d = s.recv(1024)
    d = d.upper()
    import sys
    import time
    import random
    time.sleep(random.random() * 1.5)
    sys.stdout.write(d)
    s.send(d)

