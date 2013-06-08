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


class PCapWriter (object):
  def __init__ (self, outstream, socket = None, flush = False,
                local_addrs = (None,None,None),
                remote_addrs = (None,None,None)):
    """
    outstream is the stream to write the PCAP trace to.
    Ethernet addresses have to be faked, and it can be convenient to
    fake IP and TCP addresses as well.  Thus, you can specify local_addrs
    or remote_addrs.  These are tuples of (EthAddr, IPAddr, TCPPort).
    Any item that is None gets a default value.
    """
    self._out = outstream
    self._flush = flush

    if socket is not None:
      remote = socket.getpeername()
      local = socket.getsockname()
    else:
      remote = ("1.1.1.1",1)
      local = ("0.0.0.0",0)

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
      local_addrs[0] or EthAddr("\x02" + "\x00" * 5),
      remote_addrs[0] or EthAddr("\x02" + "\x11" * 5),
      local_addrs[1] or IPAddr(local[0]),
      remote_addrs[1] or IPAddr(remote[0]),
      local_addrs[2] or local[1],
      remote_addrs[2] or remote[1],
      )

    self._s_to_c = create_packet(
      remote_addrs[0] or EthAddr("\x02" + "\x11" * 5),
      local_addrs[0] or EthAddr("\x02" + "\x00" * 5),
      remote_addrs[1] or IPAddr(remote[0]),
      local_addrs[1] or IPAddr(local[0]),
      remote_addrs[2] or remote[1],
      local_addrs[2] or local[1],
      )

    outstream.write(pack("IHHiIII",
      0xa1b2c3d4,    # Magic
      2,4,           # Version
      time.timezone, # TZ offset
      0,             # Accuracy of timestamps (apparently 0 is OK)
      0x7fffFFff,    # Snaplen
      1              # Ethernet
      ))

  def write (self, outgoing, buf):
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
    if self._flush: self._out.flush()

    e.next.next.seq += l
    e2.next.next.ack += l


class CaptureSocket (SocketWedge):
  """
  Wraps a TCP socket and writes a faked PCAP format trace
  """
  def __init__ (self, socket, outstream, close = True,
                local_addrs = (None,None,None),
                remote_addrs = (None,None,None)):
    """
    socket is the socket to be wrapped.
    outstream is the stream to write the PCAP trace to.
    Ethernet addresses have to be faked, and it can be convenient to
    fake IP and TCP addresses as well.  Thus, you can specify local_addrs
    or remote_addrs.  These are tuples of (EthAddr, IPAddr, TCPPort).
    Any item that is None gets a default value.
    """
    super(CaptureSocket, self).__init__(socket)
    self._close = close
    self._writer = PCapWriter(outstream, socket=socket,
                              local_addrs=local_addrs,
                              remote_addrs=remote_addrs)


  def _recv_out (self, buf):
    try:
      self._writer.write(False, buf)
    except Exception:
      pass

  def _send_out (self, buf, r):
    try:
      self._writer.write(True, buf[:r])
    except Exception:
      pass

  def close (self, *args, **kw):
    if self._close:
      try:
        self._writer._out.close()
      except Exception:
        pass
    return self._socket.close(*args, **kw)


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
