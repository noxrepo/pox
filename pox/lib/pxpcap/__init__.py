# Copyright 2011,2013 James McCauley
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

enabled = False
try:
  import platform
  import importlib
  _module = 'pox.lib.pxpcap.%s.pxpcap' % (platform.system().lower(),)
  pcapc = importlib.import_module(_module)
  enabled = True
except:
  # Try generic...
  try:
    import pxpcap as pcapc
    enabled = True
  except:
    # We can at least import the rest
    pass

from pox.lib.addresses import IPAddr, EthAddr, IPAddr6
import parser
from threading import Thread, Lock
import pox.lib.packet as pkt
import copy

# pcap's filter compiling function isn't threadsafe, so we use this
# lock when compiling filters.
_compile_lock = Lock()

class PCap (object):
  use_select = False # Falls back to non-select

  @staticmethod
  def get_devices ():
    def ip (addr):
      if addr is None: return None
      return IPAddr(addr, networkOrder=True)
    def ip6 (addr):
      if addr is None: return None
      return IPAddr6.from_raw(addr)
    def link (addr):
      if addr is None: return None
      if len(addr) != 6: return None
      return EthAddr(addr)
    devs = pcapc.findalldevs()
    out = {}
    for d in devs:
      addrs = {}
      n = {'desc':d[1],'addrs':addrs}
      out[d[0]] = n
      for a in d[2]:
        if a[0] == 'AF_INET':
          na = {}
          addrs[a[0]] = na
          na['addr'] = ip(a[1])
          na['netmask'] = ip(a[2])
          na['broadaddr'] = ip(a[3])
          na['dstaddr'] = ip(a[4])
        elif a[0] == 'AF_INET6':
          na = {}
          addrs[a[0]] = na
          na['addr'] = ip6(a[1])
          na['netmask'] = ip6(a[2])
          na['broadaddr'] = ip6(a[3])
          na['dstaddr'] = ip6(a[4])
        elif a[0] == 'AF_LINK':
          na = {}
          addrs[a[0]] = na
          na['addr'] = link(a[1])
          na['netmask'] = link(a[2])
          na['broadaddr'] = link(a[3])
          na['dstaddr'] = link(a[4])
        elif a[0] == 'AF_PACKET':
          addrs[a[0]] = {'addr':link(a[1])}
        elif a[0] == 'ethernet':
          addrs[a[0]] = {'addr':link(a[1])}
    return out

  @staticmethod
  def get_device_names ():
    return [d[0] for d in pcapc.findalldevs()]

  def __init__ (self, device = None, promiscuous = True, period = 10,
                start = True, callback = None, filter = None,
                use_bytearray = False, **kw):
    """
    Initialize this instance

    use_bytearray: specifies capturing to bytearray buffers instead of bytes
    """

    if filter is not None:
      self.deferred_filter = (filter,)
    else:
      self.deferred_filter = None
    self.packets_received = 0
    self.packets_dropped = 0
    self._thread = None
    self.pcap = None
    self.promiscuous = promiscuous
    self.device = None
    self.use_bytearray = use_bytearray
    self.period = period
    self.netmask = IPAddr("0.0.0.0")
    self._quitting = False
    self.addresses = {}
    if callback is None:
      self.callback = self.__class__._handle_rx
    else:
      self.callback = callback

    for k,v in kw.items():
      assert not hasattr(self, k)
      setattr(self, k, v)

    if device is not None:
      self.open(device)
    if self.pcap is not None:
      if start:
        self.start()

  def _handle_rx (self, data, sec, usec, length):
    pass

  def open (self, device, promiscuous = None, period = None,
            incoming = True, outgoing = False):
    assert self.device is None
    self.addresses = self.get_devices()[device]['addrs']
    if 'AF_INET' in self.addresses:
      self.netmask = self.addresses['AF_INET'].get('netmask')
      if self.netmask is None: self.netmask = IPAddr("0.0.0.0")
    #print "NM:",self.netmask
    #print self.addresses['AF_LINK']['addr']
    self.device = device
    if period is not None:
      self.period = period
    if promiscuous is not None:
      self.promiscuous = promiscuous
    self.pcap = pcapc.open_live(device, 65535,
                                1 if self.promiscuous else 0, self.period)
    pcapc.setdirection(self.pcap, incoming, outgoing)
    self.packets_received = 0
    self.packets_dropped = 0
    if self.deferred_filter is not None:
      self.set_filter(*self.deferred_filter)
      self.deferred_filter = None

  def set_direction (self, incoming, outgoing):
    pcapc.setdirection(self._pcap, incoming, outgoing)

  def set_nonblocking (self, nonblocking = True):
    pcapc.setnonblock(self._pcap, 1 if nonblocking else 0)

  def set_blocking (self, blocking = True):
    self.set_nonblocking(nonblocking = not blocking)

  @property
  def blocking (self):
    return False if pcapc.getnonblock(self._pcap) else True

  @blocking.setter
  def blocking (self, value):
    self.set_blocking(value)

  def next_packet (self, allow_threads = True):
    """
    Get next packet

    Returns tuple with:
      data, timestamp_seconds, timestamp_useconds, total length, and
      the pcap_next_ex return value -- 1 is success
    """
    return pcapc.next_ex(self._pcap, bool(self.use_bytearray), allow_threads)

  def _select_thread_func (self):
    try:
      import select
      fd = [self.fileno()]
    except:
      # Fall back
      self._thread_func()
      return

    self.blocking = False

    while not self._quitting:
      rr,ww,xx = select.select(fd, [], fd, 2)

      if xx:
        # Apparently we're done here.
        break
      if rr:
        r = self.next_packet(allow_threads = False)
        if r[-1] == 0: continue
        if r[-1] == 1:
          self.callback(self, r[0], r[1], r[2], r[3])
        else:
          break

    self._quitting = False
    self._thread = None

  def _thread_func (self):
    while not self._quitting:
      pcapc.dispatch(self.pcap,100,self.callback,self,bool(self.use_bytearray),True)
      self.packets_received,self.packets_dropped = pcapc.stats(self.pcap)

    self._quitting = False
    self._thread = None

  def _handle_GoingDownEvent (self, event):
    self.close()

  def start (self):
    assert self._thread is None
    from pox.core import core
    core.addListeners(self, weak=True)

    if self.use_select:
      self._thread = Thread(target=self._select_thread_func)
    else:
      self._thread = Thread(target=self._thread_func)
    #self._thread.daemon = True
    self._thread.start()

  def stop (self):
    t = self._thread
    if t is not None:
      self._quitting = True
      pcapc.breakloop(self.pcap)
      t.join()

  def close (self):
    if self.pcap is None: return
    self.stop()
    pcapc.close(self.pcap)
    self.pcap = None

  def __del__ (self):
    self.close()

  @property
  def _pcap (self):
    if self.pcap is None:
      raise RuntimeError("PCap object not open")
    return self.pcap

  def inject (self, data):
    if isinstance(data, pkt.ethernet):
      data = data.pack()
    if not isinstance(data, (bytes,bytearray)):
      data = bytes(data) # Give it a try...
    return pcapc.inject(self.pcap, data)

  def set_filter (self, filter, optimize = True):
    if self.pcap is None:
      self.deferred_filter = (filter, optimize)
      return

    if isinstance(filter, str):
      filter = Filter(filter, optimize, self.netmask.toSignedN(),
                      pcap_obj=self)
    elif isinstance(filter, Filter):
      pass
    else:
      raise RuntimeError("Filter must be string or Filter object")

    pcapc.setfilter(self.pcap, filter._pprogram)

  def fileno (self):
    if self.pcap is None:
      raise RuntimeError("PCap object not open")
    r = pcapc.get_selectable_fd(self.pcap)
    if r == -1:
      raise RuntimeError("Selectable FD not available")
    return r

  def __str__ (self):
    return "PCap(device=%s)" % (self.device)


class Filter (object):
  def __init__ (self, filter, optimize = True, netmask = None,
                pcap_obj = None, link_type = 1, snaplen = 65535):
    self._pprogram = None
    if netmask is None:
      netmask = 0
    elif isinstance(netmask, IPAddr):
      netmask = netmask.toSignedN()

    delpc = False
    if pcap_obj is None:
      delpc = True
      pcap_obj = pcapc.open_dead(link_type, snaplen)
    if isinstance(pcap_obj, PCap):
      pcap_obj = pcap_obj.pcap

    with _compile_lock:
      self._pprogram = pcapc.compile(pcap_obj, filter,
                                     1 if optimize else 0, netmask)
    if delpc:
      pcapc.close(pcap_obj)

  def __del__ (self):
    if self._pprogram:
      pcapc.freecode(self._pprogram)


try:
  _link_type_names = {}
  for k,v in copy.copy(pcapc.__dict__).iteritems():
    if k.startswith("DLT_"):
      _link_type_names[v] = k
except:
  pass

def get_link_type_name (dlt):
  return _link_type_names.get(dlt, "<Unknown " + str(dlt) + ">")


def test (interface = "en1"):
  """ Test function """
  global drop,total,bytes_got,bytes_real,bytes_diff
  drop = 0
  total = 0
  bytes_got = 0
  bytes_real = 0
  bytes_diff = 0
  def cb (obj, data, sec, usec, length):
    global drop,total,bytes_got,bytes_real,bytes_diff
    #print ">>>",data
    t,d = pcapc.stats(obj.pcap)
    bytes_got += len(data)
    bytes_real += length
    nbd = bytes_real - bytes_got
    if nbd != bytes_diff:
      bytes_diff = nbd
      print "lost bytes:",nbd
    if t > total:
      total = t + 500
      print t,"total"
    if d > drop:
      drop = d
      print d, "dropped"
    p = pkt.ethernet(data)
    ip = p.find('ipv4')
    if ip:
      print ip.srcip,"\t",ip.dstip, p

  print "\n".join(["%i. %s" % x for x in
                  enumerate(PCap.get_device_names())])

  if interface.startswith("#"):
    interface = int(interface[1:])
    interface = PCap.get_device_names()[interface]
  print "Interface:",interface

  p = PCap(interface, callback = cb,
           filter = "icmp")
           #[icmptype] != icmp-echoreply")
           #filter = "ip host 74.125.224.148")

  p.set_direction(True, True)

  def ping (eth='00:18:02:6e:ce:55', ip='192.168.0.1'):
    e = pkt.ethernet()
    e.src = p.addresses['ethernet']['addr'] or '02:00:00:11:22:33'
    e.dst = EthAddr(eth)
    e.type = e.IP_TYPE
    ipp = pkt.ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = p.addresses['AF_INET']['addr']
    ipp.dstip = IPAddr(ip)
    icmp = pkt.icmp()
    icmp.type = pkt.ICMP.TYPE_ECHO_REQUEST
    icmp.payload = "PingPing" * 6
    ipp.payload = icmp
    e.payload = ipp

    p.inject(e)

  def broadcast ():
    ping('ff:ff:ff:ff:ff:ff','255.255.255.255')

  import code
  code.interact(local=locals())


def no_select ():
  """
  Sets default PCap behavior to not try to use select()
  """
  PCap.use_select = False


def do_select ():
  """
  Sets default PCap behavior to try to use select()
  """
  PCap.use_select = True


def interfaces (verbose = False):
  """
  Show interfaces
  """
  if not verbose:
    print "\n".join(["%i. %s" % x for x in
                    enumerate(PCap.get_device_names())])
  else:
    import pprint
    print pprint.pprint(PCap.get_devices())

  from pox.core import core
  core.quit()


def launch (interface, no_incoming=False, no_outgoing=False):
  """
  pxshark -- prints packets
  """
  def cb (obj, data, sec, usec, length):
    p = pkt.ethernet(data)
    print p.dump()

  if interface.startswith("#"):
    interface = int(interface[1:])
    interface = PCap.get_device_names()[interface]

  p = PCap(interface, callback = cb, start=False)
  p.set_direction(not no_incoming, not no_outgoing)
  #p.use_select = False
  p.start()
