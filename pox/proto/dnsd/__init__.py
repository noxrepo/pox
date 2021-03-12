# Copyright 2021 James McCauley
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

"""
A not-particularly-good, but working DNS server

It also has a component for web-based administration.
"""

from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, IP_ANY
import threading
from pox.core import core
from socket import *
from select import select
import re

log = core.getLogger()

DNS = pkt.dns
RR = pkt.dns.rr

log = core.getLogger()


class DNSRecord (object):
  DEFAULT_TTL = 60 * 10
  def __init__ (self, name, value, type=RR.A_TYPE, ttl=DEFAULT_TTL):
    self.name = name
    self.value = value
    self.type = type
    self.ttl = ttl


class DNSServer (object):
  DEFAULT_TTL = 60 * 10

  def __init__ (self, bind_ip=None):
    self.db = {}
    self.bind_ip = bind_ip

    core.add_listener(self._handle_GoingUpEvent)

  def _handle_GoingUpEvent (self, event):
    self.sock = s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    if self.bind_ip is None:
      bind = ""
    else:
      bind = str(self.bind_ip)
    try:
      s.bind( (bind, 53) )
    except Exception:
      if bind == "": bind = "<Any>"
      log.exception("While binding to %s:%s", bind, 53)
      return

    s.setblocking(False)

    self.thread = t = threading.Thread(target=self._server_thread)
    t.daemon = True
    t.start()

  @staticmethod
  def is_valid_name (n):
    if re.match('^[a-zA-Z0-9-.]+$', n): return True
    return False

  @classmethod
  def _fixname (cls, n):
    if not cls.is_valid_name(n): return None
    try:
      return n.encode("utf8")
    except Exception:
      return None

  def del_record (self, name):
    name = self._fixname(name)
    if name not in self.db: return False
    self.db.pop(name)
    return True

  def add_record (self, name, v):
    name = self._fixname(name)
    if not name: return False
    try:
      v = str(v)
      if v.count(".") != 3: raise RuntimeError()
      v = IPAddr(v)
      r = DNSRecord(name, v, RR.A_TYPE, self.DEFAULT_TTL)
    except Exception:
      if not self.is_valid_name(v): return False
      r = DNSRecord(name, v, RR.CNAME_TYPE, self.DEFAULT_TTL)
    self.db[name] = r
    return True

  def _do_request (self, sock, addr, data):
    req = DNS(raw=data)
    if req.qr: return
    if not req.questions: return
    q = req.questions[0]
    if q.qclass != 1: return
    r = DNS()
    r.questions.append(q)
    rec = self.db.get(q.name)
    if not rec or rec.type != q.qtype:
      # Might want to send an NXDOMAIN, but we don't currently have SOA stuff
      # at all.  So just send back an empty reply; they'll probably get the
      # hint!
      log.debug("No such domain: %s", q.name.decode("utf8", errors="ignore"))
    else:
      rr = RR(q.name, rec.type, 1, rec.ttl, 0, rec.value)
      r.answers.append(rr)
    r.qr = 1
    r.id = req.id
    #r.aa = True

    log.debug("< %s (from %s)", req, addr)
    log.debug("> %s", r)
    sock.sendto(r.pack(), addr)

  def _server_thread (self):
    s = self.sock
    log.info("Starting DNS server")
    while True:
      rr,_,_ = select([s],[],[], 5)
      if rr:
        data,addr = s.recvfrom(1500)
        core.call_later(self._do_request, s, addr, data)


def add (**kw):
  """
  Adds A or CNAME records
  """
  for k,v in kw.items():
    core.DNSServer.add_record(k, v)


def ttl (ttl):
  try:
    core.DNSServer.DEFAULT_TTL = int(ttl)
  except Exception:
    DNSServer.DEFAULT_TTL = int(ttl)


def launch (local_ip = None):
  core.registerNew(DNSServer, bind_ip=local_ip)
