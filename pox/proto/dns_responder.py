# Copyright (c) 2013 Felician Nemeth
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
Dns_responder answers mDNS queries.  (Should we rename dsn_responder
to mdsn_respoder, mdsn_server, dsn_local, or something?)

Why?  Simple routing modules might not handle multicast traffic.
Additionally, it is sometimes not practical to set up a real DNS
server either.

On the other hand, we might take care of the lookups using out-of-band
information.  Add dns entires on commandline like:
  dns_responder --<IP>=<hostname> --<IP>=<hostname>
e.g.,
  dns_responder --10.0.0.2=h2 --10.0.0.3=h3
Or use the knowledgebase module like:
  dns_responder knowledgebase --file=dns.csv
with "dns.csv" containing
  hostname,ip
  h2,10.0.0.2
  h3,10.0.0.3

Note, libnss-mdns doesn't work in mininet: running "getent hosts
h2.local" on h1 doesn't send ipv4 packets out on interface h1-eth0.
"""

from pox.core import core
from pox.lib.addresses import IPAddr

log = core.getLogger()

class DnsResponder (object):
  def __init__ (self, db=[]):
    self._db = db
    core.listen_to_dependencies(self)

  def _answer_A (self, q):
    if not q.name.endswith('.local'):
      log.debug('ignoring question: %s' % q)
      return None
    name = q.name[:-len('.local')]

    if hasattr(core, 'Knowledgebase'):
      kb = core.Knowledgebase.query(hostname=name)
    else:
      kb = []

    for item in (self._db + kb):
      if (item.get('hostname', '').lower() == name.lower()):
        # TODO multiple addresses in the response?
        ip_str = item.get('ip')
        log.info('answering: %s with %s' % (q.name, ip_str))
        return IPAddr(ip_str)
    return None

  def _answer_PTR (self, q):
    if not q.name.endswith('.in-addr.arpa'):
      log.debug('ignoring question: %s' % q)
      return None
    name = q.name[:-len('.in-addr.arpa')]
    q_ip_str = name.split('.')
    q_ip_str.reverse()
    q_ip_str = '.'.join(q_ip_str)
    q_ip = IPAddr(q_ip_str)

    if hasattr(core, 'Knowledgebase'):
      kb = core.Knowledgebase.query(ip=q_ip_str)
    else:
      kb = []

    for item in (self._db + kb):
      if (IPAddr(item.get('ip')) == q_ip):
        # TODO multiple hostnames in the response?
        hostname = item.get('hostname')
        if hostname:
          log.info('answering: %s with %s' % (q.name, hostname))
          return hostname + '.local'
    return None

  def _answer_UNKNOWN (self, q):
    log.debug('ignoring question: %s' % q)
    return None

  def _handle_DNSHelper_DNSLookup (self, event):
    log.debug('q: (%s,%s)' % (event.name, event.qtype))
    attr = getattr(self, "_answer_" + event.qtype_name, self._answer_UNKNOWN)
    answer = attr(event)
    if answer:
      event.simple_answers.append(answer)
    return

def launch (**kw):
  db = [{"ip": k, "hostname": v} for k,v in kw.iteritems()]
  core.registerNew(DnsResponder, db)
