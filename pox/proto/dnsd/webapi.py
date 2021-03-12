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
Implements a DNS update web API compatible with other dynamic DNS
services.

NOTE: You should probably turn on https and HTTP authentication!

A request done with curl would look something like this:
  curl "http://user:pass@localhost:8000/nic/update?\
        hostname=test.somedns.com&myip=11.22.33.44"

"""

from pox.core import core
from pox.web.webcore import InternalContentHandler
from urllib.parse import parse_qsl
from pox.lib.addresses import IPAddr

log = core.getLogger()


class DNSWebAPIHandler (InternalContentHandler):
  args_content_lookup = False

  @property
  def _dns (self):
    r = self.args.get("dns_component")
    if r: return r
    return core.DNSServer

  def GETANY (self, _):
    p = self.path
    if not self.path.startswith("/update?"):
      self.send_error(404)
      return
    p = p.split("?", 1)[1]
    qs = dict(parse_qsl(p))

    hn = qs.get("hostname")
    ip = qs.get("myip", self.client_address[0])

    # Some of the errors:
    #  badauth
    #  notgqdn
    #  numhost
    #  nohost
    #  abuse
    #  badagent
    #  dnserror
    # Who knows we if we use them right, but if you
    # get one, something has definitely gone wrong.

    if not hn: return ("text/plain", "nohost")

    try:
      ip = IPAddr(ip)
    except Exception:
      log.warn("Bad IP address: %s", ip)
      return ("text/plain", "dnserr")

    hn = hn.split(",")

    try:
      for h in hn:
        self._dns.add_record(h, ip)
    except Exception:
      log.exception("While adding %s -> %s", h, ip)
      return ("text/plain", "dnserr")

    return ("text/plain", "good " + str(ip))


def launch (no_cookieguard=False):
  class Handler (DNSWebAPIHandler):
    pass

  if no_cookieguard:
    Handler.pox_cookieguard = False

  def config ():
    core.WebServer.set_handler("/nic/", Handler,
                               args = dict(_dns=core.DNSServer))

  core.call_when_ready(config, ["WebServer", "DNSServer"])
