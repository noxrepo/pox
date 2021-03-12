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
Web interface for the DNS server
"""

from pox.core import core
from pox.web.webcore import InternalContentHandler

log = core.getLogger()

_msg_marker = "<!-- MSG -->"

_header = """
<html><head><title>DNS Server</title>
<head>
<body>
<!-- MSG -->
<table id="dnstable" border="2">
  <thead><tr>
    <th>Name</th>
    <th>Value</th>
  </tr></thead>
  <tbody>
"""

_footer = """
  </tbody>
</table>

<br/>
Enter name and value to add an A or CNAME record.
<br/>
Enter name only to delete a record.

<form method="POST" action="/dns">
<input id="form_name" name="dns_name">
<input id="form_value" name="dns_value">
<input type="submit">
</form>

<script>

function onclick ()
{
  if (this.cellIndex == 0)
    document.getElementById("form_name").value = this.innerText;
  else if (this.cellIndex == 1)
    document.getElementById("form_value").value = this.innerText;
}

document.querySelectorAll("#dnstable td")
.forEach(el => el.addEventListener("click", onclick));

</script>

</body></html>
"""


class DNSWebHandler (InternalContentHandler):
  args_content_lookup = False

  @property
  def _dns (self):
    r = self.args.get("dns_component")
    if r: return r
    return core.DNSServer

  def GET_ (self, _):
    return self._get_page()

  def _get_page (self, message=None):
    try:
      o = []
      for k,v in self._dns.db.items():
        o.append("<tr><td>%s</td><td>%s</td></tr>"%(k.decode("utf8"),v.value))

      more = "<br/>Your IP is: " + self.client_address[0] + "\n<br/>"

      full = _header + "\n".join(o) + more + _footer
      if message: full = full.replace(_msg_marker, message)

      return ("text/html", full)
    except Exception:
      log.exception("Handling request")

  def POST_ (self, _, data):
    try:
      n = data.getvalue("dns_name", "")
      v = data.getvalue("dns_value", "")
      msg = None
      if not v:
        if not self._dns.del_record(n):
          msg = '<hr/><p style="color:red;">Record deletion failed</p><hr/>'
      elif not self._dns.add_record(n, v):
        msg = '<hr/><p style="color:red;">Record modify/add failed</p><hr/>'
      return self._get_page(message=msg)
    except Exception:
      log.exception("Handling POST")



def launch ():
  def config ():
    core.WebServer.set_handler("/dns", DNSWebHandler,
                               args = dict(_dns=core.DNSServer))

  core.call_when_ready(config, ["WebServer", "DNSServer"])
