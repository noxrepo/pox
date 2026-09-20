# Copyright 2021,2023 James McCauley
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
Web interfaces for the DNS server

There are actually two web interfaces in here.  The default one
adds /dns/, which provides a UI for viewing and editing DNS
records served by the DNS server.  The :history launcher starts
/dns/history, which lets you view query history and the stats
from the DNS server.
"""

from pox.core import core
from pox.web.webcore import InternalContentHandler
import pox.lib.packet as pkt
import datetime

log = core.getLogger()

_msg_marker = "<!-- MSG -->"

_header = """
<html><head><title>DNS Server</title>
</head>
<body>
<!-- MSG -->

<form method="POST" autocomplete="on">
<table id="dnstable" border="2">
  <thead><tr>
    <th>Name</th>
    <th>Value</th>
    <th>ALPN</th>
    <th>TTL</th>
  </tr></thead>
  <tbody>
"""

_footer = """
<tr>
<td><input id="form_name" name="dns_name" size="30" autofocus /></td>
<td><input id="form_value" name="dns_value" size="20" /></td>
<td><input id="form_alpn" name="dns_alpn" size="7" style="display:$ALPN_DISPLAY" /></td>
<td><input id="form_ttl" name="dns_ttl" size="5" style="display:$TTL_DISPLAY" /></td>
</tr>
  </tbody>
</table>

<input type="submit" name="dns_submit" value="Submit" />
<input type="submit" name="dns_del_a" value="Del IPv4" />
<input type="submit" name="dns_del_aaaa" value="Del IPv6" />
<input type="submit" name="dns_del_cname" value="Del CNAME" />
<button onclick="location.href=location.href;return false;">Refresh</button>
</form>

Use the bottom row to create/modify/delete records.
<br/>
Enter name and IPv4/IPv6 address(es) to set an A/AAAA record.  Include an ALPN to also get HTTPS records (if enabled).
<br/>
Enter name and alias to set a CNAME record.
<br/>
Enter name only to delete records ("Submit" deletes all types at once).
<br/>
Click/Shift-click cells to reuse values/rows.

<script>

function onclick (e)
{
  var rowCount = document.getElementById("dnstable").rows.length;
  if (this.parentElement.rowIndex == rowCount - 1) return;
  var cellmap = ["name", "value", "alpn", "ttl"];
  if (e.shiftKey) // Copy all values
  {
    var src = this.parentElement.firstElementChild;
    for (var i = 0; i < cellmap.length; ++i)
    {
      var dst = document.getElementById("form_" + cellmap[i]);
      dst.value = src.innerText;
      src = src.nextElementSibling;
    }
    return;
  }
  if (this.cellIndex >= cellmap.length) return;
  var el = "form_" + cellmap[this.cellIndex];
  document.getElementById(el).value = this.innerText;
}

document.querySelectorAll("#dnstable td")
.forEach(el => el.addEventListener("click", onclick));


function onclick_myip ()
{
  var el = document.getElementById("myip");
  document.getElementById("form_value").value = el.innerText;
}


</script>

</body></html>
"""


class DNSWebHandler (InternalContentHandler):
  args_content_lookup = False
  allow_set_alpn = True
  allow_set_ttl = True

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
      for k,vv in self._dns.db.items():
        for v in vv:
          if not v.is_address and v.type != pkt.dns.rr.CNAME_TYPE: continue
          val = v.value_str
          if v.is_address: val = f"<tt>{val}</tt>"
          alpn = v.synthetic_https_alpn or ''
          if isinstance(k, bytes): k = k.decode('ascii')
          r = f"<tr><td>{k}</td><td>{val}</td>"
          r += f"<td>{alpn}</td><td>{v.ttl}</td></tr>"
          o.append(r)

      yourip = self.headers.get("x-forwarded-for", self.client_address[0])
      yourip = "".join(filter(lambda x: x in set("0123456789.:"), yourip))
      more = ('<br/>Your IP is: <span onclick="onclick_myip()" id="myip"><tt>'
              + yourip + "</tt></span>\n<br/>")

      footer = _footer
      footer = footer.replace("$ALPN_DISPLAY",
                              "" if self.allow_set_alpn else "none")
      footer = footer.replace("$TTL_DISPLAY",
                              "" if self.allow_set_ttl else "none")
      full = _header + "\n".join(o) + more + footer
      if message: full = full.replace(_msg_marker, message)

      return ("text/html", full)
    except Exception:
      log.exception("Handling request")

  def POST_ (self, _, data):
    try:
      n = data.getvalue("dns_name", "")
      v = data.getvalue("dns_value", "")
      alpn = data.getvalue("dns_alpn", "")
      ttl = data.getvalue("dns_ttl", "")
      v = v.strip().replace(" ", ",")

      delete = v == ""
      if data.getvalue("dns_del_a", ""): delete = "A"
      if data.getvalue("dns_del_aaaa", ""): delete = "AAAA"
      if data.getvalue("dns_del_cname", ""): delete = "CNAME"

      if ttl == "": ttl = None
      if ttl: ttl = int(ttl)

      if not alpn: alpn = False

      if not self.allow_set_ttl: ttl = None
      if not self.allow_set_alpn: alpn = None

      msg = None
      if delete:
        if delete is True: delete = None
        if v or alpn or (ttl is not None):
          msg = ('<hr/><p style="color:red;">Only name can be specified when'
                 + ' deleting</p><hr/>')
        elif not self._dns.del_record(n, qtype=delete):
          msg = '<hr/><p style="color:red;">Record deletion failed</p><hr/>'
      elif not self._dns.add_record(n, v, https_alpn=alpn, ttl=ttl):
        msg = '<hr/><p style="color:red;">Record modify/add failed</p><hr/>'
      return self._get_page(message=msg)
    except Exception:
      log.exception("Handling POST")



def launch (no_ttl_setting=False, no_alpn_setting=False):
  DNSWebHandler.allow_set_alpn = not no_alpn_setting
  DNSWebHandler.allow_set_ttl = not no_ttl_setting

  def config ():
    core.WebServer.set_handler("/dns/", DNSWebHandler,
                               args = dict(_dns=core.DNSServer))

  core.call_when_ready(config, ["WebServer", "DNSServer"])



_hist_head = r"""
<html>
<head>
<title>DNS History</title>
<script>

if (location.hash == "#refresh")
  setTimeout( ()=>location.reload(), 5000);

function refresh (auto)
{
  if (auto)
  {
    location.hash = "#refresh";
    location.reload();
  }
  else
  {
    location.href = location.href.split("#")[0];
  }
  return false;
}

document.onreadystatechange = function ()
{
  if (document.readyState == "complete")
  {
    // At least on Safari, doing it without a timeout doesn't work
    setTimeout( ()=>window.scrollTo(0, document.body.scrollHeight), 0 );
  }
};

</script>
</head>
<body>
<table border="2">
"""

_hist_foot = r"""
</table>
<button onclick="return refresh(false);">Refresh</button>
<button onclick="return refresh(true);">AutoRefresh</button>
</body>
</html>
"""

class DNSHistoryHandler (InternalContentHandler):
  args_content_lookup = False

  @property
  def _dns (self):
    r = self.args.get("dns_component")
    if r: return r
    return core.DNSServer

  def GET_ (self, _):
    out = []
    for ts,query,askers in self._dns.history:
      try:
        askers = " ".join(s for s in sorted(askers))
        t = datetime.datetime.fromtimestamp(ts).isoformat()
        t = t.rsplit(".",1)[0]
        t = t.replace("T", " ")
        if isinstance(query, bytes):
          query = query.decode("ascii", "replace")
        query = query.replace("<", "?")
        row = (f"<tr><td><tt>{t}</tt></td>"
              +f"<td><tt>{query:45}</tt></td>"
              +f"<td><tt>{askers}</tt></td></tr>")
        out.append(row)
      except Exception:
        log.exception("Exception while processing history '%s,%s,%s'",
                      str(ts), str(query), str(askers))

    try:
      row = []
      for f in ('badclass','ignore','norecord','novalue','okay'):
        v = getattr(self._dns, 'counter_'+f)
        row.append( f'{f}:{v}' )
      t = datetime.datetime.now().isoformat()
      t = t.rsplit(".",1)[0]
      t = t.replace("T", " ")
      row = " ".join(row)
      row = f'<tr><td><tt>{t}</tt></td><td colspan="2"><tt>{row}</tt></td></tr>'
      out.append(row)
    except Exception:
      log.exception("While formatting final row")

    return ("text/html", _hist_head + '\n'.join(out) + _hist_foot)



def history ():
  def config ():
    core.WebServer.set_handler("/dns/history", DNSHistoryHandler,
                               args = dict(_dns=core.DNSServer))

  core.call_when_ready(config, ["WebServer", "DNSServer"])
