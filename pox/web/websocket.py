# Copyright 2018 James McCauley
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
Websocket request handler

The request handler is meant to be subclassed, and it plays nicely with
the cooperative context (you can call send() from the cooperative
context, and the override-friendly handler functions are called within
the cooperative context).

Subclasses are likely interested in overriding the _on_X() methods
(especially _on_message), and the send() and maybe disconnect() API
methods.

There's also a demonstration here which uses a websocket to send logs
to the browser and take a bit of log configuration from the browser.
Launch it with web.websocket:log_service.
"""

import socket
import threading

from pox.core import core

log = core.getLogger()

import base64
import hashlib
import struct
import json

from pox.web.webcore import SplitRequestHandler

from http.cookies import SimpleCookie

from collections import deque


class WebsocketHandler (SplitRequestHandler, object):
  """
  Websocket handler class

  New messages arriving from the browser are handed to _on_message(), which
  you can subclass.  This handler is called from the cooperative context.

  _on_start() and _on_stop() can be overridden and are called at the
  obvious times (hopefully).  Again, they're called cooperatively.

  You can send messages via send().  This should be called from the
  cooperative context.
  """

  # We always set no cookieguard, because this is what the split request
  # handler looks at, and we don't want *it* to do cookieguard.
  pox_cookieguard = False

  # This controls whether websockets actually do cookieguard.  If we
  # set it to None, the parent's (splitter's) value is used.
  ws_pox_cookieguard = None

  _websocket_open = False
  _initial_send_delay = 0.010
  _send_delay = 0
  _lock = None
  _pending = False
  _rx_queue = None

  # No longer optional. USE_LOCK = True
  READ_TIMEOUT = 5

  WS_CONTINUE = 0
  WS_TEXT = 1
  WS_BINARY = 2
  WS_CLOSE = 8
  WS_PING = 9
  WS_PONG = 10

  def log_message (self, format, *args):
    log.debug(format, *args)

  def _init (self):
    self._send_buffer = b''
    self._rx_queue = deque()
    if True: # No longer optional. self.USE_LOCK:
      self._lock = threading.RLock()

  def _serve_websocket (self):
    self.close_connection = 1

    # I think you technically need HTTP/1.1 to be able to upgrade or
    # something like that.  Firefox and Chrome don't seem to mind if
    # we reply with HTTP/1.0, but at least one (Epiphany) will fail.
    self.protocol_version = "HTTP/1.1"

    log.debug("Upgrading to websocket")
    self.send_response(101, "Switching Protocols")
    k = self.headers.get("Sec-WebSocket-Key", "")
    k += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    k = base64.b64encode(hashlib.sha1(k.encode()).digest()).decode()
    self.send_header("Sec-WebSocket-Accept", k)
    self.send_header("Upgrade", "websocket")
    self.send_header("Connection", "Upgrade")

    do_cg = getattr(self, "ws_pox_cookieguard", None)
    if do_cg is None: do_cg = getattr(self.parent, "pox_cookieguard", True)
    if not do_cg:
      cg_ok = True
    else:
      cookies = SimpleCookie(self.headers.get('Cookie'))
      cgc = cookies.get(self.parent._pox_cookieguard_cookie_name)
      if cgc and cgc.value == self.parent._get_cookieguard_cookie():
        cg_ok = True
      else:
        # Cookieguard failed.
        cookie = ("%s=%s; SameSite=Strict; HttpOnly; path=/"
                  % (self.parent._pox_cookieguard_cookie_name,
                     self.parent._get_cookieguard_cookie()))
        self.send_header("Set-Cookie", cookie)
        self.send_header("POX", "request-reconnect")

        cg_ok = False

    self.end_headers()

    # Now stop using wfile and use raw socket
    self.wfile.flush()
    self.connection.settimeout(0)

    if not cg_ok:
      log.info("Bad POX CookieGuard cookie  -- closing connection")
      return

    self._websocket_open = True
    self._queue_call(self._on_start)

    def feeder ():
      data = b''
      old_op = None
      hdr = b''
      while self._websocket_open:
        while len(hdr) < 2:
          newdata = yield True
          if newdata: hdr += newdata

        flags_op,len1 = struct.unpack_from("!BB", hdr, 0)
        op = flags_op & 0x0f
        flags = flags_op >> 4
        fin = flags & 0x8
        if (len1 & 0x80) == 0: raise RuntimeError("No mask set")
        len1 &= 0x7f
        hdr = hdr[2:]

        while True:
          if len1 <= 0x7d:
            length = len1
            break
          elif len1 == 0x7e and len(hdr) >= 2:
            length = struct.unpack_from("!H", hdr, 0)
            hdr = hdr[2:]
            break
          elif len1 == 0x7f and len(hdr) >= 8:
            length = struct.unpack_from("!Q", hdr, 0)
            hdr = hdr[8:]
            break
          else:
            raise RuntimeError("Bad length")
          hdr += yield True

        while len(hdr) < 4:
          hdr += yield True

        mask = [x for x in hdr[:4]]
        hdr = hdr[4:]

        while len(hdr) < length:
          hdr += yield True

        d = hdr[:length]
        hdr = hdr[length:]

        d = bytes((c ^ mask[i % 4]) for i,c in enumerate(d))

        if not fin:
          if op == self.WS_CONTINUE:
            if old_op is None: raise RuntimeError("Continuing unknown opcode")
          else:
            if old_op is not None: raise RuntimeError("Discarded partial message")
            old_op = op
          data += d
        else: # fin
          if op == self.WS_CONTINUE:
            if old_op is None: raise RuntimeError("Can't continue unknown frame")
            op = old_op
          d = data + d
          old_op = None
          data = b''
          if op == self.WS_TEXT: d = d.decode('utf8')

          if op in (self.WS_TEXT, self.WS_BINARY):
            self._ws_message(op, d)
          elif op == self.WS_PING:
            msg = self._frame(self.WS_PONG, d)
            self._send_real(msg)
          elif op == self.WS_CLOSE:
            if self.disconnect():
              #TODO: Send close frame?
              pass
          elif op == self.WS_PONG:
            pass
          else:
            pass # Do nothing for unknown type

    deframer = feeder()
    try:
      deframer.send(None)
    except StopIteration:
      pass # PEP 479?

    # This is nutso, but it just might work.
    # *Try* to read individual bytes from rfile in case it has some
    # buffered.  When it fails, switch to reading from connection.
    while True:
      try:
        d = self.rfile.read(1)
        if not d: break
        deframer.send(d)
      except Exception:
        break

    import select
    while self._websocket_open and core.running:
      try:
        (rx, tx, xx) = select.select([self.connection], [], [self.connection],
                                     self.READ_TIMEOUT)
      except Exception:
        # sock died
        log.warn("Websocket died")
        break
      if len(xx):
        #TODO: reopen?
        log.warn("Websocket exceptional")
        break
      if len(rx):
        try:
          r = self.connection.recv(4096)
          if not r: break
          deframer.send(r)
        except Exception as e:
          #TODO: reopen
          break

    log.debug("Done reading websocket")

    #NOTE: We should probably send a close frame, but don't.
    self.disconnect()

    #log.debug("Websocket quit")

  def do_GET (self):
    # Compatible with AuthMixin
    if hasattr(self, '_do_auth') and not self._do_auth(): return

    if self.headers.get("Upgrade") == "websocket":
      return self._serve_websocket()
    else:
      self.send_error(405, "Unacceptable request; websockets only")

  def _queue_call (self, f):
    self._ws_message(None, f) # See note in _ws_message()

  def _ws_message (self, opcode, data):
    # It's a hack, but this is also used to push arbitrary function calls from
    # the WS thread to the cooperative context, by setting opcode as None and
    # the function as data.
    self._rx_queue.append((opcode,data))
    cl = True
    if self._lock:
      with self._lock:
        if self._pending:
          cl = False
        else:
          self._pending = True
    if cl: core.call_later(self._ws_message2)

  def _ws_message2 (self):
    if self._lock:
      with self._lock:
        assert self._pending
        self._pending = False
    try:
      while True:
        op,data = self._rx_queue.popleft()
        if op is None: # See note in _ws_message()
          try:
            data()
          except Exception:
            log.exception("While calling %s", data)
        else:
          try:
            self._on_message(op, data)
          except Exception:
            log.exception("While handling message")
    except Exception:
      pass

  @staticmethod
  def _frame (opcode, msg):
    def encode_len (l):
      if l <= 0x7d:
        return struct.pack("!B", l)
      elif l <= 0xffFF:
        return struct.pack("!BH", 0x7e, l)
      elif l <= 0x7FFFFFFFFFFFFFFF:
        return struct.pack("!BQ", 0x7f, l)
      else:
        raise RuntimeError("Bad length")

    op_flags = 0x80 | (opcode & 0x0F) # 0x80 = FIN
    hdr = struct.pack("!B", op_flags) + encode_len(len(msg))

    return hdr + msg

  def _send_real (self, msg):
    if self._send_buffer:
      self._send_buffer += msg
      return

    try:
      written = self.connection.send(msg)
      if written < len(msg):
        # Didn't send all of it.
        assert not self._send_buffer
        self._send_delay = self._initial_send_delay
        self._send_buffer = msg[written:]
        core.call_later(self._delayed_send)
    except Exception as e:
      self.disconnect()
      #TODO: reopen?

  def _delayed_send (self):
    if self._websocket_open is False: return
    try:
      written = self.connection.send(self._send_buffer)
      if written < len(self._send_buffer):
        # Didn't send all of it.
        self._send_buffer = self._send_buffer[written:]
        core.call_later(self._delayed_send)
        self._send_delay = min(1, self._send_delay * 2)
      else:
        self._send_buffer = b''
    except Exception:
      self.disconnect()
      #TODO: reopen?

  def __del__ (self):
    self.disconnect()


  # The following are useful for subclasses...
  @property
  def is_connected (self):
    with self._lock:
      return self._websocket_open

  def disconnect (self):
    if self._lock:
      with self._lock:
        if self._websocket_open is False:
          return False
        self._websocket_open = False
    elif self._websocket_open is False:
      return False
    self._websocket_open = False
    try:
      self._queue_call(self._on_stop)
    except Exception:
      log.exception("While disconnecting")
    try:
      self.connection.shutdown(socket.SHUT_RD)
    except socket.error as e:
      pass
    return True

  def send (self, msg):
    if isinstance(msg, dict): msg = json.dumps(msg)
    try:
      msg = self._frame(self.WS_TEXT, msg.encode())
      self._send_real(msg)
    except Exception as e:
      log.exception("While sending")
      self.disconnect()

  def _on_message (self, op, msg):
    """
    Called when a new message arrives

    Override me!
    """
    self.log_message("Msg Op:%s Bytes:%s", op, len(msg) if msg else "None")

  def _on_start (self):
    """
    Called when the Websocket is established

    Override me!
    """
    self.log.message("Websocket connection started")

  def _on_stop (self):
    """
    Called when the Websocket connection is lost

    Override me!
    """
    self.log.message("Websocket connection stopped")



class LogWebsocketHandler (WebsocketHandler):
  """
  Sends log messages to a websocket

  The browser can also send us JSON objects with logger_name:logger_levels
  to control logging levels.

  This is mostly meant as an example of WebsocketHandler.
  """
  log_handler = None

  import logging
  class WSLogHandler (logging.Handler):
    web_handler = None # Set externally
    def emit (self, record):
      try:
        msg = self.format(record)
        self.web_handler.send(msg + "\n")
      except (KeyboardInterrupt, SystemExit):
        raise
      except:
        self.handleError(record)

  def _on_message (self, op, msg):
    import json
    import logging
    msg = json.loads(msg)
    for k,v in msg.items():
      logging.getLogger(k).setLevel(v)

  def _on_start (self):
    import logging
    self.log_handler = self.WSLogHandler()
    self.log_handler.formatter = logging.Formatter("%(levelname)s | %(name)s"
                                                   " | %(message)s")
    self.log_handler.web_handler = self
    logging.getLogger().addHandler(self.log_handler)
    log.debug("Websocket logger connected")

  def _on_stop (self):
    if self.log_handler:
      import logging
      logging.getLogger().removeHandler(self.log_handler)



_log_page = """
<!DOCTYPE html>
<html>
<head>
<title>POX Log</title>
<script language="javascript" type="text/javascript">

function out (msg, color)
{
  var el = document.createElement("pre");
  if (color) el.style.cssText = "color:" + color + ";";
  el.innerHTML = msg;
  document.getElementById("output").appendChild(el);
  el.scrollIntoView();
}

function connect ()
{
  ws = new WebSocket("ws://SERVER_ADDRESS/wslog/ws");
  ws.onopen = function(e) { };
  ws.onclose = function(e) {
    out("<a onclick='connect()' style='color:red'>Disconnected - Click to"
        + " reconnect</a>", "red");
  };
  ws.onmessage = function(e) {
    out(e.data.replace("<","&lt;").replace(">","&gt;"));
  };
  ws.onerror = function(e) { out("Error " + e.data, "red"); };
}

function send_level ()
{
  var el = document.getElementById("level_box");
  var level = el.options[el.selectedIndex].text;
  if (level)
  {
    console.log("Change level to " + level);
    ws.send(JSON.stringify({"": level}));
    // Use "" as the logger name to get the root logger
  }
}

window.addEventListener("load", connect, false);

</script>
</head>
<body>
<h1><a href="help.txt">POX Log Page</a></h1>
Root Log Level: <select id="level_box" onchange="send_level()">
  <option></option>
  <option>ERROR</option>
  <option>WARNING</option>
  <option>INFO</option>
  <option>DEBUG</option>
</select>
<div id="output"></div>
</body>
</html>
"""

_log_help_page = """
Connecting to the base page should result in log messages being sent to the
browser via a websocket.

You can also send JSON objects from the browser over the websocket containing
key/value pairs of logger-name/logger-level.  For example:

{"core": "INFO", "web":"ERROR"}

The "Root Log Level" popup does exactly this for the root logger.

This is really just meant as a demonstration of the Websocket infrastructure.
(And it demonstrates InternalContentHandler a bit too.)
"""

def log_service ():
  """
  Sends log messages to a browser via websocket

  This is mostly just meant as a demonstration of websockets in POX.
  """
  from pox.web.webcore import InternalContentHandler
  def ready ():
    addr = list(core.WebServer.socket.getsockname())
    if addr[0] == "0.0.0.0": addr[0] = "127.0.0.1"
    docs = {'/': _log_page.replace("SERVER_ADDRESS", "%s:%s" % tuple(addr)),
            '/help.txt': _log_help_page}

    core.WebServer.set_handler("/wslog/ws", LogWebsocketHandler)
    core.WebServer.set_handler("/wslog", InternalContentHandler, docs)
  core.call_when_ready(ready, ("WebServer",), "log_websocket")
