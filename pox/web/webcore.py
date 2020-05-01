# Copyright 2011,2012,2018 James McCauley
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
Webcore is a basic web server framework based on the SocketServer-based
BaseHTTPServer that comes with Python.  The big difference is that this
one can carve up URL-space by prefix, such that "/foo/*" gets handled by
a different request handler than "/bar/*".  I refer to this as "splitting".

You should also be able to make a request handler written without splitting
run under Webcore.  This may not work for all request handlers, but it
definitely works for some. :)  The easiest way to do this is with the
wrapRequestHandler() function, like so:
  from CGIHTTPServer import CGIHTTPRequestHandler as CHRH
  core.WebServer.set_handler("/foo", wrapRequestHandler(CHRH))

.. now URLs under the /foo/ directory will let you browse through the
filesystem next to pox.py.  If you create a cgi-bin directory next to
pox.py, you'll be able to run executables in it.

For this specific purpose, there's actually a SplitCGIRequestHandler
which demonstrates wrapping a normal request handler while also
customizing it a bit -- SplitCGIRequestHandler shoehorns in functionality
to use arbitrary base paths.

BaseHTTPServer is not very fast and needs to run on its own thread.
It'd actually be great to have a version of this written against, say,
CherryPy, but I did want to include a simple, dependency-free web solution.
"""

from socketserver import ThreadingMixIn
from http.server import *
from time import sleep
import select
import threading

from .authentication import BasicAuthMixin

from pox.core import core
from pox.lib.revent import Event, EventMixin

import os
import socket
import posixpath
import urllib.request, urllib.parse, urllib.error
import cgi
import errno
from io import StringIO, BytesIO

log = core.getLogger()
try:
  weblog = log.getChild("server")
except:
  # I'm tired of people running Python 2.6 having problems with this.
  #TODO: Remove this someday.
  weblog = core.getLogger("webcore.server")

def _setAttribs (parent, child):
  attrs = ['command', 'request_version', 'close_connection',
           'raw_requestline', 'requestline', 'path', 'headers', 'wfile',
           'rfile', 'server', 'client_address', 'connection', 'request']
  for a in attrs:
    setattr(child, a, getattr(parent, a))

  setattr(child, 'parent', parent)



import weakref

class ShutdownHelper (object):
  """
  Shuts down sockets for reading when POX does down

  Modern browsers may open (or leave open) HTTP connections without sending
  a request for quite a while.  Python's webserver will open requests for
  these which will then just block at the readline() in handle_one_request().
  The downside here is that when POX tries to shut down, those threads are
  left hanging.  We could change things so that it didn't just blindly call
  and block on readline.  Or we could make the handler threads daemon threads.
  But instead, we just keep track of the sockets.  When POX wants to go down,
  we'll shutdown() the sockets for reading, which will get readline() unstuck
  and let POX close cleanly.
  """
  sockets = None
  def __init__ (self):
    core.add_listener(self._handle_GoingDownEvent)

  def _handle_GoingDownEvent (self, event):
    if self.sockets is None: return
    cc = dict(self.sockets)
    self.sockets.clear()
    #if cc: log.debug("Shutting down %s socket(s)", len(cc))
    for s,(r,w,c) in cc.items():
      try:
        if r and w: flags = socket.SHUT_RDWR
        elif r: flags = socket.SHUT_RD
        elif w: slags = socket.SHUT_WR
        if r or w: s.shutdown(flags)
      except Exception as e:
        pass
      if c:
        try:
          s.close()
        except Exception:
          pass
    if cc: log.debug("Shut down %s socket(s)", len(cc))

  def register (self, socket, read=True, write=False, close=False):
    if self.sockets is None:
      self.sockets = weakref.WeakKeyDictionary()
    self.sockets[socket] = (read,write,close)

  def unregister (self, socket):
    if self.sockets is None: return
    try:
      del self.sockets[socket]
    except Exception as e:
      pass

_shutdown_helper = ShutdownHelper()



from http.cookies import SimpleCookie

POX_COOKIEGUARD_DEFAULT_COOKIE_NAME = "POXCookieGuardCookie"

def _gen_cgc ():
  #TODO: Use Python 3 secrets module
  import random
  import datetime
  import hashlib
  try:
    rng = random.SystemRandom()
  except Exception:
    log.error("Using insecure pseudorandom number for POX CookieGuard")
    rng = random.Random()
  data = "".join([str(rng.randint(0,9)) for _ in range(1024)])
  data += str(datetime.datetime.now())
  data += str(id(data))
  data = data.encode()
  return hashlib.sha256(data).hexdigest()


import urllib
from urllib.parse import quote_plus, unquote_plus

class POXCookieGuardMixin (object):
  """
  This is a CSRF mitigation we call POX CookieGuard.  This only stops
  CSRF with modern browsers, but has the benefit of not requiring
  requesters to do anything particularly special.  In particular, if you
  are doing something like using curl from the commandline to call JSON-RPCs,
  you don't need to do anything tricky like fetch an auth token and then
  include it in the RPC -- all you need is cookie support.  Basically this
  works by having POX give you an authentication token in a cookie.  This
  uses SameSite=Strict so that other sites can't convince the browser to
  send it.
  """

  _pox_cookieguard_bouncer = "/_poxcookieguard/bounce"
  _pox_cookieguard_secret = _gen_cgc()
  _pox_cookieguard_cookie_name = POX_COOKIEGUARD_DEFAULT_COOKIE_NAME
  _pox_cookieguard_consume_post = True

  def _cookieguard_maybe_consume_post (self):
    if self._pox_cookieguard_consume_post is False: return
    if self.command != "POST": return

    # Read rest of input to avoid connection reset
    cgi.FieldStorage( fp = self.rfile, headers = self.headers,
                      environ={ 'REQUEST_METHOD':'POST' } )

  def _get_cookieguard_cookie (self):
    return self._pox_cookieguard_secret

  def _get_cookieguard_cookie_path (self, requested):
    """
    Gets the path to be used for the cookie
    """

    return "/"

  def _do_cookieguard_explict_continuation (self, requested, target):
    """
    Sends explicit continuation page
    """
    log.debug("POX CookieGuard bouncer doesn't have correct cookie; "
              "Sending explicit continuation page")
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    self.wfile.write(("""
      <html><head><title>POX CookieGuard</title></head>
      <body>
      A separate site has linked you here.  If this was intentional,
      please <a href="%s">continue to %s</a>.
      </body>
      </html>
      """ % (target, cgi.escape(target))).encode())

  def _do_cookieguard_set_cookie (self, requested, bad_cookie):
    """
    Sets the cookie and redirects

    bad_cookie is True if the cookie was set but is wrong.
    """
    self._cookieguard_maybe_consume_post()
    self.send_response(307, "Temporary Redirect")

    #TODO: Set Secure automatically if being accessed by https.
    #TODO: Set Path cookie attribute
    self.send_header("Set-Cookie",
                     "%s=%s; SameSite=Strict; HttpOnly; path=%s"
                     % (self._pox_cookieguard_cookie_name,
                        self._get_cookieguard_cookie(),
                        self._get_cookieguard_cookie_path(requested)))

    self.send_header("Location", self._pox_cookieguard_bouncer + "?"
                                 + quote_plus(requested))
    self.end_headers()

  def _do_cookieguard (self, override=None):
    do_cg = override
    if do_cg is None: do_cg = getattr(self, 'pox_cookieguard', True)
    if not do_cg: return True

    requested = self.raw_requestline.split()[1].decode("latin-1")

    cookies = SimpleCookie(self.headers.get('Cookie'))
    cgc = cookies.get(self._pox_cookieguard_cookie_name)
    if cgc and cgc.value == self._get_cookieguard_cookie():
      if requested.startswith(self._pox_cookieguard_bouncer + "?"):
        log.debug("POX CookieGuard cookie is valid -- bouncing")
        qs = requested.split("?",1)[1]

        self._cookieguard_maybe_consume_post()
        self.send_response(307, "Temporary Redirect")
        self.send_header("Location", unquote_plus(qs))
        self.end_headers()
        return False

      log.debug("POX CookieGuard cookie is valid")
      return True
    else:
      # No guard cookie or guard cookie is wrong
      if requested.startswith(self._pox_cookieguard_bouncer + "?"):
        # Client probably didn't save cookie
        qs = requested.split("?",1)[1]
        target = unquote_plus(qs)
        bad_qs = quote_plus(target) != qs
        if bad_qs or self.command != "GET":
          log.warn("Bad POX CookieGuard bounce; possible attack "
                   "(method:%s cookie:%s qs:%s)",
                   self.command,
                   "bad" if cgc else "missing",
                   "bad" if bad_qs else "okay")
          self.send_response(400, "Bad Request")
          self.end_headers()
          return False

        self._do_cookieguard_explict_continuation(requested, target)
        return False

      if cgc:
        log.debug("POX CookieGuard got wrong cookie -- setting new one")
      else:
        log.debug("POX CookieGuard got no cookie -- setting one")

      self._do_cookieguard_set_cookie(requested, bool(cgc))
      return False


import http.server
from http.server import SimpleHTTPRequestHandler


class SplitRequestHandler (BaseHTTPRequestHandler):
  """
  To write HTTP handlers for POX, inherit from this class instead of
  BaseHTTPRequestHandler.  The interface should be the same -- the same
  variables should be set, and the same do_GET(), etc. methods should
  be called.

  In addition, there will be a self.args which can be specified
  when you set_handler() on the server.
  """
  # Also a StreamRequestHandler

  def __init__ (self, parent, prefix, args):
    _setAttribs(parent, self)

    self.parent = parent
    self.args = args
    self.prefix = prefix

    self._init()

  def _init (self):
    """
    This is called by __init__ during initialization.  You can
    override it to, for example, parse .args.
    """
    pass

  @classmethod
  def format_info (cls, args):
    """
    Get an info string about this handler

    This is displayed, for example, in the "Web Prefixes" list of the default
    POX web server page.
    """
    def shorten (s, length=100):
      s = str(s)
      if len(s) > length: s = s[:length] + "..."
      return s
    return shorten(str(args))

  def version_string (self):
    return "POX/%s(%s) %s" % (".".join(map(str, core.version)),
                              core.version_name,
                              BaseHTTPRequestHandler.version_string(self))

  def handle_one_request (self):
    raise RuntimeError("Not supported")

  def handle(self):
    raise RuntimeError("Not supported")

  def _split_dispatch (self, command, handler = None):
    if handler is None: handler = self
    mname = 'do_' + self.command
    if not hasattr(handler, mname):
        self.send_error(501, "Unsupported method (%r)" % self.command)
        return
    method = getattr(handler, mname)
    return method()

  def log_request (self, code = '-', size = '-'):
    weblog.debug(self.prefix + (':"%s" %s %s' %
              (self.requestline, str(code), str(size))))

  def log_error (self, fmt, *args):
    weblog.error(self.prefix + ':' + (fmt % args))

  def log_message (self, fmt, *args):
    weblog.info(self.prefix + ':' + (fmt % args))


_favicon = ("47494638396110001000c206006a5797927bc18f83ada9a1bfb49ceabda"
 + "4f4ffffffffffff21f904010a0007002c000000001000100000034578badcfe30b20"
 + "1c038d4e27a0f2004e081e2172a4051942abba260309ea6b805ab501581ae3129d90"
 + "1275c6404b80a72f5abcd4a2454cb334dbd9e58e74693b97425e07002003b")
_favicon = bytes(int(_favicon[n:n+2],16)
                 for n in range(0,len(_favicon),2))

class CoreHandler (SplitRequestHandler):
  """
  A default page to say hi from POX.
  """
  def do_GET (self):
    """Serve a GET request."""
    self.do_content(True)

  def do_HEAD (self):
    """Serve a HEAD request."""
    self.do_content(False)

  def do_content (self, is_get):
    if self.path == "/":
      self.send_info(is_get)
    elif self.path.startswith("/favicon."):
      self.send_favicon(is_get)
    else:
      self.send_error(404, "File not found on CoreHandler")

  def send_favicon (self, is_get = False):
    self.send_response(200)
    self.send_header("Content-type", "image/gif")
    self.send_header("Content-Length", str(len(_favicon)))
    self.end_headers()
    if is_get:
      self.wfile.write(_favicon)

  def send_info (self, is_get = False):
    r = "<html><head><title>POX</title></head>\n"
    r += "<body>\n<h1>POX Webserver</h1>\n<h2>Components</h2>\n"
    r += "<ul>"
    for k in sorted(core.components):
      v = core.components[k]
      r += "<li>%s - %s</li>\n" % (cgi.escape(str(k)), cgi.escape(str(v)))
    r += "</ul>\n\n<h2>Web Prefixes</h2>"
    r += "<ul>"
    m = [list(map(cgi.escape, map(str, [x[0],x[1],x[1].format_info(x[3])])))
         for x in self.args.matches]
    m.sort()
    for v in m:
      r += "<li><a href='{0}'>{0}</a> - {1} {2}</li>\n".format(*v)
    r += "</ul></body></html>\n"

    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    if is_get:
      self.wfile.write(r.encode())


class StaticContentHandler (SplitRequestHandler, SimpleHTTPRequestHandler):
  """
  A SplitRequestHandler for serving static content

  This is largely the same as the Python SimpleHTTPRequestHandler, but
  we modify it to serve from arbitrary directories at arbitrary
  positions in the URL space.
  """

  server_version = "StaticContentHandler/1.0"

  def send_head (self):
    # We override this and handle the directory redirection case because
    # we want to include the per-split prefix.
    path = self.translate_path(self.path)
    if os.path.isdir(path):
      if not self.path.endswith('/'):
        self.send_response(302)
        self.send_header("Location", self.prefix + self.path + "/")
        self.end_headers()
        return None
    return SimpleHTTPRequestHandler.send_head(self)

  def list_directory (self, dirpath):
    # dirpath is an OS path
    try:
      d = os.listdir(dirpath)
    except OSError as e:
      if e.errno == errno.EACCES:
        self.send_error(403, "This directory is not listable")
      elif e.errno == errno.ENOENT:
        self.send_error(404, "This directory does not exist")
      else:
        self.send_error(400, "Unknown error")
      return None
    d.sort(key=str.lower)
    r = StringIO()
    r.write("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n")
    path = posixpath.join(self.prefix, cgi.escape(self.path).lstrip("/"))
    r.write("<html><head><title>" + path + "</title></head>\n")
    r.write("<body><pre>")
    parts = path.rstrip("/").split("/")
    r.write('<a href="/">/</a>')
    for i,part in enumerate(parts):
      link = urllib.parse.quote("/".join(parts[:i+1]))
      if i > 0: part += "/"
      r.write('<a href="%s">%s</a>' % (link, cgi.escape(part)))
    r.write("\n" + "-" * (0+len(path)) + "\n")

    dirs = []
    files = []
    for f in d:
      if f.startswith("."): continue
      if os.path.isdir(os.path.join(dirpath, f)):
        dirs.append(f)
      else:
        files.append(f)

    def entry (n, rest=''):
      link = urllib.parse.quote(n)
      name = cgi.escape(n)
      r.write('<a href="%s">%s</a>\n' % (link,name+rest))

    for f in dirs:
      entry(f, "/")
    for f in files:
      entry(f)

    r.write("</pre></body></html>")
    r.seek(0)
    self.send_response(200)
    self.send_header("Content-Type", "text/html")
    self.send_header("Content-Length", str(len(r.getvalue())))
    self.end_headers()
    return BytesIO(r.read().encode())

  def translate_path (self, path, include_prefix = True):
    """
    Translate a web-path to a local filesystem path

    Odd path elements (e.g., ones that contain local filesystem path
    separators) are stripped.
    """

    def fixpath (p):
      o = []
      skip = 0
      while True:
        p,tail = posixpath.split(p)
        if p in ('/','') and tail == '': break
        if tail in ('','.', os.path.curdir, os.path.pardir): continue
        if os.path.sep in tail: continue
        if os.path.altsep and os.path.altsep in tail: continue
        if os.path.splitdrive(tail)[0] != '': continue

        if tail == '..':
          skip += 1
          continue
        if skip:
          skip -= 1
          continue
        o.append(tail)
      o.reverse()
      return o

    # Remove query string / fragment
    if "?" in path: path = path[:path.index("?")]
    if "#" in path: path = path[:path.index("#")]
    path = fixpath(path)
    if path:
      path = os.path.join(*path)
    else:
      path = ''
    if include_prefix:
      path = os.path.join(os.path.abspath(self.args['root']), path)
    return path


def wrapRequestHandler (handlerClass):
  return type("Split" + handlerClass.__name__,
              (SplitRequestHandler, handlerClass, object), {})


from http.server import CGIHTTPRequestHandler
class SplitCGIRequestHandler (SplitRequestHandler,
                              CGIHTTPRequestHandler, object):
  """
  Runs CGIRequestHandler serving from an arbitrary path.
  This really should be a feature of CGIRequestHandler and the way of
  implementing it here is scary and awful, but it at least sort of works.
  """
  __lock = threading.Lock()
  def _split_dispatch (self, command):
    with self.__lock:
      olddir = os.getcwd()
      try:
        os.chdir(self.args)
        return SplitRequestHandler._split_dispatch(self, command)
      finally:
        os.chdir(olddir)


class SplitterRequestHandler (BaseHTTPRequestHandler, BasicAuthMixin,
                              POXCookieGuardMixin):
  basic_auth_info = {} # username -> password
  basic_auth_enabled = None
  pox_cookieguard = True

  def __init__ (self, *args, **kw):
    if self.basic_auth_info:
      self.basic_auth_enabled = True

    #self.rec = Recording(args[0])
    #self.args = args
    #self.matches = self.matches.sort(key=lambda e:len(e[0]),reverse=True)
    #BaseHTTPRequestHandler.__init__(self, self.rec, *args[1:], **kw)
    try:
      BaseHTTPRequestHandler.__init__(self, *args, **kw)
    except socket.error as e:
      if e.errno == errno.EPIPE:
        weblog.warn("Broken pipe (unclean client disconnect?)")
      else:
        raise
    finally:
      _shutdown_helper.unregister(self.connection)

  def log_request (self, code = '-', size = '-'):
    weblog.debug('splitter:"%s" %s %s',
                 self.requestline, str(code), str(size))

  def log_error (self, fmt, *args):
    weblog.error('splitter:' + fmt % args)

  def log_message (self, fmt, *args):
    weblog.info('splitter:' + fmt % args)

  def version_string (self):
    return "POX/%s(%s) %s" % (".".join(map(str, core.version)),
                              core.version_name,
                              BaseHTTPRequestHandler.version_string(self))

  def _check_basic_auth (self, user, password):
    if self.basic_auth_info.get(user) == password: return True
    import web.authentication
    web.authentication.log.warn("Authentication failure")
    return False

  def _get_auth_realm (self):
    return "POX"

  def handle_one_request(self):
    _shutdown_helper.register(self.connection)
    self.raw_requestline = self.rfile.readline()
    if not self.raw_requestline:
        self.close_connection = 1
        return
    if not self.parse_request(): # An error code has been sent, just exit
        return

    if not self._do_auth(): return

    handler = None

    while True:
      for m in self.server.matches:
        if self.path.startswith(m[0]):
          #print m,self.path
          handler = m[1](self, m[0], m[3])
          #pb = self.rec.getPlayback()
          #handler = m[1](pb, *self.args[1:])
          _setAttribs(self, handler)
          if m[2]:
            # Trim. Behavior is not "perfect"
            handler.path = self.path[len(m[0]):]
            if m[0].endswith('/'):
              handler.path = '/' + handler.path
          break

      if handler is None:
        handler = self
        if not self.path.endswith('/'):
          # Handle splits like directories
          self.send_response(302)
          self.send_header("Location", self.path + "/")
          self.end_headers()
          break

      break

    override_cg = getattr(handler, "pox_cookieguard", None)
    if not self._do_cookieguard(override_cg): return

    event = WebRequest(self, handler)
    self.server.raiseEventNoErrors(event)
    if event.handler:
      return event.handler._split_dispatch(self.command)


class WebRequest (Event):
  """
  Hook for requests on the POX web server.

  This event is fired when the webserver is going to handle a request.
  The listener can modify the .handler to change how the event is
  handled.  Or it can just be used to spy on requests.

  If the handler is the splitter itself, then the page wasn't found.
  """
  splitter = None
  handler = None

  def __init__ (self, splitter, handler):
    self.splitter = splitter
    self.handler = handler

  def set_handler (self, handler_class):
    """
    Set a new handler class
    """
    h = self.handler
    self.handler = handler_class(h.parent, h.prefix, h.args)


class SplitThreadedServer(ThreadingMixIn, HTTPServer, EventMixin):
  _eventMixin_events = set([WebRequest])

  matches = [] # Tuples of (Prefix, TrimPrefix, Handler)

  def __init__ (self, *args, **kw):
    self.matches = list(self.matches)
    self.ssl_server_key = kw.pop("ssl_server_key", None)
    self.ssl_server_cert = kw.pop("ssl_server_cert", None)
    self.ssl_client_certs = kw.pop("ssl_client_certs", None)
    HTTPServer.__init__(self, *args, **kw)
#    self.matches = self.matches.sort(key=lambda e:len(e[0]),reverse=True)

    self.ssl_enabled = False
    if self.ssl_server_key or self.ssl_server_cert or self.ssl_client_certs:
      import ssl
      # The Python SSL stuff being used this way means that failing to set up
      # SSL can hang a connection open, which is annoying if you're trying to
      # shut down POX.  Do something about this later.
      cert_reqs = ssl.CERT_REQUIRED
      if self.ssl_client_certs is None:
        cert_reqs = ssl.CERT_NONE
      self.socket = ssl.wrap_socket(self.socket, server_side=True,
          keyfile = self.ssl_server_key, certfile = self.ssl_server_cert,
          ca_certs = self.ssl_client_certs, cert_reqs = cert_reqs,
          do_handshake_on_connect = True,
          ssl_version = ssl.PROTOCOL_TLSv1_2,
          suppress_ragged_eofs = True)
      self.ssl_enabled = True

  def set_handler (self, prefix, handler, args = None, trim_prefix = True):
    # Not very efficient
    assert (handler is None) or (issubclass(handler, SplitRequestHandler))
    self.matches = [m for m in self.matches if m[0] != prefix]
    if handler is None: return
    self.matches.append((prefix, handler, trim_prefix, args))
    self.matches.sort(key=lambda e:len(e[0]),reverse=True)

  def add_static_dir (self, www_path, local_path=None, relative=False):
    """
    Serves a directory of static content.
    www_path is the prefix of the URL that maps to this directory.
    local_path is the directory to serve content from.  If it's not
    specified, it is assume to be a directory with the same name as
    www_path.
    relative, if True, means that the local path is to be a sibling
    of the calling module.
    For an example, see the launch() function in this module.
    """
    if not www_path.startswith('/'): www_path = '/' + www_path

    if local_path is None:
      local_path = www_path[1:]
      if relative:
        local_path = os.path.basename(local_path)
    if relative:
      import inspect
      path = inspect.stack()[1][1]
      path = os.path.dirname(path)
      local_path = os.path.join(path, local_path)

    local_path = os.path.abspath(local_path)

    log.debug("Serving %s at %s", local_path, www_path)

    self.set_handler(www_path, StaticContentHandler,
                     {'root':local_path}, True);


class InternalContentHandler (SplitRequestHandler):
  """
  Serves data from inside the application, without backing files

  When it receives a GET or a HEAD, it translates the path from something
  like "/foo/bar.txt" to "foo__bar_txt".  It then tries several things:
  1) Looking up an attribute on the handler called "GET_foo__bar_txt".
  2) Treating self.args as a dictionary and looking for
     self.args["/foo/bar.txt"].
  3) Looking on self.args for an attribute called "GET_foo__bar_txt".
  4) Looking up an attribute on the handler called "GETANY".
  5) Looking up the key self.args[None].
  6) Looking up the attribute "GETANY" on self.args.

  Whichever of these it gets, it the result is callable, it calls it,
  passing the request itself as the argument (so if the thing is a
  method, it'll essentially just be self twice).

  The attribute or return value is ideally a tuple of (mime-type, bytes,
  headers).  You may omit the headers.  If you include it, it can either
  be a dictionary or a list of name/value pairs.  If you return a string
  or bytes instead of such a tuple, it'll try to guess between HTML or
  plain text.  It'll then send that to the client.  Easy!

  When a handler is set up with set_handler(), the third argument becomes
  self.args on the request.  So that lets you put data into an
  InternalContentHandler without subclassing.  Or just subclass it.

  For step 2 above, it will also look up the given path plus a slash.  If
  it finds it, it'll do an HTTP redirect to it.  In this way, you can
  provide things which look like directories by including the slashed
  versions in the dictionary.
  """
  args_content_lookup = True # Set to false to disable lookup on .args

  def do_GET (self):
    self.do_response(True)
  def do_HEAD (self):
    self.do_response(False)

  def do_response (self, is_get):
    path = "<Unknown>"
    try:
      path = self.path.lstrip("/").replace("/","__").replace(".","_")
      r = getattr(self, "GET_" + path, None)
      if r is None and self.args is not None and self.args_content_lookup:
        try:
          r = self.args[self.path]
        except Exception:
          try:
            dummy = self.args[self.path + "/"]
            # Ahh... directory without trailing slash.  Let's redirect.
            self.send_response(302, "Redirect to directory")
            self.send_header('Location', self.parent.path + '/')
            self.end_headers()
            return
          except Exception:
            pass
        if r is None:
          r = getattr(self.args, "GET_" + path, None)
      if r is None:
        r = getattr(self, "GETANY", None)
        if r is None and self.args is not None:
          try:
            r = self.args[None]
          except Exception:
            pass
          if r is None:
            r = getattr(self.args, "GETANY", None)
      if callable(r):
        r = r(self)

      if r is None:
        self.send_error(404, "File not found")
        return

      response_headers = []

      if len(r) >= 2 and len(r) <= 3 and not isinstance(r, (str,bytes)):
        ct = r[0]
        if len(r) >= 3:
          response_headers = r[2]
        r = r[1]
      else:
        if isinstance(r, str): r = r.encode()
        if r.lstrip().startswith(b'{') and r.rstrip().endswith(b'}'):
          ct = "application/json"
        elif b"<html" in r[:255]:
          ct = "text/html"
        else:
          ct = "text/plain"
      if isinstance(r, str): r = r.encode()
    except Exception as exc:
      self.send_error(500, "Internal server error")
      msg = "%s failed trying to get '%s'" % (type(self).__name__, path)
      if str(exc): msg += ": " + str(exc)
      log.debug(msg)
      return

    self.send_response(200)
    self.send_header("Content-type", ct)
    self.send_header("Content-Length", str(len(r)))
    if isinstance(response_headers, dict):
      response_headers = list(response_headers.items())
    for hname,hval in response_headers:
      self.send_header(hname, hval)
    self.end_headers()
    if is_get:
      self.wfile.write(r)


class FileUploadHandler (SplitRequestHandler):
  """
  A default page to say hi from POX.
  """
  def do_GET (self):
    """Serve a GET request."""
    self.send_form(True)

  def do_HEAD (self):
    """Serve a HEAD request."""
    self.send_form(False)

  def send_form (self, is_get = False, msg = None):
    r = "<html><head><title>POX</title></head>\n"
    r += "<body>\n<h1>POX File Upload</h1>\n"
    if msg:
      r += msg
      r += "\n<hr />\n"
    r += "<form method='POST' enctype='multipart/form-data' action='?'>\n"
    r += "File to upload: <input type='file' name='upload'>\n"
    r += "<input type='submit' value='Upload!' /></form>\n"
    r += "</body></html>\n"

    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    if is_get:
      self.wfile.write(r.encode())

  def do_POST (self):
    mime,params = cgi.parse_header(self.headers.get('content-type'))
    if mime != 'multipart/form-data':
      self.send_error(400, "Expected form data")
      return
    #query = cgi.parse_multipart(self.rfile, params)
    #data = query.get("upload")
    data = cgi.FieldStorage( fp = self.rfile, headers = self.headers,
                             environ={ 'REQUEST_METHOD':'POST' } )
    if not data or "upload" not in data:
      self.send_error(400, "Expected upload data")
      return
    uploadfield = data["upload"]

    msg = self.on_upload(uploadfield.filename, uploadfield.file)

    self.send_form(True, msg=msg)

  def on_upload (self, filename, datafile):
    data = datafile.read()
    import hashlib
    h = hashlib.md5()
    h.update(data)
    hc = h.hexdigest()
    msg = "Received file '%s'.  bytes:%s md5:%s" % (filename, len(data), hc)
    log.warn(msg)
    return msg


def upload_test (save=False):
  """
  Launch a file upload test

  --save will save the file using its MD5 for the filename
  """
  class SaveUploader (FileUploadHandler):
    def on_upload (self, filename, datafile):
      import io
      data = datafile.read()
      datafile = io.BytesIO(data)
      ret = super().on_upload(filename, datafile)
      import hashlib
      h = hashlib.md5()
      h.update(data)
      h = h.hexdigest().upper()
      with open("FILE_UPLOAD_" + h, "wb") as f:
        f.write(data)
      return ret
  handler = SaveUploader if save else FileUploadHandler

  core.WebServer.set_handler("/upload_test", handler)


def launch (address='', port=8000, static=False, ssl_server_key=None,
            ssl_server_cert=None, ssl_client_certs=None,
            no_cookieguard=False):
  """
  Starts a POX webserver

  --ssl_client_certs are client certificates which the browser supplies
    basically in order to authorize the client.  This is much more
    secure than just using HTTP authentication.

  --static alone enables serving static content from POX's www_root
    directory.  Otherwise it is a comma-separated list of prefix:paths
    pairs to serve (that is, it will serve the path at the prefix.  If
    there is no colon, it assumes the path and prefix are the same.  If
    one of the pairs is empty, we'll also serve www_root.

  --no-cookieguard disables POX CookieGuard.  See POXCookieGuardMixin
    documentation for more on this, but the short story is that disabling
    it will make your server much more vulnerable to CSRF attacks.
  """

  if no_cookieguard:
    SplitterRequestHandler.pox_cookieguard = False
    assert no_cookieguard is True, "--no-cookieguard takes no argument"

  def expand (f):
    if isinstance(f, str): return os.path.expanduser(f)
    return f
  ssl_server_key = expand(ssl_server_key)
  ssl_server_cert = expand(ssl_server_cert)
  ssl_client_certs = expand(ssl_client_certs)

  httpd = SplitThreadedServer((address, int(port)), SplitterRequestHandler,
                              ssl_server_key=ssl_server_key,
                              ssl_server_cert=ssl_server_cert,
                              ssl_client_certs=ssl_client_certs)
  core.register("WebServer", httpd)
  httpd.set_handler("/", CoreHandler, httpd, True)
  #httpd.set_handler("/foo", StaticContentHandler, {'root':'.'}, True)
  #httpd.set_handler("/f", StaticContentHandler, {'root':'pox'}, True)
  #httpd.set_handler("/cgis", SplitCGIRequestHandler, "pox/web/www_root")
  if static is True:
    httpd.add_static_dir('static', 'www_root', relative=True)
  elif static is False:
    pass
  else:
    static = static.split(",")
    for entry in static:
      if entry.lower() == "":
        httpd.add_static_dir('static', 'www_root', relative=True)
        continue
      if ':' not in entry:
        directory = entry
        prefix = os.path.split(directory)
        if prefix[1] == '':
          prefix = os.path.split(prefix[0])
        prefix = prefix[1]
        assert prefix != ''
      else:
        prefix,directory = entry.split(":")
      directory = os.path.expanduser(directory)
      httpd.add_static_dir(prefix, directory, relative=False)

  def run ():
    try:
      msg = "https" if httpd.ssl_enabled else "http"
      msg += "://%s:%i" % httpd.socket.getsockname()
      log.info("Listening at " + msg)
      httpd.serve_forever()
    except:
      pass
    log.info("Server quit")

  def go_up (event):
    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()

  def go_down (event):
    httpd.shutdown()

  core.addListenerByName("GoingUpEvent", go_up)
  core.addListenerByName("GoingDownEvent", go_down)
