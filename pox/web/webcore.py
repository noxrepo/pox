# Copyright 2011,2012 James McCauley
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

from SocketServer import ThreadingMixIn
from BaseHTTPServer import *
from time import sleep
import select
import threading

import random
import hashlib
import base64

from pox.core import core

import os
import socket
import posixpath
import urllib
import cgi
import errno
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

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
    for s,(r,w,c) in cc.iteritems():
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


import SimpleHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler


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
_favicon = ''.join([chr(int(_favicon[n:n+2],16))
                   for n in xrange(0,len(_favicon),2)])

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
    m = [map(cgi.escape, map(str, [x[0],x[1],x[1].format_info(x[3])]))
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
      self.wfile.write(r)


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
        self.send_response(301)
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
      link = urllib.quote("/".join(parts[:i+1]))
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
      link = urllib.quote(n)
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
    return r

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


from CGIHTTPServer import CGIHTTPRequestHandler
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


class SplitterRequestHandler (BaseHTTPRequestHandler):
  def __init__ (self, *args, **kw):
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

  def handle_one_request(self):
    _shutdown_helper.register(self.connection)
    self.raw_requestline = self.rfile.readline()
    if not self.raw_requestline:
        self.close_connection = 1
        return
    if not self.parse_request(): # An error code has been sent, just exit
        return

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
          self.send_response(301)
          self.send_header("Location", self.path + "/")
          self.end_headers()
          break

      break

    return handler._split_dispatch(self.command)


class SplitThreadedServer(ThreadingMixIn, HTTPServer):
  matches = [] # Tuples of (Prefix, TrimPrefix, Handler)

#  def __init__ (self, *args, **kw):
#    BaseHTTPRequestHandler.__init__(self, *args, **kw)
#    self.matches = self.matches.sort(key=lambda e:len(e[0]),reverse=True)

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

  The attribute or return value is ideally a tuple of (mime-type, bytes),
  though if you just return the bytes, it'll try to guess between HTML or
  plain text.  It'll then send that to the client.  Easy!

  When a handler is set up with set_handler(), the third argument becomes
  self.args on the request.  So that lets you put data into an
  InternalContentHandler without subclassing.  Or just subclass it.

  For step 2 above, it will also look up the given path plus a slash.  If
  it finds it, it'll do an HTTP redirect to it.  In this way, you can
  provide things which look like directories by including the slashed
  versions in the dictionary.
  """
  def do_GET (self):
    self.do_response(True)
  def do_HEAD (self):
    self.do_response(False)

  def do_response (self, is_get):
    try:
      path = self.path.lstrip("/").replace("/","__").replace(".","_")
      r = getattr(self, "GET_" + path, None)
      if r is None and self.args is not None:
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

      if len(r) == 2 and not isinstance(r, str):
        ct,r = r
      else:
        if "<html" in r[:255]:
          ct = "text/html"
        else:
          ct = "text/plain"
    except Exception:
      self.send_error(500, "Internal server error")
      return

    self.send_response(200)
    self.send_header("Content-type", ct)
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    if is_get:
      self.wfile.write(r)


def launch (address='', port=8000, static=False):
  httpd = SplitThreadedServer((address, int(port)), SplitterRequestHandler)
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
      log.debug("Listening on %s:%i" % httpd.socket.getsockname())
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
