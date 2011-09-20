# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

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

#from pox.messenger.messenger import MessengerConnection

from pox.core import core

import os
import posixpath
import urllib
import cgi
import shutil
import mimetypes
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

log = core.getLogger()

def _setAttribs (parent, child):
  attrs = ['command', 'request_version', 'close_connection',
           'raw_requestline', 'requestline', 'path', 'headers', 'wfile',
           'rfile', 'server', 'client_address']
  for a in attrs:
    setattr(child, a, getattr(parent, a))

  setattr(child, 'parent', parent)

import SimpleHTTPServer


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
    log.debug(self.prefix + (':"%s" %s %s' % 
              (self.requestline, str(code), str(size))))

  def log_error (self, fmt, *args):
    log.error(self.prefix + ':' + (fmt % args))

  def log_message (self, fmt, *args):
    log.info(self.prefix + ':' + (fmt % args))


class CoreHandler (SplitRequestHandler):
  """
  A default page to say hi from POX.
  """
  def do_GET (self):
    """Serve a GET request."""
    self.send_info(True)

  def do_HEAD (self):
    """Serve a HEAD request."""
    self.self_info(False)

  def send_info (self, isGet = False):
    r = "<html><head><title>POX</title></head>\n"
    r += "<body>\n<h1>POX Webserver</h1>\n<h2>Components</h2>\n"
    r += "<ul>"
    for k in sorted(core.components):
      v = core.components[k]
      r += "<li>%s - %s</li>\n" % (cgi.escape(str(k)), cgi.escape(str(v)))
    r += "</ul>\n\n<h2>Web Prefixes</h2>"
    r += "<ul>"
    m = [map(cgi.escape, map(str, [x[0],x[1],x[3]]))
         for x in self.args.matches]
    m.sort()
    for v in m:
      r += "<li>%s - %s %s</li>\n" % tuple(v)
    r += "</ul></body></html>\n"

    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    if isGet:
      self.wfile.write(r)


class StaticContentHandler (SplitRequestHandler):
    # This is basically SimpleHTTPRequestHandler from Python, but
    # modified to serve from given directories and to inherit from
    # SplitRequestHandler.

    """Simple HTTP request handler with GET and HEAD commands.

    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method.

    The GET and HEAD requests are identical except that the HEAD
    request omits the actual contents of the file.

    """

    server_version = "StaticContentHandler/1.0"

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def send_head(self):
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.prefix + self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may
            # cause newline translations, making the actual size of the
            # content transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified",self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        f = StringIO()
        displaypath = cgi.escape(urllib.unquote(self.path))
        f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write("<html>\n<title>Directory listing for %s</title>\n" %
                displaypath)
        f.write("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
        f.write("<hr>\n<ul>\n")
        f.write('<li><a href=".."><i>Parent Directory</i></a>\n')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # a link to a directory displays with @ and links with /
            f.write('<li><a href="%s">%s</a>\n'
                    % (urllib.quote(linkname), cgi.escape(displayname)))
        f.write("</ul>\n<hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        #path = os.getcwd()
        path = os.path.abspath(self.args['root'])
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.

        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).

        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.

        """
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        """Guess the type of a file.

        Argument is a PATH (a filename).

        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.

        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.

        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })


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
    BaseHTTPRequestHandler.__init__(self, *args, **kw)

  def log_request (self, code = '-', size = '-'):
    log.debug('splitter:"%s" %s %s',
              self.requestline, str(code), str(size))

  def log_error (self, fmt, *args):
    log.error('splitter:' + fmt % args)

  def log_message (self, fmt, *args):
    log.info('splitter:' + fmt % args)

  def handle_one_request(self):
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
          # redirect browser - doing basically what apache does
          self.send_response(301)
          print "redirect to ",self.path+'/'
          self.send_header("Location", self.path + "/")
          self.end_headers()
          continue

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


def launch (address='', port=8000, debug=False, static=False):
  if debug:
    log.setLevel("DEBUG")
    log.debug("Debugging enabled")
  elif log.isEnabledFor("DEBUG"):
    log.setLevel("INFO")

  httpd = SplitThreadedServer((address, int(port)), SplitterRequestHandler)
  core.register("WebServer", httpd)
  httpd.set_handler("/", CoreHandler, httpd, True)
  #httpd.set_handler("/foo", StaticContentHandler, {'root':'.'}, True)
  #httpd.set_handler("/f", StaticContentHandler, {'root':'pox'}, True)
  #httpd.set_handler("/cgis", SplitCGIRequestHandler, "pox/web/www_root")
  if static:
    httpd.add_static_dir('static', 'www_root', relative=True)

  def run ():
    try:
      httpd.serve_forever()
    except:
      pass
    log.info("Server quit")

  thread = threading.Thread(target=run)
  thread.daemon = True
  thread.start()

