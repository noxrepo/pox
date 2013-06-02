# Copyright 2013 James McCauley
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
A demo of working with IOWorker clients and servers

Run the server as:
 lib.ioworker.notify_demo:server

Clients can be run in several ways...

To just listen for notifications and show them as log messages:
 lib.ioworker.notify_demo:client --server=127.0.0.1 --name=SirSpam

To send a notification and quit, append --msg="Spam eggs spam".

Run with the Python interpreter (the 'py' component), and you get a
notify("<message>") command:
 POX> notify("Grilled tomatoes")

Run with Tk (the 'tk' component) to get a GUI.
"""

from pox.lib.ioworker import *
from pox.lib.ioworker.workers import *
from pox.core import core

log = core.getLogger()


# ---------------------------------------------------------------------------
# Client Stuff
# ---------------------------------------------------------------------------

client_worker = None
username = None
single_message = None

def notify (msg):
  if msg is None: return
  if client_worker is None:
    log.error("Can't send notification -- not connected")
  msg = msg.split("\n")
  for m in msg:
    client_worker.send("N %s %s\n" % (username, m))

class ClientWorker (PersistentIOWorker):
  def __init__ (self, *args, **kw):
    self.data = b''
    super(ClientWorker,self).__init__(*args,**kw)

  def _handle_close (self):
    global client_worker
    if client_worker is self:
      client_worker = None
      log.info("Disconnect")
    super(ClientWorker, self)._handle_close()
    if single_message:
      core.quit()

  def _handle_connect (self):
    global client_worker
    if client_worker is not None:
      client_worker.close()
    log.info("Connect")
    super(ClientWorker, self)._handle_connect()
    client_worker = self
    if single_message:
      notify(single_message)
      self.shutdown()

  def _handle_rx (self):
    self.data += self.read()
    while '\n' in self.data:
      msg,self.data = self.data.split('\n',1)
      if msg.startswith("N "):
        _,name,content = msg.split(None,2)
        log.warn("** %s: %s **", name, content)
        if core.hasComponent('tk'):
          # If Tk is running, pop up the message.
          core.tk.dialog.showinfo("Message from " + name, content)


def setup_input ():
  def cb (msg):
    if msg is None: core.quit()
    setup_input() # Pop box back up
    notify(msg)
  if not core.running: return
  core.tk.dialog.askstring_cb(cb, "Notification",
      "What notification would you like to send?")


def client (server, name = "Unknown", port = 8111, msg = None):

  global loop, username, single_message
  username = str(name).replace(" ", "_")
  single_message = msg

  core.Interactive.variables['notify'] = notify

  loop = RecocoIOLoop()
  #loop.more_debugging = True
  loop.start()

  w = ClientWorker(loop=loop, addr=server, port=int(port))

  if not msg:
    # If we have Tk running, pop up an entry box
    core.call_when_ready(setup_input, ['tk'])


# ---------------------------------------------------------------------------
# Server Stuff
# ---------------------------------------------------------------------------

class ServerWorker (TCPServerWorker, RecocoIOWorker):
  pass

clients = set()

class NotifyWorker (RecocoIOWorker):
  def __init__ (self, *args, **kw):
    super(NotifyWorker, self).__init__(*args, **kw)
    self._connecting = True
    self.data = b''

  def _handle_close (self):
    log.info("Client disconnect")
    super(NotifyWorker, self)._handle_close()
    clients.discard(self)

  def _handle_connect (self):
    log.info("Client connect")
    super(NotifyWorker, self)._handle_connect()
    clients.add(self)

  def _handle_rx (self):
    self.data += self.read()
    while '\n' in self.data:
      msg,self.data = self.data.split('\n',1)
      if msg.startswith("N "):
        _,name,content = msg.split(None,2)
        log.warn("** %s: %s **", name, content)
        for c in clients:
          if c is not self:
            c.send(msg + "\n")


def server (port = 8111):
  global loop
  loop = RecocoIOLoop()
  #loop.more_debugging = True
  loop.start()

  w = ServerWorker(child_worker_type=NotifyWorker, port = int(port))
  loop.register_worker(w)
