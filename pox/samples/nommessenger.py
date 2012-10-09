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

from pox.core import core
from pox.messenger.messenger import *
from pox.lib.graph.util import *

log = pox.core.getLogger()

class NomMessenger (object):
  """
  The NomMessenger grabs a current JSON representation of the NOM and sends it
  to interested clients.
  The clients can request for the NOM sending the following messages to POX:
  '{"hello":"nommessenger"}' and '{"getnom":0}'
  """
  def __init__ (self):
    log.info("initializing")
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived, weak=True)
    self._targetName = "nommessenger"
    
    self.myEncoder = NOMEncoder()

  def _handle_global_MessageReceived (self, event, msg):
    try:
      n = msg['hello']
      if n == self._targetName:
        # It's for me!
        event.con.read() # Consume the message
        event.claim()
        event.con.addListener(MessageReceived, self._handle_MessageReceived, weak=True)
        print self._targetName, "- started conversation with", event.con
      else:
        print self._targetName, "- ignoring", n
    except:
      pass

  def _handle_MessageReceived (self, event, msg):
    if event.con.isReadable():
      r = event.con.read()
      print self._targetName, "-",r
      if type(r) is dict and r.get("bye",False):
        print self._targetName, "- GOODBYE!"
        event.con.close()
      if type(r) is dict and "getnom" in r:
        #
        #msg = {}
        nom = {"switches":[], "hosts":[], "links":[]}
        for s in core.topology.getEntitiesOfType(Switch):
          nom["switches"].append(self.myEncoder.encode(s))
        for h in core.topology.getEntitiesOfType(Host):
          nom["hosts"].append(self.myEncoder.encode(h))
        for l in core.topology.getEntitiesOfType(Link):
          nom["links"].append(self.myEncoder.encode(l))
        event.con.send(nom)
    else:
      print self._targetName, "- conversation finished"

def launch ():
  def realStart (event=None):
    if not core.hasComponent("messenger"):
      if event is None:
        # Only do this the first time
        log.warning("Deferring firing up NomMessenger because Messenger isn't up yet")
        core.addListenerByName("ComponentRegistered", realStart, once=True)
      return
    if not core.hasComponent(NomMessenger.__name__):
      core.registerNew(NomMessenger)
      log.info("Up...")

  realStart()
