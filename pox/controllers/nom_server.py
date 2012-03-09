#!/usr/bin/env python
# Nom nom nom nom

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import *
from pox.messenger.messenger import *
import pox.topology.topology as topology

from collections import namedtuple

import sys
import signal
import socket

name = "nom_server"
log = core.getLogger(name)

# Keep Nom Updates unique`
NomUpdate = namedtuple('NomUpdate', 'xid id2entity')

class NomServer (EventMixin):
  """
  The Nom "database". Keeps a copy of the Nom in memory, as well as a list
  of all registered clients. When a client calls NomServer.put(),
  invalidates + updates the caches of all registered clients

  Visually,  NomClient's connect to the NomServer through
  the following interfaces:

  ==========================                            ==========================
  |    NomClient           |                            |    NomServer           |
  |                        |   any mutating operation   |                        |
  |                        |  -------------------->     |server.put(nom)         |
  |                        |                            |                        |
  |          client.       |                            |                        |
  |            update_nom()|    cache invalidation      |                        |
  |                        |   <-------------------     |                        |
  ==========================                            ==========================
  """

  _core_name = name

  # The set of components we depend on. These must be loaded before we can begin.i
  _wantComponents = set(['topology'])

  def __init__(self):
    # Pre: core.messenger is registered
    # Wait for connections
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived, weak=True)

    # client name -> TCPMessageConnection
    self.registered = {}

    # Unique ids for Nom Updates (id's needed for ACKs)
    self.next_nom_update_id = 0

    # TODO: the following code is highly redundant with controller.rb
    self.topology = None
    if not core.listenToDependencies(self, self._wantComponents):
      # If dependencies aren't loaded, register event handlers for ComponentRegistered
      self.listenTo(core)
    else:
      self._finish_initialization()

  def _handle_global_MessageReceived (self, event, msg):
    try:
      if 'nom_server_handshake' in msg:
        # It's for me! Store the connection object. Their name is the value
        event.con.read() # Consume the message
        # Claiming the message channel causes (local) MessageReceived to be triggered
        # from here on after
        event.claim()
        event.con.addListener(MessageReceived, self._handle_MessageReceived, weak=True)
        controller_name = msg['nom_server_handshake']
        self.register_client(controller_name, event.con)
        log.debug("- started conversation with %s" % controller_name)
      else:
        log.debug("- ignoring")
    except:
      pass

  def _handle_MessageReceived (self, event, msg):
    # Message handler for an individiual connection
    if event.con.isReadable():
      r = event.con.read()
      if type(r) is not dict:
        log.warn("message was not a dict!")
        return

      log.debug("MessageRecieved -%s" % str(r.keys()))

      if r.get("bye",False):
        log.debug("- goodbye!")
        event.con.close()
      if "get" in r:
        self.get(event.con)
      if "put" in r:
        self.put(r["put"])
      if "nom_update_ack" in r:
        self.update_ack(r['nom_update_ack'])
    else:
      log.debug("- conversation finished")

  def _handle_ComponentRegistered (self, event):
    """ Checks whether the newly registered component is one of our dependencies """
    if core.listenToDependencies(self, self._wantComponents):
      self._finish_initialization()

  def _finish_initialization(self):
    self.topology = core.components['topology']
    log.info("nom_server: initialization completed")

  def register_client(self, client_name, connection):
    log.info("register %s" % client_name)
    self.registered[client_name] = connection
    # TODO: can we assume that topology is booted?
    self.topology.addEntity(topology.Controller(client_name))

  def unregister_client(self, client):
    pass

  def _next_update_xid(self):
    xid = self.next_nom_update_id
    self.next_nom_update_id += 1
    return xid

  def get(self, conn):
    log.info("get")
    serialized = self.topology.serialize()
    xid = self._next_update_xid()
    update = NomUpdate(xid, serialized)
    conn.send({"nom_update":update})
    log.debug("get answer %d sent" % xid)

  def put(self, id2entity):
    # TODO: does nom_server need to send back an ACK?
    log.info("put")
    self.topology.deserializeAndMerge(id2entity)
    # TODO: optimization: don't send upate to the original sender
    # TODO: rather than send a snapshot of the entire Topology, use
    #       an rsync-like stream of Updates
    for client_name in self.registered.keys():
      log.debug("invalidating/updating %s" % client_name)
      connection = self.registered[client_name]
      # Push out the new topology
      self.get(connection)

  def update_ack(self, update_ack):
    xid, controller_name = update_ack
    controller = self.topology.getEntityByID(controller_name)
    controller.handshake_completed()
    self.topology.raiseEvent(topology.Update())
    # TODO: do something else with the ACK

def launch():
  import pox.messenger.messenger as messenger
  # TODO: don't assume localhost:7790 for emulation
  messenger.launch()
  from pox.core import core
  core.registerNew(NomServer)
