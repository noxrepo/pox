#!/usr/bin/env python
# Nom nom nom nom

# TODO: there is currently a dependency on the order of initialization of
# client and server... . for example:

#  $ pox.py nom_client nom_server    # blocks indefinitely

# whereas

#  $ pox.py nom_server nom_client    # works

from pox.core import core, UpEvent
from pox.lib.revent.revent import EventMixin
import pox.messenger.messenger as messenger
import pox.topology.topology as topology

import sys
import threading
import signal
import time
import copy
import socket
import pickle
from collections import namedtuple

UpdateACK = namedtuple('UpdateACK', 'xid controller_name')

class DistributedController(EventMixin, topology.Controller):
  """
  Keeps a copy of the Nom in its cache. Arbitrary controller applications
  can be implemented on top of NomClient through inheritance. Mutating calls to
  self.nom transparently write-through to the NomServer

  Visually,  NomClient's connect to the NomServer through
  the following interfaces:

  ==========================                            ==========================
  |    NomClient           |                            |    NomServer           |
  |                        |   any mutating operation   |                        |
  |                        |  -------------------->     |server.put(nom)         |
  |                        |                            |                        |
  |          client.       |   cache invalidation, or   |                        |
  |            update_nom()|   network event            |                        |
  |                        |   <-------------------     |                        |
  ==========================                            ==========================
  """
  def __init__(self, name):
    """
    Note that server may be a direct reference to the NomServer (for simulation), or a Pyro4 proxy
    (for emulation)

    pre: name is unique across the network
    """
    EventMixin.__init__(self)
    # We are a "controller" entity in pox.topology.
    # (Actually injecting ourself into pox.topology is handled
    # by nom_server)
    topology.Controller.__init__(self, name)
    self.name = name
    self.log = core.getLogger(name)
    # Construct an empty topology
    # The "master" copy topology will soon be merged into this guy
    self.topology = topology.Topology("topo:%s" % self.name)
    # Register subclass' event handlers
    self.listenTo(self.topology, "topology")

    self._server_connection = None
    self._queued_commits = []

    # For simulation. can't connect to NomServer until the Messenger is listening to new connections
    # TODO: for emulation, this should be removed / refactored --
    # just assume that the NomServer machine is up
    core.messenger.addListener(messenger.MessengerListening, self._register_with_server)

  def _register_with_server(self, event):
    self.log.debug("Attempting to register with NomServer")
    sock = socket.socket()
    # TODO: don't assume localhost -> should point to machine NomServer is running on
    # TODO: magic numbers should be re-factored as constants
    sock.connect(("localhost",7790))
    self._server_connection = messenger.TCPMessengerConnection(socket = sock)
    self._server_connection.addListener(messenger.MessageReceived, self._handle_MessageReceived)
    self.log.debug("Sending nom_server handshake")
    self._server_connection.send({"nom_server_handshake":self.name})
    self.log.debug("nom_server handhsake sent -- sending get request")
    # Answer comes back asynchronously as a call to nom_update
    self._server_connection.send({"get":None})
    self.log.debug("get request sent. Starting listen task")
    self._server_connection.start()

  def _handle_MessageReceived (self, event, msg):
    # TODO: event.claim() should be factored out -- I want to claim the connection
    #       before the first MessageReceived event occurs.
    event.claim()
    if event.con.isReadable():
      r = event.con.read()
      if type(r) is not dict:
        self.log.warn("message was not a dict!")
        return

      self.log.debug("Message received, type: %s-" % r.keys())

      if "nom_update" in r:
        self.nom_update(r["nom_update"])
    else:
      self.log.debug("- conversation finished")

  def nom_update(self, update):
    """
    According to Scott's philosophy of SDN, a control application is a
    function: F(view) => configuration

    This method is the entry point for the POX platform to update the
    view.

    The POX platform may invoke it in two situations:
      i.  NomServer will invalidate this client's cache in the
          case where another client modifies its copy of the NOM

      ii. Either POX or this client (should) register this method as a
          handler for network events.
    """
    xid, id2entity = update
    self.log.debug("nom_update %d" % xid)
    self.topology.deserializeAndMerge(id2entity)

    update_ack = UpdateACK(xid, self.name)
    self._server_connection.send({"nom_update_ack":update_ack})
    self.log.debug("Sent nom_update_ack %d, %s" % update_ack)

    # TODO: react to the change in the topology, by firing queued events to
    # subclass' ?
    return True

  def commit_nom_change(self):
    self.log.debug("Committing NOM update")
    if self._server_connection:
      self._server_connection.send({"put":self.topology.serialize()})
    else:
      self.log.debug("Queuing nom commit")
      self._queued_commits.append(copy.deepcopy(self.topology))

    # TODO: need to commit nom changes whenever the learning switch updates its state...
