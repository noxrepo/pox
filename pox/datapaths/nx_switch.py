# Copyright 2011 Andreas Wundsam
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

import inspect

import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira_ext as nx
from pox.openflow.switch_impl import SwitchImpl, ControllerConnection

_slave_blacklist = set([of.ofp_flow_mod, of.ofp_packet_out, of.ofp_port_mod, of.ofp_barrier_request])
_messages_for_all = set([of.ofp_port_status])

class NXSwitchImpl(SwitchImpl):
  """ Extension of the SwichImpl software switch that supports the nicira (NX) vendor extension from
      OpenVSwitch that allows the switch to connect to multiple controllers at the same time.

      In the beginning, all controllers start out as equals (ROLE_OTHER). Through the NX vendor message
      role_request, one controller can be promoted to ROLE_MASTER, in which case all other controllers
      are downgraded to slave status.

      The switch doesn't accept state-mutating messages (e.g., FLOW_MOD, see _slave_blacklist) from
      slave controllers.

      Messages are distributed to controllers according to their type:
       - symmetric message replies are sent to the controller that initiated them (e.g., STATS_REQUEST -> REPLY)
       - port_status messages are distributed to all controllers
       - all other messages are distributed to the master controller, or if non is present, any controller
         in ROLE_OTHER
  """
  def __init__(self, *args, **kw):
    SwitchImpl.__init__(self, *args, **kw)
    self.role_by_conn={}
    self.connections = []
    self.connection_in_action = None
    # index of the next 'other' controller to get a message 
    # (for round robin of async messages)
    self.next_other = 0

    self.beef_up_handlers()

  def beef_up_handlers(self):
    self.orig_handlers = self.ofp_handlers
    handlers = {}
    for (command, handler) in self.orig_handlers.iteritems():
      # note: python has lexical scoping. So I need to convert the
      # handler variable to a parameter in order to capture the current value
      def _handle(ofp, connection, handler=handler):
        self.connection_in_action = connection
        if not self.check_rights(ofp, connection):
          self.log.warn("Message %s not allowed for slave controller %d" % (ofp, connection.ID))
          self.send_error(connection)
        else:
          if "connection" in inspect.getargspec(handler)[0]:
            handler(ofp, connection=connection)
          else:
            handler(ofp)
        self.connection_in_action = None
      handlers[command] = _handle
    self.log.info(str(handlers))
    self.ofp_handlers = handlers

  def check_rights(self, ofp, connection):
    if self.role_by_conn[connection.ID] != nx.ROLE_SLAVE:
      return True
    else:
      return not type(ofp) in _slave_blacklist

  def send_error(self, connection):
    # We don't support vendor extensions, so send an OFP_ERROR, per page 42 of spec
    err = of.ofp_error(type=of.OFPET_BAD_REQUEST, code=of.OFPBRC_BAD_VENDOR)
    connection.send(err)

  def send(self, message):
    if type(message) in _messages_for_all:
      for c in self.connections:
        c.send(message)
    elif self.connection_in_action:
      #self.log.info("Sending %s to active connection %d" % (str(message), self.connection_in_action.ID))
      self.connection_in_action.send(message)
    else:
      masters = [c for c in self.connections if self.role_by_conn[c.ID] == nx.ROLE_MASTER]
      if len(masters) > 0:
        masters[0].send(message)
      else:
        others = [c for c in self.connections if self.role_by_conn[c.ID] == nx.ROLE_OTHER]
        if len(others) > 0:
          self.next_other = self.next_other % len(others)
          #self.log.info("Sending %s to 'other' connection %d" % (str(message), self.next_other))
          others[self.next_other].send(message)
          self.next_other += 1
        else:
          self.log.info("Could not find any connection to send messages %s" % str(message))

  def set_io_worker(self, io_worker):
    conn = self.add_connection(ControllerConnection(io_worker, self.ofp_handlers))
    return conn

  def add_connection(self, connection):
    self.role_by_conn[connection.ID] = nx.ROLE_OTHER
    self.connections.append(connection)
    return connection

  def set_connection(self, connection):
    self.add_connection(connection)

  def set_role(self, connection, role):
    self.role_by_conn[connection.ID] = role
    if role == nx.ROLE_MASTER:
      for c in self.connections:
        if c != connection:
          self.role_by_conn[c.ID] = nx.ROLE_SLAVE

  def _receive_vendor(self, vendor, connection):
    self.log.debug("Vendor %s %s" % (self.name, str(vendor)))
    if(vendor.vendor == nx.VENDOR_ID):
      try:
        data = nx.unpack_vendor_data_nx(vendor.data)
        if isinstance(data, nx.role_request_data):
          self.set_role(connection, data.role)
          reply = of.ofp_vendor(vendor = nx.VENDOR_ID, data = nx.role_reply_data(role = data.role))
          self.send(reply)
          return
      except NotImplemented:
        self.send_error(connection)
    else:
      return SwitchImpl._receive_vendor(self, vendor)
