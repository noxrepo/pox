# Copyright 2011,2012 Andreas Wundsam
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

import inspect

import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nx
from pox.datapaths.switch import SoftwareSwitch, OFConnection

_slave_blacklist = set([of.ofp_flow_mod, of.ofp_packet_out, of.ofp_port_mod,
                        of.ofp_barrier_request])
_messages_for_all = set([of.ofp_port_status])


class NXSoftwareSwitch (SoftwareSwitch):
  """
  Software datapath with Nicira (NX) extensions

  Extension of the software switch that supports some of the Nicira (NX) vendor
  extensions that are part of Open vSwitch.

  In particular, this include the ability for a switch to connect to multiple
  controllers at the same time.

  In the beginning, all controllers start out as equals (ROLE_OTHER). Through
  the NX vendor message role_request, one controller can be promoted to
  ROLE_MASTER, in which case all other controllers are downgraded to slave
  status.

  The switch doesn't accept state-mutating messages (e.g., FLOW_MOD, see
  _slave_blacklist) from slave controllers.

  Messages are distributed to controllers according to their type:
    - symmetric message replies are sent to the controller that initiated them
      (e.g., STATS_REQUEST -> REPLY)
    - port_status messages are distributed to all controllers
    - all other messages are distributed to the master controller, or if none
      is present, any controller in ROLE_OTHER
  """

  def __init__ (self, *args, **kw):
    SoftwareSwitch.__init__(self, *args, **kw)
    self.role_by_conn={}
    self.connections = []
    self.connection_in_action = None
    # index of the next 'other' controller to get a message
    # (for round robin of async messages)
    self.next_other = 0

    # Set of connections to which we have sent hellos.  This is used to
    # as part of overriding the single-connection logic in the superclass.
    self._sent_hellos = set()

  def rx_message (self, connection, msg):
    """
    Handles incoming messages

    @overrides SoftwareSwitch.rx_message
    """

    self.connection_in_action = connection
    if not self.check_rights(msg, connection):
      self.log.warn("Message %s not allowed for slave controller %d", msg,
                    connection.ID)
      self.send_vendor_error(connection)
    else:
      SoftwareSwitch.rx_message(self, connection, msg)

    self.connection_in_action = None

  def check_rights (self, ofp, connection):
    if self.role_by_conn[connection.ID] != nx.NX_ROLE_SLAVE:
      return True
    else:
      return not type(ofp) in _slave_blacklist

  def send_vendor_error (self, connection):
    err = of.ofp_error(type=of.OFPET_BAD_REQUEST, code=of.OFPBRC_BAD_VENDOR)
    connection.send(err)

  def send (self, message):
    connections_used = []
    if type(message) in _messages_for_all:
      for c in self.connections:
        c.send(message)
        connections_used.append(c)
    elif self.connection_in_action:
      #self.log.info("Sending %s to active connection %d",
      #              (str(message), self.connection_in_action.ID))
      self.connection_in_action.send(message)
      connections_used.append(self.connection_in_action)
    else:
      masters = [c for c in self.connections
                 if self.role_by_conn[c.ID] == nx.NX_ROLE_MASTER]
      if len(masters) > 0:
        masters[0].send(message)
        connections_used.append(masters[0])
      else:
        others = [c for c in self.connections
                  if self.role_by_conn[c.ID] == nx.NX_ROLE_OTHER]
        if len(others) > 0:
          self.next_other = self.next_other % len(others)
          #self.log.info("Sending %s to 'other' connection %d",
          #              (str(message), self.next_other))
          others[self.next_other].send(message)
          connections_used.append(others[self.next_other])
          self.next_other += 1
        else:
          self.log.info("Could not find any connection to send messages %s",
                        str(message))
    return connections_used

  def add_connection (self, connection):
    self.role_by_conn[connection.ID] = nx.NX_ROLE_OTHER
    connection.set_message_handler(self.rx_message)
    self.connections.append(connection)
    return connection

  def set_connection (self, connection):
    self.add_connection(connection)

  def set_role (self, connection, role):
    self.role_by_conn[connection.ID] = role
    if role == nx.NX_ROLE_MASTER:
      for c in self.connections:
        if c != connection:
          self.role_by_conn[c.ID] = nx.NX_ROLE_SLAVE

  def _rx_hello (self, ofp, connection):
    # Override the usual hello-send logic
    if connection not in self._sent_hellos:
      self._sent_hellos.add(connection)
      self.send_hello(force=True)

  def _rx_vendor (self, vendor, connection):
    self.log.debug("Vendor %s %s", self.name, str(vendor))
    if vendor.vendor == nx.NX_VENDOR_ID:
      try:
        data = nx._unpack_nx_vendor(vendor.data)
        if isinstance(data, nx.nx_role_request):
          self.set_role(connection, data.role)
          reply = of.ofp_vendor(xid=vendor.xid, vendor = nx.NX_VENDOR_ID,
                                data = nx.nx_role_reply(role = data.role))
          self.send(reply)
          return
      except NotImplementedError:
        self.send_vendor_error(connection)
    else:
      return SoftwareSwitch._rx_vendor(self, vendor)
