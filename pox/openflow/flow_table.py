#!/usr/bin/env python
"""
Implementation of an OpenFlow flow table

@author: Colin Scott (cs@cs.berkeley.edu)

"""
from collections import namedtuple
from libopenflow_01 import *

import time

# FlowTable Entries:
#   match - ofp_match (13-tuple)
#   counters - hash from name -> count. May be stale
#   actions - ordered list of ofp_action_*s to apply for matching packets
class TableEntry (object):
  """
  Models a flow table entry, with a match, actions, and options/flags/counters.
  Note: the current time can either be specified explicitely with the optional 'now' parameter or is taken from time.time()
  """

  def __init__(self,priority=OFP_DEFAULT_PRIORITY, cookie = 0, idle_timeout=0, hard_timeout=0, match=ofp_match(), actions=[], now=None):
    # overriding __new__ instead of init to make fields optional. There's probably a better way to do this.
    if now==None: now = time.time()
    self.counters = {
        'created': now,
        'last_touched': now,
        'bytes': 0,
        'packets': 0
    }
    self.priority = priority
    self.cookie = cookie
    self.idle_timeout = idle_timeout
    self.hard_timeout = hard_timeout
    self.match = match
    self.actions = actions

  @staticmethod
  def from_flow_mod(flow_mod):
    priority = flow_mod.priority
    cookie = flow_mod.cookie
    match = flow_mod.match
    actions = flow_mod.actions

    return TableEntry(priority, cookie, flow_mod.idle_timeout, flow_mod.hard_timeout, match, actions)

  def to_flow_mod(self, **kw):
    return ofp_flow_mod(priority = self.priority, cookie = self.cookie, match = self.match,
                        idle_timeout = self.idle_timeout, hard_timeout = self.hard_timeout,
                          actions = self.actions, **kw)

  def is_matched_by(self, match, priority = None, strict = False):
    """ return whether /this/ entry is matched by some other entry (e.g., for FLOW_MOD updates) """
    if(strict):
      return (self.match == match and self.priority == priority)
    else:
      return match.matches_with_wildcards(self.match)

  def touch_packet(self, byte_count, now=None):
    """ update the counters and expiry timer of this entry for a packet with a given byte count"""
    if now==None: now = time.time()
    self.counters["bytes"] += byte_count
    self.counters["packets"] += 1
    self.counters["last_touched"] = now

  def is_expired(self, now=None):
    """" return whether this flow entry is expired due to its idle timeout or hard timeout"""
    if now==None: now = time.time()
    return (self.hard_timeout > 0 and now - self.counters["created"] > self.hard_timeout) or (self.idle_timeout > 0 and now - self.counters["last_touched"] > self.idle_timeout)

class FlowTable (object):
  """
  General model of a flow table. Maintains an ordered list of flow entries, and finds
  matching entries for packets and other entries. Supports expiration of flows.
  """
  def __init__(self):
    # For now we represent the table as a multidimensional array.
    #
    # [ (cookie, match, counters, actions),
    #   (cookie, match, counters, actions),
    #    ...                        ]
    # 
    # Implies O(N) lookup for now. TODO: fix
    self._table = []

  @property
  def entries(self):
    return self._table

  def __len__(self):
    return len(self._table)

  def add_entry(self, entry):
    if not isinstance(entry, TableEntry):
      raise "Not an Entry type"
    self._table.append(entry)

    # keep table sorted by descending priority, with exact matches always going first
    # note: python sort is stable
    self._table.sort(key=lambda(e): (e.priority if e.match.is_wildcarded else (1<<16) + 1), reverse=True)

  def entries_for_port(self, port_no):
    entries = []
    for entry in self._table:
      actions = entry.actions
      if len(actions) > 0:
        last_action = actions[-1]
        if type(last_action) == ofp_action_output:
          outgoing_port = last_action.port.port_no
          if outgoing_port == port_no:
            entries.apend(entry)
    return entries

  def matching_entries(self, match, priority=0, strict=False):
    return [ entry for entry in self._table if entry.is_matched_by(match, priority, strict) ]

  def expired_entries(self, now=None):
    return [ entry for entry in self._table if entry.is_expired(now) ]

  def remove_expired_entries(self, now=None):
    remove_flows = self.expired_entries(now)
    for entry in remove_flows:
        self._table.remove(entry)
    return remove_flows

  def remove_matching_entries(self, match, priority=0, strict=False):
    remove_flows = self.matching_entries(match, priority, strict)
    for entry in remove_flows:
        self._table.remove(entry)
    return remove_flows

  def entry_for_packet(self, packet, in_port=None):
    """ return the highest priority flow table entry that matches the given packet 
    on the given in_port, or None if no matching entry is found. """
    packet_match = ofp_match.from_packet(packet, in_port)
    for entry in self._table:
      if entry.match.matches_with_wildcards(packet_match):
        return entry
    else:
      return None

class SwitchFlowTable(FlowTable):
  """ 
  Model a flow table for our switch implementation. Handles the behavior in response
  to the OF messages send to the switch 
  """

  def process_flow_mod(self, flow_mod):
    """ Process a flow mod sent to the switch 
    @return a tuple (added|modified|removed, [list of affected entries])
    """
    if(flow_mod.flags & OFPFF_CHECK_OVERLAP): raise("OFPFF_CHECK_OVERLAP checking not implemented")
    if(flow_mod.out_port != OFPP_NONE): raise("flow_mod outport checking not implemented")

    if flow_mod.command == OFPFC_ADD:
      # exactly matching entries have to be removed
      self.remove_matching_entries(flow_mod.match,flow_mod.priority, strict=True)
      return ("added", self.add_entry(TableEntry.from_flow_mod(flow_mod)))
    elif flow_mod.command == OFPFC_MODIFY or flow_mod.command == OFPFC_MODIFY_STRICT:
      is_strict = (flow_mod.command == OFPFC_MODIFY_STRICT)
      modified = []
      for entry in self._table:
        # update the actions field in the matching flows
        if(entry.is_matched_by(flow_mod.match, priority=flow_mod.priority, strict=is_strict)):
          entry.actions = flow_mod.actions
          modified.append(entry)
      if(len(modified) == 0):
        # if no matching entry is found, modify acts as add
        return ("added", self.add_entry(TableEntry.from_flow_mod(flow_mod)))
      else:
        return ("modified", modified)

    elif flow_mod.command == OFPFC_DELETE or flow_mod.command == OFPFC_DELETE_STRICT:
      is_strict = (flow_mod.command == OFPFC_DELETE_STRICT)
      return ("removed", self.remove_matching_entries(flow_mod.match, flow_mod.priority, strict=True))
    else:
      raise AttributeError("Command not yet implemented: %s" % command)

class NOMFlowTable(FlowTable):
  """ 
  Model a flow table for use in our NOM model. Keep in sync with a switch through a
  connection using a sync strategy
  """

  def process_flow_removed(self, flow_removed):
    """ process a flow removed event -- remove the matching flow from the table. """
    for flow in self._table:
      if(flow_removed.match == flow.match and flow_removed.cookie == flow.cookie):
        self._table.remove(flow)
        return

class TableSyncStrategy:
  """" Keeps the topology-level FlowTable in sync with the connection """
  def __init__(self, connection, connect_merge_policy):
    self.switch = switch
    self.connection = connection
    self.connect_merge_policy = connect_merge_policy
    self._syncConnection(True)

  def _syncConnection(initial_connect):
    if(self.connect_merge_policy == OVERWRITE_SWITCH):
      connection.send(of.ofp_flow_mod(match=of.ofp_match(), command=of.OFPFC_DELETE))
      barrier = of.ofp_barrier_request()
      def finish_clear (event):
        if event.xid == barrier.xid:
          self.install_flows(flow_table)
          return EventHaltAndRemove
        else:
          return EventContinue
      connection.addListener(BarrierIn, finish_connecting)
      connection.send(barrier)
    elif(self.connect_merge_policy == OVERWRITE_CONTROLLER):
      def flow_stats_received(event):
        self.update_table_from_stats(event.stats)
        return EventHaltAndRemove
      connection.addListener(FlowStatsReceived, overwrite_stats)
      connection.send(of.ofp_flow_stats_request())

  def update_table_from_stats(self, stats):
    for flow in stats.flows:
      table.for_cookie[flow.cookie] = flow

  def install_all_flows(self, flow_table):
    for entry in flow_table.entries:
      self.connection.send(entry.to_flow_mod(command = OFP_FLOW_ADD))

    barrier = of.ofp_barrier_request()
    def finish_install (event):
      if event.xid == barrier.xid:
        self.install_flows(flow_table)
        return EventHaltAndRemove
      else:
        return EventContinue
    connection.addListener(BarrierIn, finish_install)
    connection.send(barrier)

  def switch_connectionUp(connection, initial_connect):
    self.connection = connection
    self._syncConnection(False)

  def switch_connectionDown():
    self.connection = None

