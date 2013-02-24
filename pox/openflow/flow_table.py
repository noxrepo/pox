# Copyright 2011,2012,2013 Colin Scott
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
Implementation of an OpenFlow flow table
"""

from libopenflow_01 import *
from pox.lib.revent import *

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

  def __init__(self,priority=OFP_DEFAULT_PRIORITY, cookie = 0, idle_timeout=0, hard_timeout=0, flags=0, match=ofp_match(), actions=[], buffer_id=None, now=None):

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
    self.flags = flags
    self.match = match
    self.actions = actions
    self.buffer_id = buffer_id

  @staticmethod
  def from_flow_mod(flow_mod):
    priority = flow_mod.priority
    cookie = flow_mod.cookie
    match = flow_mod.match
    actions = flow_mod.actions
    buffer_id = flow_mod.buffer_id
    flags = flow_mod.flags

    return TableEntry(priority, cookie, flow_mod.idle_timeout, flow_mod.hard_timeout, flags, match, actions, buffer_id)

  def to_flow_mod(self, flags=None, **kw):
    if flags is None:
      flags = self.flags
    return ofp_flow_mod(priority = self.priority, cookie = self.cookie, match = self.match,
                        idle_timeout = self.idle_timeout, hard_timeout = self.hard_timeout,
                          actions = self.actions, buffer_id = self.buffer_id, flags = flags, **kw)

  def is_matched_by(self, match, priority = None, strict = False, out_port=None):
    """ return whether /this/ entry is matched by some other entry (e.g., for FLOW_MOD updates) """
    check_port = lambda: out_port == None or any(isinstance(a, ofp_action_output) and a.port == out_port for a in self.actions)

    if(strict):
      return (self.match == match and self.priority == priority) and check_port()
    else:
      return match.matches_with_wildcards(self.match) and check_port()

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

  def __str__ (self):
    return self.__class__.__name__ + "\n  " + self.show()

  def __repr__(self):
    return "TableEntry("+self.show() + ")"

  def show(self):
       return "priority=%s, cookie=%x, idle_timeoout=%d, hard_timeout=%d, match=%s, actions=%s buffer_id=%s" % (
          self.priority, self.cookie, self.idle_timeout, self.hard_timeout, self.match, repr(self.actions), str(self.buffer_id))

  def flow_stats(self, now=None):
    if now == None: now = time.time()
    duration = now - self.counters["created"]
    return ofp_flow_stats (
        match = self.match,
        duration_sec = int(duration),
        duration_nsec = int(duration * 1e9),
        priority = self.priority,
        idle_timeout = self.idle_timeout,
        hard_timeout = self.hard_timeout,
        cookie = self.cookie,
        packet_count = self.counters["packets"],
        byte_count = self.counters["last_touched"],
        actions = self.actions
        )


class FlowTableModification (Event):
  def __init__(self, added=[], removed=[]):
    Event.__init__(self)
    self.added = added
    self.removed = removed


class FlowTable (EventMixin):
  _eventMixin_events = set([FlowTableModification])

  """
  General model of a flow table. Maintains an ordered list of flow entries, and finds
  matching entries for packets and other entries. Supports expiration of flows.
  """
  def __init__(self):
    EventMixin.__init__(self)
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

    self.raiseEvent(FlowTableModification(added=[entry]))

  def remove_entry(self, entry):
    if not isinstance(entry, TableEntry):
      raise "Not an Entry type"
    self._table.remove(entry)
    self.raiseEvent(FlowTableModification(removed=[entry]))

  def entries_for_port(self, port_no):
    entries = []
    for entry in self._table:
      actions = entry.actions
      if len(actions) > 0:
        last_action = actions[-1]
        if type(last_action) == ofp_action_output:
          outgoing_port = last_action.port#.port_no
          if outgoing_port == port_no:
            entries.append(entry)
    return entries

  def matching_entries(self, match, priority=0, strict=False, out_port=None):
    return [ entry for entry in self._table if entry.is_matched_by(match, priority, strict, out_port) ]

  def flow_stats(self, match, out_port=None, now=None):
    return ( e.flow_stats() for e in self.matching_entries(match=match, strict=False, out_port=out_port))

  def expired_entries(self, now=None):
    return [ entry for entry in self._table if entry.is_expired(now) ]

  def remove_expired_entries(self, now=None):
    remove_flows = self.expired_entries(now)
    for entry in remove_flows:
        self._table.remove(entry)
    self.raiseEvent(FlowTableModification(removed=remove_flows))
    return remove_flows

  def remove_matching_entries(self, match, priority=0, strict=False):
    remove_flows = self.matching_entries(match, priority, strict)
    for entry in remove_flows:
        self._table.remove(entry)
    self.raiseEvent(FlowTableModification(removed=remove_flows))
    return remove_flows

  def entry_for_packet(self, packet, in_port):
    """ return the highest priority flow table entry that matches the given packet
    on the given in_port, or None if no matching entry is found. """
    packet_match = ofp_match.from_packet(packet, in_port)

    for entry in self._table:
      if entry.match.matches_with_wildcards(packet_match, consider_other_wildcards=False):
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
    if(flow_mod.flags & OFPFF_CHECK_OVERLAP):
      raise NotImplementedError("OFPFF_CHECK_OVERLAP checking not implemented")
    if(flow_mod.out_port != OFPP_NONE and
       flow_mod.command == ofp_flow_mod_command_rev_map['OFPFC_DELETE']):
      raise NotImplementedError("flow_mod outport checking not implemented")

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
      raise AttributeError("Command not yet implemented: %s" % flow_mod.command)
