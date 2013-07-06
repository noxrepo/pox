# Copyright 2011,2012,2013 Colin Scott
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

  Note: The current time can either be specified explicitely with the optional
        'now' parameter or is taken from time.time()
  """
  def __init__ (self, priority=OFP_DEFAULT_PRIORITY, cookie=0, idle_timeout=0,
                hard_timeout=0, flags=0, match=ofp_match(), actions=[],
                buffer_id=None, now=None):
    """
    Initialize table entry
    """
    # Overriding __new__ instead of init to make fields optional. There's
    #  probably a better way to do this.
    if now == None: now = time.time()
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
  def from_flow_mod (flow_mod):
    return TableEntry(priority=flow_mod.priority,
                      cookie=flow_mod.cookie,
                      idle_timeout=flow_mod.idle_timeout,
                      hard_timeout=flow_mod.hard_timeout,
                      flags=flow_mod.flags,
                      match=flow_mod.match,
                      actions=flow_mod.actions,
                      buffer_id=flow_mod.buffer_id)

  def to_flow_mod (self, flags=None, **kw):
    if flags is None: flags = self.flags
    return ofp_flow_mod(priority=self.priority,
                        cookie=self.cookie,
                        match=self.match,
                        idle_timeout=self.idle_timeout,
                        hard_timeout=self.hard_timeout,
                        actions=self.actions,
                        buffer_id=self.buffer_id,
                        flags=flags, **kw)

  def is_matched_by (self, match, priority=None, strict=False, out_port=None):
    """
    Tests whether a given match object matches this entry

    Used for, e.g., flow_mod updates
    """
    match_a = lambda a: isinstance(a, ofp_action_output) and a.port == out_port
    check_port = out_port == None or any(match_a(a) for a in self.actions)

    if strict:
      return self.match == match and self.priority == priority and check_port
    else:
      return match.matches_with_wildcards(self.match) and check_port

  def touch_packet (self, byte_count, now=None):
    """
    Updates information of this entry based on encountering a packet.

    Updates both the cumulative given byte counts of packets encountered and
    the expiration timer.
    """
    if now == None: now = time.time()
    self.counters["bytes"] += byte_count
    self.counters["packets"] += 1
    self.counters["last_touched"] = now

  def is_expired (self, now=None):
    """
    Tests whether this flow entry is expired due to its idle or hard timeout
    """
    if now == None: now = time.time()
    expired_hard = now - self.counters["created"] > self.hard_timeout
    expired_idle = now - self.counters["last_touched"] > self.idle_timeout
    return (self.hard_timeout > 0 and expired_hard
         or self.idle_timeout > 0 and expired_idle)

  def __str__ (self):
    return self.__class__.__name__ + "\n  " + self.show()

  def __repr__ (self):
    return "TableEntry(" + self.show() + ")"

  def show (self):
    outstr = ''
    outstr += "priority=%s, " % self.priority
    outstr += "cookie=%x, " % self.cookie
    outstr += "idle_timeout=%d, " % self.idle_timeout
    outstr += "hard_timeout=%d, " % self.hard_timeout
    outstr += "match=%s, " % self.match
    outstr += "actions=%s, " % repr(self.actions)
    outstr += "buffer_id=%s" % str(self.buffer_id)
    return outstr

  def flow_stats (self, now=None):
    if now == None: now = time.time()
    duration = now - self.counters["created"]
    return ofp_flow_stats(match=self.match,
                          duration_sec=int(duration),
                          duration_nsec=int(duration * 1e9),
                          priority=self.priority,
                          idle_timeout=self.idle_timeout,
                          hard_timeout=self.hard_timeout,
                          cookie=self.cookie,
                          packet_count=self.counters["packets"],
                          byte_count=self.counters["bytes"],
                          actions=self.actions)


class FlowTableModification (Event):
  def __init__ (self, added=[], removed=[]):
    Event.__init__(self)
    self.added = added
    self.removed = removed


class FlowTable (EventMixin):
  """
  General model of a flow table.

  Maintains an ordered list of flow entries, and finds matching entries for
  packets and other entries. Supports expiration of flows.
  """
  _eventMixin_events = set([FlowTableModification])

  def __init__ (self):
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
  def entries (self):
    return self._table

  def __len__ (self):
    return len(self._table)

  def add_entry (self, entry):
    if not isinstance(entry, TableEntry):
      raise TypeError("Not an Entry type")
    self._table.append(entry)

    # keep table sorted by descending priority, with exact matches always first
    # note: python sort is stable
    key = lambda e: e.priority if e.match.is_wildcarded else (1<<16) + 1
    self._table.sort(key=key, reverse=True)

    self.raiseEvent(FlowTableModification(added=[entry]))

  def remove_entry (self, entry):
    if not isinstance(entry, TableEntry):
      raise TypeError("Not an Entry type")
    self._table.remove(entry)
    self.raiseEvent(FlowTableModification(removed=[entry]))

  def entries_for_port (self, port_no):
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

  def matching_entries (self, match, priority=0, strict=False, out_port=None):
    entry_match = lambda e: e.is_matched_by(match, priority, strict, out_port)
    return [ entry for entry in self._table if entry_match(entry) ]

  def flow_stats (self, match, out_port=None, now=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    return ( e.flow_stats() for e in mc_es ) # CHECK: Should this be string?

  def expired_entries (self, now=None):
    return [ entry for entry in self._table if entry.is_expired(now) ]

  def _remove_specific_entries (self, remove_flows):
    #for entry in remove_flows:
    #  self._table.remove(entry)
    self._table = [entry for entry in self._table if entry not in remove_flows]
    self.raiseEvent(FlowTableModification(removed=remove_flows))

  def remove_expired_entries (self, now=None):
    remove_flows = self.expired_entries(now)
    self._remove_specific_entries(remove_flows)

  def remove_matching_entries (self, match, priority=0, strict=False):
    remove_flows = self.matching_entries(match, priority, strict)
    self._remove_specific_entries(remove_flows)

  def entry_for_packet (self, packet, in_port):
    """
    Finds the flow table entry that matches the given packet.

    Returns the highest priority flow table entry that matches the given packet
    on the given in_port, or None if no matching entry is found.
    """
    packet_match = ofp_match.from_packet(packet, in_port)

    for entry in self._table:
      if entry.match.matches_with_wildcards(packet_match,
                                            consider_other_wildcards=False):
        return entry

    return None


class SwitchFlowTable (FlowTable):
  """
  Models a flow table for our switch implementation.

  Handles the behavior in response to the OF messages send to the switch
  """

  def process_flow_mod (self, flow_mod):
    """
    Process a flow mod sent to the switch.
    """
    if flow_mod.flags & OFPFF_CHECK_OVERLAP:
      raise NotImplementedError("OFPFF_CHECK_OVERLAP checking not implemented")
    if flow_mod.out_port != OFPP_NONE and flow_mod.command == OFPFC_DELETE:
      raise NotImplementedError("flow_mod outport checking not implemented")

    command = flow_mod.command
    match = flow_mod.match
    priority = flow_mod.priority

    if command == OFPFC_ADD:
      # exactly matching entries have to be removed
      self.remove_matching_entries(match, priority=priority, strict=True)
      self.add_entry(TableEntry.from_flow_mod(flow_mod))
    elif command == OFPFC_MODIFY or command == OFPFC_MODIFY_STRICT:
      is_strict = (command == OFPFC_MODIFY_STRICT)
      modified = False
      for entry in self._table:
        # update the actions field in the matching flows
        if entry.is_matched_by(match, priority=priority, strict=is_strict):
          entry.actions = flow_mod.actions
          modified = True
      if not modified:
        # if no matching entry is found, modify acts as add
        self.add_entry(TableEntry.from_flow_mod(flow_mod))
    elif command == OFPFC_DELETE or command == OFPFC_DELETE_STRICT:
      is_strict = (command == OFPFC_DELETE_STRICT)
      self.remove_matching_entries(match, priority=priority, strict=is_strict)
    else:
      raise AttributeError("Command not yet implemented: %s" % command)
