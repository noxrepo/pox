# Copyright 2011 James McCauley
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
The Topology module is the root of an object model composed of entities
like switches, hosts, links, etc.  This object model is populated by other
modules.  For example, openflow.topology populates the topology object
with OpenFlow switches.

Note that this means that you often want to invoke something like:
   $ ./pox.py topology openflow.discovery openflow.topology
"""

from pox.lib.revent import *
from pox.core import core
from pox.lib.addresses import *
import traceback

import pickle


class EntityEvent (Event):
  def __init__ (self, entity):
    self.entity = entity

class EntityJoin (EntityEvent):
  """
  An entity has been added.

  Note that if there is a more specific join event defined for a particular
  entity, (e.g., SwitchJoin), this event will not be fired.

  TODO: or we could always raise EntityJoins along with SwitchJoins, which
  seems more intuitive to me.
  """
  pass

class EntityLeave (EntityEvent):
  """
  An entity has been removed

  Note that if there is a more specific leave event defined for a particular
  entity, (e.g., SwitchLeave), this event will not be fired.

  TODO: or we could always raise EntityLeaves along with SwitchLeaves, which
  seems more intuitive to me.
  """
  pass

class SwitchEvent (EntityEvent): pass

class SwitchJoin (SwitchEvent):
  """
  As opposed to ConnectionUp, SwitchJoin occurs over large time scales
  (e.g. an administrator physically moving a switch).
  """
  def __init__ (self, switch):
    SwitchEvent.__init__(self, switch)
    self.switch = switch

class SwitchLeave (SwitchEvent):
  """
  As opposed to ConnectionDown, SwitchLeave occurs over large time scales
  (e.g. an administrator physically moving a switch).
  """
  pass

class SwitchConnectionUp(SwitchEvent):
  def __init__(self, switch, connection):
    SwitchEvent.__init__(self, switch)
    self.switch = switch
    self.connection = connection

class SwitchConnectionDown(SwitchEvent): pass

class HostEvent (EntityEvent): pass
class HostJoin (HostEvent): pass
class HostLeave (HostEvent): pass

class Update (Event):
  """
  Fired by Topology whenever anything has changed
  """
  def __init__ (self, event=None):
    self.event = event

class Entity (object):
  """
  Note that the Entity class is intentionally simple; It only serves as a
  convenient SuperClass type.

  It's up to subclasses to implement specific functionality (e.g.
  OpenFlow1.0 switch functionality).  The purpose of this design decision
  is to prevent protocol specific details from being leaked into this
  module... but this design decision does /not/ imply that pox.toplogy
  serves to define a generic interface to abstract entity types.

  NOTE: /all/ subclasses must call this superconstructor, since
        the unique self.id is field is used by Topology
  """
  # This is a counter used so that we can get unique IDs for entities.
  # Some entities don't need this because they have more meaningful
  # identifiers.
  _next_id = 101
  _all_ids = set()
  _tb = {}

  def __init__ (self, id=None):
    if id:
      if id in Entity._all_ids:
        print(("".join(traceback.format_list(self._tb[id]))))
        raise Exception("ID %s already taken" % str(id))
    else:
      while Entity._next_id in Entity._all_ids:
        Entity._next_id += 1
      id = Entity._next_id

    self._tb[id] = traceback.extract_stack()
    Entity._all_ids.add(id)
    self.id = id

  def serialize(self):
    return pickle.dumps(self, protocol = 0)

  @classmethod
  def deserialize(cls):
    return pickle.loads(cls, protocol = 0)

class Host (Entity):
  """
  A generic Host entity.
  """
  def __init__(self,id=None):
    Entity.__init__(self, id)

class Switch (Entity):
  """
  Subclassed by protocol-specific switch classes,
  e.g. pox.openflow.topology.OpenFlowSwitch
  """
  def __init__(self, id=None):
    # Switches often have something more meaningful to use as an ID
    # (e.g., a DPID or MAC address), so they take it as a parameter.
    Entity.__init__(self, id)

class Port (Entity):
  def __init__ (self, num, hwAddr, name):
    Entity.__init__(self)
    self.number = num
    self.hwAddr = EthAddr(hwAddr)
    self.name = name

class Controller (Entity):
  def __init__(self, name, handshake_complete=False):
    self.id = name
    # TODO: python aliases?
    self.name = name
    self.handshake_complete = handshake_complete

  def handshake_completed(self):
    self.handshake_complete = True

class Topology (EventMixin):
  _eventMixin_events = [
    SwitchJoin,
    SwitchLeave,
    HostJoin,
    HostLeave,
    EntityJoin,
    EntityLeave,

    Update
  ]

  _core_name = "topology" # We want to be core.topology

  def __init__ (self, name="topology"):
    EventMixin.__init__(self)
    self._entities = {}
    self.name = name
    self.log = core.getLogger(name)

    # If a client registers a handler for these events after they have
    # already occurred, we promise to re-issue them to the newly joined
    # client.
    self._event_promises = {
      SwitchJoin : self._fulfill_SwitchJoin_promise
    }

  def getEntityByID (self, ID, fail=False):
    """
    Raises an exception if fail is True and the entity doesn't exist
    See also: The 'entity' property.
    """
    if fail:
      return self._entities[ID]
    else:
      return self._entities.get(ID, None)

  def removeEntity (self, entity):
    del self._entities[entity.id]
    self.log.info(str(entity) + " left")
    if isinstance(entity, Switch):
      self.raiseEvent(SwitchLeave, entity)
    elif isinstance(entity, Host):
      self.raiseEvent(HostLeave, entity)
    else:
      self.raiseEvent(EntityLeave, entity)

  def addEntity (self, entity):
    """ Will raise an exception if entity.id already exists """
    if entity.id in self._entities:
      raise RuntimeError("Entity exists")
    self._entities[entity.id] = entity
    self.log.debug(str(entity) + " (id: " + str(entity.id) + ") joined")
    if isinstance(entity, Switch):
      self.raiseEvent(SwitchJoin, entity)
    elif isinstance(entity, Host):
      self.raiseEvent(HostJoin, entity)
    else:
      self.raiseEvent(EntityJoin, entity)

  def getEntitiesOfType (self, t=Entity, subtypes=True):
    if subtypes is False:
      return [x for x in self._entities.values() if type(x) is t]
    else:
      return [x for x in self._entities.values() if isinstance(x, t)]

  def addListener(self, eventType, handler, once=False, weak=False,
                  priority=None, byName=False):
    """
    We interpose on EventMixin.addListener to check if the eventType is
    in our promise list. If so, trigger the handler for all previously
    triggered events.
    """
    if eventType in self._event_promises:
      self._event_promises[eventType](handler)

    return EventMixin.addListener(self, eventType, handler, once=once,
                                  weak=weak, priority=priority,
                                  byName=byName)

  def raiseEvent (self, event, *args, **kw):
    """
    Whenever we raise any event, we also raise an Update, so we extend
    the implementation in EventMixin.
    """
    rv = EventMixin.raiseEvent(self, event, *args, **kw)
    if type(event) is not Update:
      EventMixin.raiseEvent(self, Update(event))
    return rv

  def serialize (self):
    """
    Picklize our current entities.

    Returns a hash: { id -> pickled entitiy }
    """
    id2entity = {}
    for id in self._entities:
      entity = self._entities[id]
      id2entity[id] = entity.serialize()
    return id2entity

  def deserializeAndMerge (self, id2entity):
    """
    Given the output of topology.serialize(), deserialize each entity, and:
      - insert a new Entry if it didn't already exist here, or
      - update a pre-existing entry if it already existed
    """
    for entity_id in id2entity.keys():
      pickled_entity = id2entity[entity_id].encode('ascii', 'ignore')
      entity = pickle.loads(pickled_entity)
      entity.id = entity_id.encode('ascii', 'ignore')
      try:
        # Try to parse it as an int
        entity.id = int(entity.id)
      except ValueError:
        pass

      existing_entity = self.getEntityByID(entity.id)
      if existing_entity:
        self.log.debug("New metadata for %s: %s " % (str(existing_entity), str(entity)))
        # TODO: define an Entity.merge method (need to do something about his update!)
      else:
        self.addEntity(entity)

  def _fulfill_SwitchJoin_promise(self, handler):
    """ Trigger the SwitchJoin handler for all pre-existing switches """
    for switch in self.getEntitiesOfType(Switch, True):
      handler(SwitchJoin(switch))

  def __len__(self):
    return len(self._entities)

  def __str__(self):
    # TODO: display me graphically
    strings = []
    strings.append("topology (%d total entities)" % len(self._entities))
    for id,entity in self._entities.items():
      strings.append("%s %s" % (str(id), str(entity)))

    return '\n'.join(strings)
