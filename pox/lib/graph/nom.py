# Copyright 2012 James McCauley
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
"""

from pox.lib.revent import *
from pox.core import core
from pox.lib.addresses import *
from pox.lib.graph.graph import *

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

class Update (Event):
  """
  Fired by Topology whenever anything has changed
  """
  def __init__ (self, event):
    self.event = event

class Entity (Node):
  """
  Note that the Entity class is intentionally simple; It only serves as a
  convenient SuperClass type.

  It's up to subclasses to implement specific functionality (e.g.
  OpenFlow1.0 switch functionality).  The purpose of this design decision
  is to prevent protocol specific details from being leaked into this
  module... but this design decision does /not/ imply that pox.toplogy
  serves to define a generic interface to abstract entity types.
  """

class Host (Entity):
  """
  A generic Host entity.
  """
  def __init__(self):
    Entity.__init__(self)

class Switch (Entity):
  """
  Subclassed by protocol-specific switch classes,
  e.g. pox.openflow.topology.OpenFlowSwitch
  """

"""
class Port (Entity):
  def __init__ (self, num, hwAddr, name):
    Entity.__init__(self)
    self.number = num
    self.hwAddr = EthAddr(hwAddr)
    self.name = name
"""

class NOM (Graph, EventMixin):
  __eventMixin_events = [
    EntityJoin,
    EntityLeave,

    Update
  ]

  def __init__ (self):
    Graph.__init__(self)
    EventMixin.__init__(self)
    self._eventMixin_addEvents(self.__eventMixin_events)
    self._entities = {}
    self.log = core.getLogger(self.__class__.__name__)

  def getEntityByID (self, ID, fail=False):
    """
    Raises an exception if fail is True and the entity doesn't exist
    See also: The 'entity' property.
    """
    r = self.find(Or(Equal('DPID', ID),Equal(F('ID'), ID)))
    if len(r) == 0:
      if fail:
        raise RuntimeError("No entity with ID " + str(ID))
      else:
        return None
    assert len(r) == 1
    return r[0]

  def removeEntity (self, entity):
    if entity in self:
      self.remove(entity)
      self.log.info(str(entity) + " left")
      self.raiseEvent(EntityLeave, entity)

  def addEntity (self, entity):
    """ Will raise an exception if entity.id already exists """
    if entity in self:
      raise RuntimeError("Entity exists")
    self.add(entity)
    self.log.info(str(entity) + " joined")
    self.raiseEvent(EntityJoin, entity)

  def getEntitiesOfType (self, t=Entity, subtypes=True):
    if subtypes is False:
      return self.find(is_a=t)
    else:
      return self.find(type=t)

  def raiseEvent (self, event, *args, **kw):
    """
    Whenever we raise any event, we also raise an Update, so we extend
    the implementation in EventMixin.
    """
    rv = EventMixin.raiseEvent(self, event, *args, **kw)
    if type(event) is not Update:
      EventMixin.raiseEvent(self, Update(event))
    return rv

  def __str__(self):
    return "<%s len:%i>" % (self.__class__.__name__, len(self))
