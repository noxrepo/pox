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

from pox.lib.revent.revent import *
from pox.core import core
from pox.lib.addresses import *

log = core.getLogger()

class EntityEvent (Event):
  def __init__ (self, entity):
    self.entity = entity

class SwitchEvent (EntityEvent): pass
class SwitchJoin (SwitchEvent): pass
class SwitchLeave (SwitchEvent): pass

class HostEvent (EntityEvent): pass
class HostJoin (HostEvent): pass
class HostLeave (HostEvent): pass

class EntityJoin (EntityEvent): pass
class EntityLeave (EntityEvent): pass

class Entity (object):
  def __init__ (self, id):
    self.id = id

class Host (Entity):
  pass

class Switch (Entity):
  pass

class Port (Entity):
  def __init__ (self, num, hwAddr, name):
    self.number = num
    self.hwAddr = EthAddr(hwAddr)
    self.name = name

class Topology (EventMixin):
  _eventMixin_events = [
    SwitchJoin,
    SwitchLeave,
    HostJoin,
    HostLeave,
    EntityJoin,
    EntityLeave,
  ]

  _core_name = "topology" # We want to be core.topology

  def __init__ (self):
    EventMixin.__init__(self)
    self.entities = {}

  def getEntityByID (self, ID, fail=False):
    if fail:
      return self.entities[ID]
    else:
      return self.entities.get(ID, None)

  def removeEntity (self, entity):
    del self.entities[entity.id]
    log.info(str(entity) + " left")
    if isinstance(entity, Switch):
      self.raiseEvent(SwitchLeave, entity)
    elif isinstance(entity, Host):
      self.raiseEvent(HostLeave, entity)
    else:
      self.raiseEvent(EntityLeave, entity)

  def addEntity (self, entity):
    assert entity.id not in self.entities
    self.entities[entity.id] = entity
    log.info(str(entity) + " joined")
    if isinstance(entity, Switch):
      self.raiseEvent(SwitchJoin, entity)
    elif isinstance(entity, Host):
      self.raiseEvent(HostJoin, entity)
    else:
      self.raiseEvent(EntityJoin, entity)

  def getEntitiesOfType (self, t=Entity, subtypes=True):
    if subtypes is False:
      return (x for x in self.entities.itervalues() if type(x) is t)
    else:
      return (x for x in self.entities.itervalues() if isinstance(x, t))



