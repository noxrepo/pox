from pox.lib.revent.revent import *
from pox.core import core

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

  def __init__ (self):
    EventMixin.__init__(self)
    self.entities = {}

  def getEntityByID (self, ID):
    return self.entities[ID]

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



