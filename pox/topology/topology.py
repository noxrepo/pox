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

"""
The Topology module encapsulates the Network Object Model (NOM).

This is the "substrate" NOM, containing non-virtualized (read: raw OpenFlow)
entities.

NOTE: this module is passive; it won't do anything unless other modules call
methods on it. As an example, to populate it with OpenFlow switches you would 
need to invoke:
   $ ./pox.py topology openflow.discovery openflow.topology
   
   
topology is this module, which simply stores the NOM datastructure.

openflow.discovery sends out LLDP packets and discovers OpenFLow
switches in the network.

openflow.topology is an "adaptor" between OpenFlow semantics and 
topology semantics; it listens on openflow.discovery events, and pushes
(generic) changes to this module.

TODO: the above invocation is somewhat awkward and error-prone. Is there a better
way to add Openflow switches to the NOM? I suppose this module is intended to 
implement "OS"-functionality; when most applications move to using the NOM, the NOM
will automatically be populated by pox. 
"""

from pox.lib.revent.revent import *
from pox.core import core
from pox.lib.addresses import *

log = core.getLogger()

class EntityEvent (Event):
  def __init__ (self, entity):
    self.entity = entity
    
# An entity is inserted into the NOM
class EntityJoin (EntityEvent): pass
# An entity is removed from the NOM
class EntityLeave (EntityEvent): pass

class SwitchEvent (EntityEvent): pass
# As opposed to ConnectionUp, SwitchJoin occurs over large time scales 
# (e.g. an administrator physically moving a switch). 
class SwitchJoin (SwitchEvent): 
  def __init__ (self, switch):
    self.switch = switch
    
# As opposed to ConnectionDown, SwitchLeave occurs over large time scales 
# (e.g. an administrator physically moving a switch). 
class SwitchLeave (SwitchEvent): pass

class HostEvent (EntityEvent): pass
class HostJoin (HostEvent): pass
class HostLeave (HostEvent): pass

class Entity (object):
  """ 
  Note that the Entity class is intentionally simple; It only serves as a 
  convenient SuperClass type.
  
  It's up to subclasses to implement specific functionality (e.g. OpenFlow1.0 
  switch functionality). This is possible since Python is a dynamic language... 
  the purpose of this design decision is to prevent protocol specific details
  from being leaked into this module... But this design decision does /not/
  imply that pox.toplogy serves to define a generic interface to abstract
  entity types.
  """
  # Globally unique id for this entity
  ID = 0
  
  def __init__ (self):
    Entity.ID += 1
    self.id = Entity.ID

class Host (Entity):
  def __init__(self):
    Entity.__init__(self)

class Switch (Entity):
  """
  Subclassed by protocol-specific switch classes,
  e.g. pox.openflow.topology.OpenFlowSwitch
  """
  def __init__(self, id):
    # Switch takes a dpid instead of calling super constructor
    self.id = id

class Port (Entity):
  def __init__ (self, num, hwAddr, name):
    Entity.__init__(self)
    self.number = num
    self.hwAddr = EthAddr(hwAddr)
    self.name = name

class Topology (EventMixin):
  # Hmm, it's not clear that we want these events. An alternative would be to have 
  # all applications interested in using the NOM to define a method `nom_update()`, which
  # feeds in updated NOMs. We then call that single interface when any of the events below
  # occur. Makes it a little easier for the application programmer, I would argue. Haven't
  # thought about it too deeply though... This definitely gives the programmer more 
  # fine-grained control over the events they see.
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
    
    # If a client registers a handler for these events after they have already
    # occurred, we promise to re-issue them to the newly joined client.
    self._event_promises = {
      SwitchJoin : self._fulfill_SwitchJoin_promise
    }

  def getEntityByID (self, ID, fail=False):
    """ Raises an exception if fail is True and the entity is not in the NOM """    
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
    """ Will raise an exception if entity.id is already in the NOM """
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

  def getSwitchWithConnection (self, connection):
    """
    OpenFlow events only contain a refence to a connection object, not a
    switch object. Perhaps this should be changed, but for now, find the
    switch the corresponding connection object.
    
    Return None if no such switch found.
    """
    self.getEntitiesOfType(Switch).find(lambda switch: switch.connection == connection)
    
  def addListener(self, eventType, handler, once=False, weak=False, priority=None, byName=False):
    """
    We interpose on EventMixin.addListener to check if the eventType is
    in our promise list. If so, trigger the handler for all previously
    triggered events.
    """
    if eventType in self._event_promises:
      self._event_promises[eventType](handler)
    
    return EventMixin.addListener(self, eventType, handler, once=once, weak=weak, priority=priority, byName=byName)
  
  def _fulfill_SwitchJoin_promise(self, handler):
    """ Trigger the SwitchJoin handler for all pre-existing switches """
    for switch in self.getEntitiesOfType(Switch, True):
      handler(switch)
    
  def __str__(self):
    # TODO: display me graphically
    strings = []
    strings.append("topology (%d total entities)" % len(self.entities))
    for id,entity in self.entities:
      strings.append("%s %s" % (str(id), str(entity))) 
      
    return strings
    