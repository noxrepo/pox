# Copyright 2012 James McCauley
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
"""

from pox.lib.revent import *
from pox.core import core
from pox.lib.addresses import *
from pox.lib.graph.graph import *

class EntityEvent (Event):
  def __init__ (self, entity):
    Event.__init__(self)
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
    Event.__init__(self)
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

class HostJoin (HostEvent):
  def __init__(self, host):
    HostEvent.__init__(self, host)

class HostLeave (HostEvent):
  def __init__(self, host):
    HostEvent.__init__(self, host)

class LinkEvent (Event):
  def __init__ (self, add, link):
    Event.__init__(self)
    self.link = link
    self.added = add
    self.removed = not add

  def portForDPID (self, dpid):
    if self.link.dpid1 == dpid:
      return self.link.port1
    if self.link.dpid2 == dpid:
      return self.link.port2
    return None

class Update (Event):
  """
  Fired by Topology whenever anything has changed
  """
  def __init__ (self, event):
    Event.__init__(self)
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
  def __init__(self, macstr=None, ip=None, location=None, **kw):
    Entity.__init__(self)
    if macstr:
      self.mac = EthAddr(macstr)
      self.macstr = self.mac.toStr() # this is used as a key for topology.find()
    if ip:
      self.ip = IPAddr(ip)
    self.location = location
    '''
    This is an example of what can be added by a component that does
    os fingerprinting and replaces a generic to-be-added Host object with one
    that has this field as an extension
    '''
    #self.os =

  def setLocation(self, switch, port):
    '''
    Sets the location where the host is currently connected
    as a (switch, port) tuple
    '''
    self.location = (switch, port)

  def getLocation(self):
    '''
    Returns the location where the host is currently connected
    as a (switch, port) tuple
    '''
    return (switch, port)

  def __repr__ (self):
    return "<Host " + self.mac.toStr() + ">"

class Switch (Entity):
  """
  Subclassed by protocol-specific switch classes,
  e.g. pox.openflow.topology.OpenFlowSwitch
  """

class Port (Entity):
  def __init__ (self, num, hwAddr, name):
    Entity.__init__(self)
    self.number = num
    self.hwAddr = EthAddr(hwAddr)
    self.name = name

class Link (Entity):
  """
  A generic Link entity.
  """
  def __init__(self, node1, port1, node2, port2):
    Entity.__init__(self)
    self.node1 = node1
    self.port1 = port1
    self.node2 = node2
    self.port2 = port2

  def __repr__ (self):
    return "<Link (%s:%s <-> %s:%s)" % (self.node1 , self.port1,
                                        self.node2, self.port2)
class AccessLink (Link):
  """
  A Link connecting a host to a switch.
  """
  def __init__(self, node1, port1, hostmac):
    Entity.__init__(self)
    self.node1 = node1
    self.port1 = port1
    self.hostmac = hostmac

  def __repr__ (self):
    return "<Link (%s:%s <-> %s)" % (self.node1 , self.port1, self.hostmac)

class Controller (Entity):
  ''' Used for tracking distributed controllers '''
  def __init__(self, name, handshake_complete=False):
    Entity.__init__(self)
    self.name = name
    self.handshake_complete = handshake_complete

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
    self.log = core.getLogger(self.__class__.__name__)

  def getEntityByID (self, ID, fail=False):
    """
    Raises an exception if fail is True and the entity doesn't exist
    See also: The 'entity' property.
    """
    r = self.find(Equal(F('dpid'), ID))
    # Or is not working atm, so we only match dpids
    #r = self.find(Or(Equal(F('dpid'), ID),Equal(F('id'), ID)))
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
      self.log.info("%s left %s", str(entity))
      self.raiseEvent(EntityLeave, entity)

  def addEntity (self, entity):
    """ Will raise an exception if entity.id already exists """
    if entity in self:
      raise RuntimeError("Entity exists")
    self.add(entity)
    self.raiseEvent(EntityJoin, entity)

  def getEntitiesOfType (self, t=Entity, subtypes=True):
    if subtypes:
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
      EventMixin.raiseEvent(self, Update(event), *args, **kw)
    return rv

  def __str__(self):
    return "<%s len:%i>" % (self.__class__.__name__, len(self))

