# Copyright 2011 James McCauley
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

#import networkx as nx
import pox.lib.graph.minigraph as nx
try:
  from weakref import WeakSet
except:
  # python 2.6 compatibility
  from weakrefset import WeakSet
from collections import defaultdict
from copy import copy

LINK = 'link'

class Link (object):

  def reorder (self, l):
    """
    Flips a list of Links so that this node is first in each
    """
    return Link.order(l, self)

  @staticmethod
  def order (links, n):
    """
    Give a list of Links that each contain node n, flips any links so
    that n is always the first element of the link.
    """
    r = []
    for l in links:
      assert n in l
      if l._n[0] == n:
        r.append(l)
      else:
        r.append(l.flip())
    return r

  def __init__ (self, np1, np2):
    self._n = [np1[0],np2[0]]
    self._p = [np1[1],np2[1]]

  def _index (self, i):
    if i in self._n:
      i = self._n.index(i)
    assert i == 0 or i == 1
    return i

  def flip (self):
    """
    Returns the same link, but flipped (a,b) becomes (b,a)
    """
    return Link(self[1], self[0])

  def port (self, n):
    return self._p[_index(n)]

  def other_port (self, n):
    """
    Returns the other end's port.
    See other().
    """
    return self.other(n)[1]

  def other (self, n):
    """
    Returns the other end of a link.
    Given a node or (node,port) that is part of this link, it returns
    the opposite end's (node,port).
    """
    if type(n) is tuple:
      if self[0] == n:
        return self[1]
      assert self[1] == n
      return self[0]

    if self[0][0] == n:
      return self[1]
    assert self[1][0] == n
    return self[0]

  def __contains__ (self, n):
    """
    Does this link contain (node,port) or node?
    """
    if type(n) is tuple:
      return n in [self[0], self[1]]
    else:
      return n in [self._n]

  def __len__ (self):
    return 2

  def __getitem__ (self, i):
    """
    Gets (node,port) based on index
    """
    i = self._index(i)
    return (self._n[i], self._p[i])

  def __repr__ (self):
    return "Link(%s, %s)" % (self[0], self[1])

def _void ():
  return None

class Node (object):
  _next_num = 1

  def __init__ (self):
    self._num = self.__class__._next_num
    self.__class__._next_num += 1

  @property
  def _g (self):
    #TODO: Remove this
    return self._parent_graph

  @property
  def neighbors (self):
    return self._g.neighbors(self)

  @property
  def ports (self):
    """
    Map of local_port -> (other, other_port)
    """
    ports = defaultdict(_void)
    for n1,n2,k,d in self._g._g.edges(data=True, keys=True):
      p = d[LINK]
      assert n1 is self
      assert ports.get(p[self]) is None
      ports[p[self][1]] = p.other(self)
    return ports

  def disconnect_port (self, num):
    self._g.disconnect_port((self,num))

  def disconnect_all (self):
    for n in self.neighbors:
      self.disconnect_node(n)

  def disconnect_node (self, n):
    """
    n can be a node or a (node,port)
    Returns number of nodes disconnected
    """
    if isinstance(n, Node):
      c = 0
      for k,v in self.ports.iteritems():
        if v[0] == n:
          self.disconnect_port(k)
          c += 1
      return c
    else:
      for k,v in self.ports.iteritems():
        if v[0] == n[0]:
          if v[1] == n[1]:
            self.disconnect_port(k)
            return 1
      return 0

  def find_ports (self, n, pairs=False):
    """
    Gets the list of ports connected to a node.
    n can be the other node or a (node,port)
    if pairs is True, returns (self_port,other_port).
    otherwise, just returns the port on this side.
    """
    np = None
    if type(n) is tuple:
      np = n
      n = n[0]

    r = []
    for k,v in self.ports.iteritems():
      if v[0] is n:
        if np is None or np == v:
          if pairs:
            r.append((k,v[1]))
          else:
            r.append(k)
    return r

  def connected_to (self, n):
    return len(self.find_ports(n)) > 0

  def find_port (self, n, pairs=False, error=True):
    p = self.find_ports(n, pairs)
    if len(p) == 0:
      if error:
        raise RuntimeError("%s is not connected to %s" % (self, n))
      return None
    return p[0]


  def __repr__ (self):
    return "#" + str(self._num)


class LeaveException (RuntimeError):
  pass



class Operator (object):
  def __repr__ (self):
    return "<%s>" % (self.__class__.__name__)

class Literal (Operator):
  def __init__ (self, v):
    self._v = v
  def __call__ (self, n, li=None):
    return self._v
  def __repr__ (self):
    return repr(self._v)

class Anything (Operator):
  def __call__ (self, n, li):
    return True

  def __repr__ (self):
    return "Anything"

class Self (Operator):
  def __call__ (self, n, li=None):
    return n
  def __repr__ (self):
    return "Self"

class Port (Operator):
  def __call__ (self, n, li):
    if li is None:
      raise RuntimeError("You can only use Port for link queries")
    return li[0][1]

  def __repr__ (self):
    return "Port"

class OtherPort (Operator):
  def __call__ (self, n, li):
    if li is None:
      raise RuntimeError("You can only use OtherPort for link queries")
    return li[1][1]

  def __repr__ (self):
    return "OtherPort"

class Other (Operator):
  def __call__ (self, n, li):
    if li is None:
      raise RuntimeError("You can only use Other for link queries")
    return li[1][0]

  def __repr__ (self):
    return "Other"

class Call (Operator):
  def __init__ (_self, *arg, **kw):
    _self._arg = []
    for v in arg:
      ao = None
      if isinstance(v, Operator):
        ao = v
      else:
        ao = Literal(v)
      _self._arg.append(ao)
    _self._kw = {}
    for k,v in kw.iteritems():
      ao = None
      if isinstance(v, Operator):
        ao = v
      else:
        ao = Literal(v)
      _self._kw[k].append(ao)

  def __call__ (self, n, li):
    arglist = []
    for arg in self._arg:
      arglist.append(arg(n,li))
    kws = {}
    for k,v in self._kw.iteritems():
      kws[k] = v(n)
    func = arglist.pop(0)
    return func(*arglist, **kws)

  def __repr__ (self):
    r = str(self._arg[0])
    args = [str(s) for s in self._arg[1:]]
    args.append(["%s=%s" % (k,str(v)) for k,v in self._kw])
    return "%s(%s)" % (self._arg[0], ', '.join(args))

class UnaryOp (Operator):
  def __init__ (self, operand):
    if isinstance(operand, Operator):
      self._operand = operand
    else:
      self._operand = Literal(operand)

  def __call__ (self, n, li):
    a = self._operand(n, li)
    return self._apply(a)

  def _apply (self, attr):
    raise RuntimeError("Unimplemented")

# TODO: There is a bug here
# Probably BinaryOp and NodeOp need to become aware of LeaveException
class BinaryOp (Operator): 
  def __init__ (self, left, right):
    if isinstance(left, Operator):
      self._left = left 
    else:
      self._left = Literal(left)
    if isinstance(right, Operator):
      self._right = right
    else:
      self._right = Literal(right)

  def __call__ (self, n, li):
    l = self._left(n, li)
    r = self._right(n, li)
    return self._apply(l, r)

  def _apply (self, l, r):
    raise RuntimeError("Unimplemented")

  def __repr__ (self):
    if hasattr(self, '_symbol'):
      return "%s %s %s" % (self._left, self._symbol, self._right)
    else:
      return "%s(%s, %s)" % (self.__class__.__name__, self._left, self._right)

class Or (BinaryOp): 
  _symbol = "or"
  def _apply (self, l, r):
    return l or r

class And (BinaryOp):
  _symbol = "and"
  def _apply (self, l, r):
    return l and r

"""
class Equal (BinaryOp):
  _symbol = "=="
  def _apply (self, l, r):
    return l == r

class Is (BinaryOp):
  _symbol = "is"
  def _apply (self, l, r):
    return l is r
"""

class LessThan (BinaryOp):
  _symbol = "<"
  def _apply (self, value):
    return value < self._value

class GreaterThan (BinaryOp):
  _symbol = ">"
  def _apply (self, l, r):
    return value > self._value

class LessThanEqualTo (BinaryOp):
  _symbol = "<="
  def _apply (self, l, r):
    return value <= self._value

class GreaterThanEqualTo (BinaryOp):
  _symbol = "=>"
  def _apply (self, l, r):
    return value > self._value

class Not (UnaryOp):
  def _apply (self, v):
    return not v

  def __repr__ (self):
    return "(Not %s)" % (self._operand,)

class Length (UnaryOp):
  def _apply (self, v):
    return len(v)

  def __repr__ (self):
    return "len(%s)" % (self._operand,)

class Index (BinaryOp):
  def _apply (self, l, r):
    return l[r]

  def __repr__ (self):
    return "%s[%s]" % (self._left, self._right)

# TODO: There is a bug here
# Probably BinaryOp and NodeOp need to become aware of LeaveException
_dummy = object()
class NodeOp (Operator):
  """
  Can be a binary operator, or if only one argument supplied, the
  left one defaults to the node.
  """
  def __init__ (self, left, right=_dummy):
    if right is _dummy:
      right = left
      left = Self()

    if isinstance(left, Operator):
      self._left = left 
    else:
      self._left = Literal(left)
    if isinstance(right, Operator):
      self._right = right
    else:
      self._right = Literal(right)

  def __call__ (self, n, li):
    l = self._left(n, li)
    r = self._right(n, li)
    return self._apply(l, r)

  def _apply (self, l, r):
    raise RuntimeError("Unimplemented")

  def __repr__ (self):
    if hasattr(self, '_symbol'):
      return "%s %s %s" % (self._left, self._symbol, self._right)
    else:
      return "%s(%s, %s)" % (self.__class__.__name__, self._left, self._right)

class Equal (NodeOp):
  _symbol = "=="
  def _apply (self, l, r):
    #print "???", repr(l), repr(r), l == r
    return l == r

class Is (NodeOp):
  _symbol = "is"
  def _apply (self, l, r):
    return l is r

class Field (NodeOp):
  def __init__ (self, left, right=_dummy, optional=True):
    NodeOp.__init__(self, left, right)
    self._optional = optional

  def _apply (self, l, r):
    #print ">>",self._attr_name,hasattr(n, self._attr_name)
    do_call = r.endswith("()")
    if do_call: r = r[:-2]
    if not hasattr(l, r) and self._optional:
      raise LeaveException
    a = getattr(l, r)
    if do_call: a = a()
    #print ">>>",a
    return a
F = Field # Short alias

class IsInstance (NodeOp):
  def _apply (self, l, r):
    return isinstance(l, r)
  def __repr__ (self):
    return "isinstance(%s, %s)" % (self._left, self._right)

class IsType (NodeOp):
  def _apply (self, l, r):
    if isinstance(r, str):
      return type(l).__name__ == r
    return type(l) is r
  def __repr__ (self):
    return "type(%s) == %s" % (self._left, self._right)

class ConnectedTo (NodeOp):
  def _apply (self, l, r):
    return l.connected_to(r)
  def __repr__ (self):
    return "%s.connected_to(%s)" % (self._left, self._right)

class InValues (BinaryOp):
  def __init__ (self, left, right):
    super(Member, self).__init__(left, right)
    self._optional = optional

  def _apply (self, l, r):
    return l in r.values()

class In (BinaryOp):
  def _apply (self, l, r):
    return l in r

class Member (BinaryOp):
  _symbol = "."
  def __init__ (self, left, right, optional = True):
    super(Member, self).__init__(left, right)
    self._optional = optional

  def _apply (self, l, r):
    if not hasattr(l, r) and self._optional:
      raise LeaveException
    return getattr(l, r)


class Graph (object):
  def __init__ (self):
    self._g = nx.MultiGraph()

  def __contains__ (self, n):
    return n in self._g.nodes() or n in self._g.edges()

  def add (self, node):
    assert not hasattr(node, '_parent_graph') or node._parent_graph in [None, self]
    self._g.add_node(node)
    node._parent_graph = self

  def remove (self, node):
    self._g.remove_node(node)

  def neighbors (self, n):
    return nx.MultiGraph.neighbors(self._g, n)

  def find_ports (self, n1, *arg, **kw):
    return n1.find_ports(*arg, **kw)

  def find_port (self, n1, *arg, **kw):
    return n1.find_port(*arg, **kw)

  def disconnect_port (self, np):
    """
    Disconnects the given (node,port)
    """
    assert type(np) is tuple
    remove = []
    for n1,n2,k,d in self._g.edges(np[0], data=True, keys=True):
      if np in d[LINK]:
        remove.append((n1,n2,k))
    for e in remove:
      #print "remove",e
      self._g.remove_edge(*e)
    return len(remove)

  def unlink (self, np1, np2):
    try:
      n1 = np1[0]
      p1 = np1[1]
    except:
      n1 = np1
      p1 = None
    try:
      n2 = np2[0]
      p2 = np2[1]
    except:
      n2 = np2
      p2 = None

    count = 0
    assert n1._g is self
    ports = n1.find_ports(n2, pairs=True)
    for p in ports:
      if p1 is not None:
        if p1 != p[0]: continue
      if p2 is not None:
        if p2 != p[1]: continue
      count += self.disconnect_port((n1,p[0]))
      #TODO: Can optimize for exact removal?
    return count

  def link (self, np1, np2, allow_multiple=False):
    """
    Links two nodes on given ports
    np1 is (node1, port1)
    np2 is (node2, port2)
    if allow_multiple, you can connect multiple to same port
    """
    #FIXME: the portless variation doesn't really make sense with
    #       allow_multiples yet.
    try:
      _ = np1[0]
    except:
      # portless (hacky)
      for free in xrange(1000):
        if free not in np1.ports:
          np1 = (np1,free)
          break
    try:
      _ = np2[0]
    except:
      # portless (hacky)
      for free in xrange(1000):
        if free not in np2.ports:
          np2 = (np2,free)
          break
    self._g.add_node(np1[0])
    self._g.add_node(np2[0])
    if not allow_multiple:
      self.disconnect_port(np1)
      self.disconnect_port(np2)
    self._g.add_edge(np1[0],np2[0],link=Link(np1,np2))

  def find_links (self, query1=None, query2=()):
    # No idea if new link query stuff works.

    if query2 is None: query2 = query1
    if query1 == (): query1 = None
    if query2 == (): query2 = None

    o = set()
    for n1,n2,k,d in self._g.edges(data=True, keys=True):
      l = d[LINK]
      ok = False
      if query1 is None or self._test_node(l[0][0], args=(query1,), link=l):
#        print "pass",l[0],query1
        if query2 is None or self._test_node(l[1][0], args=(query2,), link=l):
#          print "pass",l[1],query2
          ok = True
      if not ok and (query1 != query2):
        if query2 is None or self._test_node(l[0][0], args=(query2,), link=l):
#          print "pass",l[0],query2
          if query1 is None or self._test_node(l[1][0], args=(query1,), link=l):
#            print "pass",l[1],query1
            ok = True
            l = l.flip()
      if ok:
        o.add(l)
    return list(o)

  def get_one_link (self, query1=None, query2=(), **kw):
    return self.get_link(query1, query2, one=True, **kw)

  def get_link (self, query1=None, query2=(), **kw):
    """
    Keyword argument "default" lets you set a default value if
    no node is found.  Note that this means you must use
    Equal(F("default"), <value>) to actually check a field called
    "default" on a node.
    """
    if 'default' in kw:
      has_default = True
      default = kw['default']
      del kw['default']
    else:
      has_default = False
    one = False
    if 'one' in kw:
      del kw['one']
      one = True
    assert len(kw) == 0
    r = self.find_links(query1, query2)
    if len(r) > 1 and one is True:
      raise RuntimeError("More than one match")
    elif len(r) == 0:
      if has_default:
        return default
      raise RuntimeError("Could not get element")
    return r[0]

  def has_link (self, query1=None, query2=()):
    # Really bad implementation.  We can easily scape early.
    return len(self.find_links(query1, query2)) > 0

  def _test_node (self, n, args=(), kw={}, debug=False, link=None):
    #TODO: Should use a special value for unspecified n2
    for k,v in kw.iteritems():
      if k == "is_a":
        if not isinstance(n,v): return
      elif k == "type":
        if type(n) is not v: return
      else:
        if not hasattr(n, k): return
        if getattr(n, k) != v: return
    for a in args:
      if debug: print ">>",a,
      try:
        if not a(n, link):
          if debug: print " -> ",False
          return
      except LeaveException:
        if debug: print " ...  Skip"
        return
      if debug: print " -> ",True
    return True

  def find (self, *args, **kw):
    debug = False#True
    r = []
    def test (n):
      return self._test_node(n, args, kw, debug)
    """
    def test (n):
      for k,v in kw:
        if k == "is_a":
          if not isinstance(n,v): return
        elif k == "type":
          if type(n) is not kind: return
        else:
          if not hasattr(n, k): return
          if getattr(n, k) != v: return
      for a in args:
        if debug: print ">>",a,
        try:
          if not a(n):
            if debug: print " -> ",False
            return
        except LeaveException:
          if debug: print " ...  Skip"
          return
        if debug: print " -> ",True
      return True
    """

    for n in self._g.nodes():
      if debug: print ">", n
      if test(n):
        if debug: print ">> YES"
        r.append(n)
      else:
        if debug: print ">> NO"
    return r

  def get_one (self, *args, **kw):
    kw['one'] = True
    return self.get(*args, **kw)

  def get (self, *args, **kw):
    """
    Keyword argument "default" lets you set a default value if
    no node is found.  Note that this means you must use
    Equal(F("default"), <value>) to actually check a field called
    "default" on a node.
    """
    if 'default' in kw:
      has_default = True
      default = kw['default']
      del kw['default']
    else:
      has_default = False
    one = False
    if 'one' in kw:
      del kw['one']
      one = True
    r = self.find(*args,**kw)
    if len(r) > 1 and one is True:
      raise RuntimeError("More than one match")
    elif len(r) == 0:
      if has_default:
        return default
      raise RuntimeError("Could not get element")
    return r[0]

  def has (self, *args, **kw):
    # Really bad implementation.  We can easily scape early.
    return len(self.find(*args,**kw)) > 0

  def __len__ (self):
    return len(self._g)



if __name__ == "__main__":
  n1 = Node();n1.label=1
  n2 = Node();n2.label=2
  n3 = Node();n3.label=3

  g.add(n1)
  g.add(n2)
  g.add(n3)
  g.link((n1,0),(n2,0))
  g.link((n1,1),(n3,0))

  print g.find_links()

  import code
  code.interact(local=locals())
 
