# Copyright 2011 James McCauley
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

#import networkx as nx
import pox.lib.graph.minigraph as nx
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


class Node (object):
  pass
  #TODO: Add back in some convenience methods that call real methods
  #      on the parent graph?  Or just remove?


def _void ():
  return None

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
    for k,v in kw.items():
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
    for k,v in self._kw.items():
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
    self.node_port = {}

  def __contains__ (self, n):
    return n in self._g

  def add (self, node):
    self._g.add_node(node)
    self.node_port[node] = {}

  def remove (self, node):
    self._g.remove_node(node)

  def neighbors (self, n):
    return self._g.neighbors(n)

  def find_port (self, node1, node2):
    for n1, n2, k, d in self._g.edges([node1, node2], data=True, keys=True):
      return (d[LINK][node1][1], d[LINK][node2][1])
    return None

  def connected(self, node1, node2):
    return (self.find_port(node1, node2) != None)

  def disconnect_port (self, np):
    """
    Disconnects the given (node,port)
    """
    assert type(np) is tuple
    remove = []
    if self.port_for_node(np[0], np[1]) is None:
      return 0
    for n1,n2,k,d in self._g.edges([np[0], self.node_port[np[0]][np[1]][0]], data=True, keys=True):
      if np in d[LINK]:
        remove.append((n1,n2,k))
        del self.node_port[n1][d[LINK][n1][1]]
        del self.node_port[n2][d[LINK][n2][1]]
    for e in remove:
      #print "remove",e
      self._g.remove_edge(*e)
    return len(remove)

  def unlink (self, np1, np2):
    count = 0
    if isinstance(np1, tuple):
      count = disconnect_port(np1)
    elif isinstance(np2, tuple):
      count = disconnect_port(np2)
    else:
      for n1, n2, k, d in self._g.edges([np1, np2], data=True, keys=True):
        self._g.remove_edge(n1,n2,k)
        del self.node_port[n1][d[LINK][n1][1]]
        del self.node_port[n2][d[LINK][n2][1]]
        count = count + 1
    return count

  def link (self, np1, np2):
    """
    Links two nodes on given ports
    np1 is (node1, port1)
    np2 is (node2, port2)
    """
    #FIXME: the portless variation doesn't really make sense with
    #       allow_multiples yet.
    try:
      _ = np1[0]
    except:
      # portless (hacky)
      for free in range(1000):
        if free not in np1.ports:
          np1 = (np1,free)
          break
    try:
      _ = np2[0]
    except:
      # portless (hacky)
      for free in range(1000):
        if free not in np2.ports:
          np2 = (np2,free)
          break
    self._g.add_node(np1[0])
    self._g.add_node(np2[0])
    self.disconnect_port(np1)
    self.disconnect_port(np2)
    self._g.add_edge(np1[0],np2[0],link=Link(np1,np2))
    self.node_port[np1[0]][np1[1]] = np2
    self.node_port[np2[0]][np2[1]] = np1

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
        if query2 is None or self._test_node(l[1][0], args=(query2,), link=l):
          ok = True
      if not ok and (query1 != query2):
        if query2 is None or self._test_node(l[0][0], args=(query2,), link=l):
          if query1 is None or self._test_node(l[1][0], args=(query1,), link=l):
            ok = True
            l = l.flip()
      if ok:
        o.add(l)
    return list(o)

  def ports_for_node (self, node):
    """
    Map of local port -> (other, other_port)
    """
    ports = defaultdict(_void)
    for n1, n2, k, d in self._g.edges([node], data=True, keys=True):
      p = d[LINK]
      assert n1 is node
      assert ports.get(p[node]) is None
      ports[p[node][1]] = p.other(node)
    return ports

  def port_for_node(self, node, port):
    assert node in self.node_port
    return self.node_port[node].get(port)

  def disconnect_nodes(self, node1, node2):
    """ Disconnect node1 from node2. Either of node1 or node2
      can be a node, or a (node, port) pair
      Returns number of nodes disconnected
    """
    self.unlink(node1, node2)

  def disconnect_node(self, node1):
    """ Disconnecte node from all neighbours """
    for neighbor in self.neighbors(node1):
      self.disconnect_nodes(node1, neighbor)

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
      one = kw['one']
      del kw['one']
    assert len(kw) == 0
    r = self.find_links(query1, query2)
    if len(r) > 1 and one:
      raise RuntimeError("More than one match")
    elif len(r) == 0:
      if has_default:
        return default
      raise RuntimeError("Could not get element")
    return r[0]

  def has_link (self, query1=None, query2=()):
    # Really bad implementation.  We can easily scape early.
    return len(self.find_links(query1, query2)) > 0

  def _test_node (self, n, args=(), kw={}, link=None):
    #TODO: Should use a special value for unspecified n2
    for k,v in kw.items():
      if k == "is_a":
        if not isinstance(n,v): return False
      elif k == "type":
        if type(n) is not v: return False
      else:
        if not hasattr(n, k): return False
        if getattr(n, k) != v: return False
    for a in args:
      try:
        if not a(n, link):
          return False
      except LeaveException:
        return False
    return True

  def find (self, *args, **kw):
    r = []
    def test (n):
      return self._test_node(n, args, kw)
    for n in self._g.nodes():
      if test(n):
        r.append(n)
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
    if len(r) > 1 and one:
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

def test():
  class Node1 (object):
    _next_num = 0
    def __init__ (self):
      self._num = self.__class__._next_num
      self.__class__._next_num += 1

    def __repr__ (self):
      return "Node1 #" + str(self._num)

  class Node2 (object):
    _next_num = 0
    def __init__ (self):
      self._num = self.__class__._next_num
      self.__class__._next_num += 1

    def __repr__ (self):
      return "Node2 #" + str(self._num)

  class Node3 (Node1):
    _next_num = 0
    def __init__ (self):
      self._num = self.__class__._next_num
      self.__class__._next_num += 1

    def __repr__ (self):
      return "Node3 #" + str(self._num)
  g = Graph()
  n1 = Node1();n1.label=1
  n2 = Node2();n2.label=2
  n3 = Node3();n3.label=3

  g.add(n1)
  g.add(n2)
  g.add(n3)
  g.link((n1,0),(n2,0))
  g.link((n1,1),(n3,0))

  print(g.find(is_a=Node1))
  print(g.find(is_a=Node2))
  print(g.find(type=Node1))
  print(g.find(type=Node3))
  print(g.find_links())
  print("=== NEIGHBORS ===")
  print(g.neighbors(n1))
  print(g.find_port(n1, n2))
  print(g.connected(n1, n3))
  print(g.ports_for_node(n3))

  print([(n, x[0], x[1][0], x[1][1]) for n in g.find(is_a=Node1) for x in g.ports_for_node(n).items() ])

  g.disconnect_nodes(n1, n3)

  print(g.find_links())
  g.link((n2, 1), (n3, 1))
  g.link((n1,1), (n3, 0))
  g.link((n1,0), (n2, 0))
  print(g.find_links())
  g.disconnect_node(n3)
  print(g.find_links())
  import code
  code.interact(local=locals())


if __name__ == "__main__":
  test()
