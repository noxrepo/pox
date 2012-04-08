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
A minimal reimplementation of enough of NetworkX's MultiGraph so that
the NOM graph stuff should work.  This actually doesn't present an
ideal way to store the underlying graph, but it'll work for now.
"""

from collections import defaultdict as ddict

class MultiGraph (object):
  def __init__ (self):
    self._next_key = 0

    self._edges = ddict(lambda:ddict(lambda:ddict(lambda:{})))
    # node -> node -> key -> {attr}

    self._nodes = {}
    # node -> {attr}

  def nodes (self, data = False):
    if not data:
      return self._nodes.keys()
    return self._nodes.items()

  def edges (self, nbunch = None, data = False, keys = False):
    def fix (a,b):
      if a>b: return (b,a)
      return (a,b)

    if nbunch is not None:
      nbunch = set(nbunch)

    edges = {}

    for e1,otherEnd in self._edges.iteritems():
      for e2,rest in otherEnd.iteritems():
        if nbunch is not None:
          if e1 not in nbunch: continue
          if len(nbunch) > 1 and e2 not in nbunch: continue

        e = fix(e1,e2)
        if e in edges: continue

        edges[e] = rest

    r = []
    for nodes,edgelist in edges.iteritems():
      for k,d in edgelist.iteritems():
        if data and keys:
          r.append((nodes[0],nodes[1],k,d)) # Is the order right?
        elif data:
          r.append((nodes[0],nodes[1],d))
        elif keys:
          r.append((nodes[0],nodes[1],k))
        else:
          r.append(nodes)

    return r

  def neighbors (self, node):
    assert node in self._nodes
    return list(set(self._edges[node].keys()))

  def _gen_key (self):
    r = self._next_key
    self._next_key += 1
    return r

  def add_node (self, node, **attr):
    if node in self._nodes:
      self._nodes[node].update(attr)
    else:
      self._nodes[node] = attr

  def remove_node (self, node):
    others = self._edges[node].keys()
    del self._edges[node]
    for other in others:
      if other == node: continue
      del self._edges[other][node]
    del self._nodes[node]

  def add_edge (self, node1, node2, key=None, **attr):
    assert node1 is not node2
    self.add_node(node1)
    self.add_node(node2)
    if key is None: key = self._gen_key()
    e = self._edges[node1][node2][key]
    e.update(attr)
    self._edges[node2][node1][key] = e

  def add_edges_from (self, edges, **attr):
    for e in edges:
      if len(e) == 2:
        self.add_edge(*e)
      elif len(e) == 3:
        d = e[2].copy()
        d.update(attr)
        self.add_edge(e[0],e[1],**d)
      elif len(e) == 4:
        d = e[3].copy()
        d.update(attr)
        self.add_edge(e[0],e[1],key=e[3],**d)
      else:
        assert False

  def remove_edge (self, node1, node2, key=None):
    if key is None:
      key = self._edges[node1][node2].keys()[0] # First one is fine
    del self._edges[node1][node2][key]
    del self._edges[node2][node1][key]

  def add_path (self, nodes, **attr):
    for n in nodes:
      self.add_node(n, **attr)
    for n1,n2 in zip(nodes[:-1],nodes[1:]):
      self.add_edge(n1,n2)

  def __getitem__ (self, node):
    o = {}
    for k0,v0 in self._edges[node].iteritems():
      if k0 not in o: o[k0] = {}
      for k1,v1 in v0.iteritems():
        if k1 not in o[k0]: o[k0][k1] = {}
        o[k0][k1] = v1

    return o # This is self._edges but as a normal dict


