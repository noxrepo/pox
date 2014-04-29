# Copyright 2014 James McCauley
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
An embedded DSL for OVSDB in Python

Highly experimental.  Possibly insane?
"""

__all__ = [] # Stuff to export (added to later)

class Statement (object):
  """
  OVSDB DSL statement
  """
  def __init__ (self, el=None):
    self.els = []
    if el is not None: self.els.append(el)

  def _parse (self):
    return parse_statement(self)

  def _append (self, other):
    if isinstance(other,Statement):
      self.els.extend(other.els)
      other.els = self.els
    else:
      self.els.append(other)

  def __or__ (self, other):
    self._append(other)
    return self

  def __lt__ (self, other):
    self.els.append(LESSER)
    self._append(other)
    return self
  def __gt__ (self, other):
    self.els.append(GREATER)
    self._append(other)
    return self
  def __le__ (self, other):
    self.els.append(LESSEREQUAL)
    self._append(other)
    return self
  def __ge__ (self, other):
    self.els.append(GREATEREQUAL)
    self._append(other)
    return self
  def __eq__ (self, other):
    self.els.append(EQUAL)
    self._append(other)
    return self
  def __ne__ (self, other):
    self.els.append(NOTEQUAL)
    self._append(other)
    return self

  def __str__ (self):
    #return "(%s)" % " ".join(str(e) for e in self.els)
    return "%s(%s)" % (type(self).__name__, " ".join(str(e) for e in self.els))



class ReservedWord (object):
  """
  Reserved word for OVSDB DSL
  """
  def __or__ (self, other):
    e = Statement(self)
    e.els.append(other)
    return e

  def __ror__ (self, other):
    e = Statement(other)
    e.els.append(self)
    return e

  def __str__ (self):
    n = type(self).__name__
    return "<"+n+">"



class NO_VALUE (object): pass



class Operation (object):
  """
  Superclass for OVSDB operations
  """
  def _format__json (self):
    return {k:v for k,v in vars(self).items() if v is not NO_VALUE}

  def __str__ (self):
    from ovsdb import to_raw_json
    return to_raw_json(self._format__json())
    #return str(self._format__json())



class Insert (Operation):
  """
  INSERT <row> INTO <table> [WITH UUID_NAME <uuid-name>]
  """
  def __init__ (self, table, row, uuid_name = None):
    self.op = 'insert'
    self.table = table
    self.row = row
    self.uuid_name = uuid_name

  @classmethod
  def parse (cls, expr):
    els = expr
    expect(els, INSERT)

    row = els.pop(0)
    expect(els, INTO)
    table = els.pop(0)
    if expect(els, WITH, optional=True):
      expect(els, UUID_NAME)
      uuid_name = els.pop(0)
    else:
      uuid_name = None

    return cls(table, row, uuid_name)



class Select (Operation):
  """
  SELECT [<columns>] FROM <table> WHERE <condition> [AND <condition> ...]
  columns can be a list/tuple of columns, or a list of columns separated by AND.
  """
  def __init__ (self, table, where=[], columns=NO_VALUE):
    self.op = 'select'
    self.table = table
    self.where = where
    self.columns = columns

  @classmethod
  def parse (cls, expr):
    els = expr
    expect(els, SELECT)

    columns = NO_VALUE
    cur = els[0]
    if cur != FROM:
      # Must be columns
      columns = []
      while True:
        cur = els.pop(0)
        if isinstance(cur, basestring):
          columns.append(cur)
        else:
          try:
            columns.extend(list(cur))
          except:
            columns.append(cur)
        cur = els[0]
        if cur != AND:
          break
        els.pop(0)

    expect(els, FROM)
    table = els.pop(0)
    where = []
    if expect(els, WHERE, optional=True):
      where = parse_conditions(els)
    if els:
      raise RuntimeError("Junk trailing SELECT")

    return cls(table=table, where=where, columns=columns)



class Update (Operation):
  """
  UPDATE <table> [WHERE <conditions>] WITH <row>
  """
  def __init__ (self, table, row, where=[]):
    self.op = 'update'
    self.table = table
    self.where = where
    self.row = row

  @classmethod
  def parse (cls, expr):
    data = expr
    expect(data, UPDATE)

    table = data.pop(0)
    where = []
    if expect(data, WHERE, optional=True):
      where = parse_conditions(data)

    expect(data, WITH)

    row = data.pop(0)

    if data:
      raise RuntimeError("Junk trailing UPDATE")

    return cls(table=table, row=row, where=where)



class Mutate (Operation):
  """
  IN <table> [WHERE <conditions>] MUTATE <mutations>

  mutations is an AND-separated list of one of:
    <column> INCREMENT/DECREMENT/MULTIPLYBY/DIVIDEBY/REMAINDEROF <value>
    DELETE <value> FROM <column>
    INSERT <value> INTO <column>
  """
  def __init__ (self, table, where = [], mutations = []):
    self.op = 'mutate'
    self.table = table
    self.where = where
    self.mutations = mutations

  @classmethod
  def parse (cls, expr):
    data = expr

    expect(data, IN)
    table = data.pop(0)
    where = []
    if data[0] is WHERE:
      data.pop(0)
      where = parse_conditions(data)
    expect(data, MUTATE)

    mutations = []
    while data:
      mutation = [None,None,None] # col, mutator, value
      mutations.append(mutation)
      if data[0] in (INSERT, DELETE):
        mutation[1] = _mutator_map[data[0]]
        data.pop(0)
        mutation[2] = data.pop(0)
        if data[0] not in (INTO,FROM,IN): # Hah
          raise RuntimeError("Expected INTO/FROM/IN in mutator")
        data.pop(0)
        mutation[0] = data.pop(0) # column
      else:
        mutation[0] = data.pop(0)
        mutation[1] = _mutator_map[data.pop(0)]
        mutation[2] = data.pop(0)
      expect(data, AND, optional=True)

    return cls(table=table, where=where, mutations=mutations)



# OVSDB DSL definition stuff

def _reserve_word (symbols):
  for op in symbols:
    n = type(op, (ReservedWord,), {})()
    __all__.append(op)
    globals()[op] = n

_keywords = 'AND FROM INTO WHERE IN WITH UUID_NAME'.split()

_operations = 'SELECT INSERT MUTATE UPDATE'.split()

_conditions = ('INCLUDES EXCLUDES GREATER LESSER GREATEREQUAL LESSEREQUAL '
              'EQUAL INEQUAL').split()

_mutations = ('INCREMENT DECREMENT MULTIPLYBY DIVIDEBY REMAINDEROF ' #INSERT '
             ' DELETE').split()


_reserve_word(_keywords)
_reserve_word(_operations)
_reserve_word(_conditions)
_reserve_word(_mutations)

NOTEQUAL = INEQUAL # A synonym


_condition_map = {
  INCLUDES     : 'includes',
  EXCLUDES     : 'excludes',
  GREATER      : '>',
  LESSER       : '<',
  GREATEREQUAL : '>=',
  LESSEREQUAL  : '<=',
  EQUAL        : '==',
  NOTEQUAL     : '!=',
}

_mutator_map = {
  INCREMENT    : '+=',
  DECREMENT    : '-=',
  MULTIPLYBY   : '*=',
  DIVIDEBY     : '/=',
  REMAINDEROF  : '%=',
  INSERT       : 'insert',
  DELETE       : 'delete',
}



# OVSDB DSL parsing stuff

def expect (list, expect, optional = False):
  if not list:
    if optional:
      return None
    raise RuntimeError("Expected '%s' but got nothing", (expect,))

  got = list.pop(0)
  if got != expect:
    raise RuntimeError("Expected '%s' but got '%s'" % (expect, got))
  return got


def parse_statement (expr):
  expr = expr.els
  if expr[0] is SELECT:
    return Select.parse(expr)
  elif expr[0] is INSERT:
    return Insert.parse(expr)
  elif MUTATE in expr:
    return Mutate.parse(expr)
  elif expr[0] is UPDATE:
    return Update.parse(expr)
  raise RuntimeError("Syntax error")


def parse_conditions (data):
  conditions = []
  while True:
    col = data.pop(0)
    op = data.pop(0)
    val = data.pop(0)
    op = _condition_map[op]
    conditions.append([col,op,val])

    if not data: break
    if data[0] is not AND: break
    data.pop(0)

  return conditions



# Quick test stuff

def _test ():
  p = parse_statement
  print p( SELECT|FROM|"Bridge"|WHERE|"datapath_id" == "0000000000000001"
           |AND|"a2" == "bad" )
  print p( SELECT|"controller"|FROM|"Bridge"|WHERE|
           "datapath_id" == "0000000000000001"|AND|"a2" == "bad" )
  print p( IN|"Bridge"|WHERE|"dpid" == 3|AND|"controller" != 5|MUTATE|
           "dpid"|INCREMENT|4|AND|DELETE|"hi"|FROM|"greetings" )


if __name__ == '__main__':
  _test()
