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

import pox.ovsdb

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
    return pox.ovsdb.to_raw_json(self._format__json())
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

    #FIXME: use parse_list() in this function

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



class Wait (Operation):
  """
  WAIT UNTIL/WHILE <columns> [WHERE <conditions>] IN <table> ARE|IS [NOT] <rows>
      [[WITH] TIMEOUT <timeout>]

  columns is a list/tuple or AND-separated list of column names
  rows in AND-separated list of rows
  """
  def __init__ (self, table, columns, rows, where=[], timeout=NO_VALUE,
                invert=False):
    """
    Initialize

    If invert is true, wait until the condition is NOT true
    """
    self.op = 'wait'
    self.table = table
    self.columns = columns
    self.rows = rows
    self.where = where
    self.timeout = timeout
    self.until = '!=' if invert else '=='

  @classmethod
  def parse (cls, data):
    expect(data, WAIT)

    invert = False
    if data[0] is UNTIL:
      pass
    elif data[0] is WHILE:
      invert = True
    else:
      raise RuntimeError("Expected UNTIL or WHILE")
    del data[0]

    columns = parse_list(data)

    where = []
    if data[0] is WHERE:
      del data[0]
      where = parse_conditions(data)

    expect(data, IN)
    table = data.pop(0)

    if data.pop(0) not in (ARE, IS):
      raise RuntimeError("Expected IS or ARE")

    if data[0] is NOT:
      invert = not invert
      del data[0]

    rows = parse_list(data)

    timeout = NO_VALUE
    if data and data[0] is WITH:
      del data[0]
      expect(data, TIMEOUT)
      timeout = data.pop(0)
    else:
      if expect(data, TIMEOUT, optional=True):
        timeout = data.pop(0)

    if data:
      raise RuntimeError("Trailing garbage")

    return cls(table=table, columns=columns, rows=rows, where=where,
               timeout=timeout, invert=invert)



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



class Delete (Operation):
  """
  DELETE [IN|FROM] <table> [WHERE <conditions>]
   or
  DELETE [WHERE <conditions>] IN|FROM <table>
  """
  def __init__ (self, table, where=[]):
    self.op = 'delete'
    self.table = table
    self.where = where

  @classmethod
  def parse (cls, expr):
    data = expr
    expect(data, DELETE)

    where = []
    for i in range(len(data)-1):
      if data[i] is WHERE:
        del data[i]
        where = parse_conditions(data, i)
        break

    if not data:
      raise RuntimeError("Expected table specification")

    if data[0] in (IN, FROM):
      del data[0]

    table = data.pop(0)

    if data:
      raise RuntimeError("Trailing junk")

    return cls(table=table, where=where)



class Commit (Operation):
  """
  COMMIT [DURABLE]
  """
  def __init__ (self, durable = True):
    self.op = 'commit'
    self.durable = durable

  @classmethod
  def parse (cls, data):
    expect(data, COMMIT)

    durable = False
    if expect(data, DURABLE, optional=True):
      durable = True

    if data:
      raise RuntimeError("Trailing junk")

    return cls(durable=durable)



class Abort (Operation):
  """
  ABORT
  """
  def __init__ (self):
    self.op = 'abort'

  @classmethod
  def parse (cls, data):
    expect(data, ABORT)

    if data:
      raise RuntimeError("Trailing junk")

    return cls()



class Comment (Operation):
  """
  COMMENT [<comment>]
  """
  def __init__ (self, comment):
    self.op = 'comment'
    self.comment = comment

  @classmethod
  def parse (cls, data):
    expect(data, COMMENT)

    comment = data.pop(0)

    if data:
      raise RuntimeError("Trailing junk")

    return cls(comment=comment)



class Assert (Operation):
  """
  ASSERT OWN [LOCK] <lock-id>
  """
  def __init__ (self, lock):
    self.op = 'assert'
    self.lock = lock

  @classmethod
  def parse (cls, data):
    expect(data, ASSERT)
    expect(data, OWN)
    if data[0] is LOCK:
      del data[0]
    lock_id = data.pop(0)

    if data:
      raise RuntimeError("Trailing junk")

    return cls(lock=lock_id)



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



class MonitorRequest (Operation):
  """
  MONITOR [<columns>] IN <table> [FOR [INITIAL] [INSERT] [DELETE] [MODIFY]]

  Not actually a transact operation.  This is used with the 'monitor' method.
  """
  def __init__ (self, table, columns = NO_VALUE, select = NO_VALUE):
    self.table = table
    self.columns = columns
    self.select = select

  @classmethod
  def parse (cls, data):
    if isinstance(data, ReservedWord):
      data = [data]
    else:
      data = data.els

    if data[0] is MONITOR: del data[0]

    # Somewhat more flexible than advertised...
    table = None
    if IN in data:
      table_pos = data.index(IN)
      del data[table_pos]
      table = data[table_pos]
      del data[table_pos]
    else:
      # Assume it's at the beginning
      table = data.pop(0)

    columns = parse_list(data, allow_empty=True)
    if not columns:
      columns = NO_VALUE

    select = NO_VALUE

    if data:
      select = {x:False for x in 'initial insert delete modify'.split()}
      if data[0] is FOR:
        del data[0]

      while data:
        if data[0] in (INITIAL, INSERT, DELETE, MODIFY):
          #select[type(data[0]).__name__.lower()] = True
          select.pop(type(data[0]).__name__.lower())
          del data[0]
        else:
          raise RuntimeError("Expected INITIAL/INSERT/DELETE/MODIFY")
        if data and data[0] == AND:
          del data[0]

    if data:
      raise RuntimeError("Trailing junk")

    return cls(table = table, columns = columns, select = select)



# OVSDB DSL definition stuff

def _reserve_word (symbols):
  for op in symbols:
    n = type(op, (ReservedWord,), {})()
    __all__.append(op)
    globals()[op] = n

_keywords =   ('AND FROM INTO WHERE IN WITH UUID_NAME DURABLE OWN LOCK '
               'UNTIL WHILE IS NOT ARE TIMEOUT').split()

_operations = ('SELECT INSERT MUTATE UPDATE DELETE COMMIT ABORT COMMENT '
               'ASSERT WAIT').split()

_conditions = ('INCLUDES EXCLUDES GREATER LESSER GREATEREQUAL LESSEREQUAL '
              'EQUAL INEQUAL').split()

_mutations =  ('INCREMENT DECREMENT MULTIPLYBY DIVIDEBY REMAINDEROF ' #INSERT '
               ' DELETE').split()

_monitor =    ('INITIAL INSERT DELETE MODIFY MONITOR FOR').split()

_reserve_word(_keywords)
_reserve_word(_operations)
_reserve_word(_conditions)
_reserve_word(_mutations)
_reserve_word(_monitor)

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
    #FIXME: Error message could be better when optional=True
  return got


def parse_statement (expr):
  if isinstance(expr, ReservedWord):
    expr = [expr]
  else:
    expr = expr.els
  if expr[0] is SELECT:
    return Select.parse(expr)
  elif expr[0] is INSERT:
    return Insert.parse(expr)
  elif MUTATE in expr:
    return Mutate.parse(expr)
  elif expr[0] is UPDATE:
    return Update.parse(expr)
  elif expr[0] is DELETE:
    return Delete.parse(expr)
  elif expr[0] is COMMIT:
    return Commit.parse(expr)
  elif expr[0] is ABORT:
    return Abort.parse(expr)
  elif expr[0] is COMMENT:
    return Comment.parse(expr)
  elif expr[0] is ASSERT:
    return Assert.parse(expr)
  elif expr[0] is WAIT:
    return Wait.parse(expr)
  raise RuntimeError("Syntax error")


def parse_conditions (data, offset=0):
  """
  Parse conditions from data, removing them as it goes
  """
  conditions = []
  while True:
    col = data.pop(offset)
    op = data.pop(offset)
    val = data.pop(offset)
    op = _condition_map[op]
    conditions.append([col,op,val])

    if offset >= len(data): break
    if data[offset] is not AND: break
    data.pop(offset)

  return conditions


def parse_list (data, offset=0, allow_empty=False):
  """
  Parse a tuple/list of items or an AND-separated list
  """
  r = []
  while True:
    if offset >= len(data) or isinstance(data[offset], ReservedWord):
      if not r and allow_empty:
        # No items, but that's okay.
        break
      raise RuntimeError("Expected list of items")
    elif isinstance(data[offset], (tuple, list)):
      #FIXME: anything list-like will do
      r.extend(data.pop(offset))
    else:
      r.append(data.pop(offset))
    if offset >= len(data): break
    if data[offset] is not AND:
      break
    del data[offset]

  if not r and not allow_empty:
    raise RuntimeError("Expected list of items")

  return r
