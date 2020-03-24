# Copyright 2017 James McCauley
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
A parser/evaluator meant for configuration data
"""

#TODO: Rewrite as classes.

import ast

default_symbols = {'True':True, 'False':False, 'None':None}


def eval_list (text, result_type=list, dict_type=dict,
                ignore_commas=True, loose_strings=True,
                symbols = default_symbols, functions = None,
                allow_hyphens=False):
  """
  Parses a list of things

  symbols is a dictionary with names and values they map to.  The default
  symbols are Python-like, e.g., "True" maps to True.  You could change
  this to be JSON-like, and you could add your own symbols.

  functions is a dictionary with names and functions.  Things that look
  like function invocations will call the function and insert its value.

  If loose_strings is True and you get an alphanumeric name which isn't
  in symbols or functions, then it will be turned into a string.

  There is no need for commas between items at the top level.  If you
  set ignore_commas=True, then commas at the top level are ignored.
  This allows you to, e.g., pass in something that looks like a Python
  list or JavaScript list (but without the start and end brackets).

  You can override the type used for dictionaries using dict_type.  For
  example, you might want to substitute OrderedDict.  You can also
  override the result type from the default plain list.
  """
  return _eval_text(text=text, result_type=result_type, dict_type=dict_type,
                     ignore_commas=ignore_commas, loose_strings=loose_strings,
                     symbols=symbols, functions=functions,
                     allow_hyphens=allow_hyphens)



def eval_dict (text, result_type=None, dict_type=dict,
                ignore_commas=True, loose_strings=True,
                symbols = default_symbols, functions = None,
                allow_hyphens=False):
  """
  Parses a string of key:value pairs into a dictionary

  symbols is a dictionary with names and values they map to.  The default
  symbols are Python-like, e.g., "True" maps to True.  You could change
  this to be JSON-like, and you could add your own symbols.

  functions is a dictionary with names and functions.  Things that look
  like function invocations will call the function and insert its value.

  If loose_strings is True and you get an alphanumeric name which isn't
  in symbols or functions, then it will be turned into a string.

  There is no need for commas between items at the top level (but if
  one of your values is a {dictionary}, *that* will need commas).  If
  you set ignore_commas=True, then commas at the top level are ignored.
  This allows you to, e.g., pass in something that looks like a Python
  dict or JSON object (but without the start and end braces).

  You can override the type used for dictionaries using dict_type.  For
  example, you might want to substitute OrderedDict.  You can also
  override the result type independently.

  Keys and values can be separated by either ':' or '=' at the top level.

  assert eval_dict("this:that number:42")['number'] == 42
  """
  if result_type is None: result_type = dict_type
  return _eval_text(text=text, result_type=result_type, dict_type=dict_type,
                     ignore_commas=ignore_commas, loose_strings=loose_strings,
                     symbols=symbols, functions=functions,
                     allow_hyphens=allow_hyphens)



def _eval_text (text, result_type=dict, dict_type=dict,
                 ignore_commas=True, loose_strings=True,
                 symbols = default_symbols, allow_hyphens=False,
                 functions = None):
  """
  Implements eval_list and eval_dict

  Internal use.
  """

  #TODO: Turn into a class instead of this nested function insanity.

  r = dict_type()

  class ParseError (RuntimeError):
    pass

  DIGITS = set("0123456789")
  HEX = set("abcdefABCDEF0123456789")
  WHITESPACE = set("\r\n \t")
  LOWER = set("abcdefghijklmnopqrstuvwxyz")
  UPPER = set(x.upper() for x in LOWER)
  ALPHA = LOWER.union(UPPER)
  ALPHANUM = ALPHA.union(DIGITS)

  class DONE (object):
    def __repr__ (self):
      return "<end>"
  DONE = DONE()

  #text = list(text)
  #text.append(DONE)
  ptr = [0]

  pos = [1,1] # Column,Row

  pos_stack = []


  def push_pos ():
    pos_stack.append( (ptr[0],pos[0],pos[1]) )

  def pop_pos ():
    ptr[0],pos[0],pos[1] = pos_stack.pop()

  def drop_pos ():
    pos_stack.pop()


  def peek ():
    return text[ptr[0]:ptr[0]+1] or DONE

  def peek_back ():
    return text[ptr[0]-1:ptr[0]] or DONE

  def eat ():
    c = peek()
    if c == "\n":
      pos[0] = 0
      pos[1] += 1
    pos[0] += 1
    ptr[0] += 1
    #print "EAT",repr(c)
    return peek_back()

  def is_done ():
    return peek() is DONE

  def expect (ex):
    tok = peek()
    if isinstance(ex, (set,list)):
      if tok in ex: return eat()
      ex = " or ".join(repr(x) for x in ex)
    elif ex == tok:
      return eat()
    else:
      ex = repr(ex)
    raise ParseError("Expected %s at or before %s" % (ex, repr(tok)))

  def maybe (ex):
    tok = peek()
    if isinstance(ex, (set,list)):
      if tok in ex: return eat()
    elif ex == tok:
      return eat()
    return False

  def skip_whitespace ():
    while maybe(WHITESPACE):
      pass

  def fail (ex = None):
    if ex is None:
      raise ParseError("Got unexpected %s" % (repr(peek())))
    raise ParseError("Expected %s at or before %s" % (ex, repr(peek())))


  def quoted_string (q):
    s = ''
    while True:
      if maybe(q):
        break
      elif maybe(DONE):
        fail("closing quotation mark")
      elif maybe("\\"):
        c = maybe("\\'\"\a\b\f\n\r\t\v")
        if c is not False:
          s += ast.literal_eval("\\" + c + "\\")
        elif maybe("x"):
          c1 = expect(HEX)
          c2 = expect(HEX)
          s += chr(int(c1+c2, 16))
        fail("valid escape sequence")
      s += eat()
    return s

  def number ():
    s = peek_back()
    is_int = True

    while True:
      if maybe(DIGITS):
        s += peek_back()
      elif s == "0" and maybe("x"):
        # Hex
        s = ''
        s += expect(HEX)
        while maybe(HEX):
          s += peek_back()
        return int(s, 16)
      else:
        break

    if maybe("."):
      is_int = False
      s += "."
      s += expect(DIGITS)
      while True:
        if maybe(DIGITS):
          s += peek_back()
        else:
          break

    if maybe("e"):
      is_int = False
      s += "."
      s += expect(DIGITS)
      while True:
        if maybe(DIGITS):
          s += peek_back()
        else:
          break

    return ast.literal_eval(s)

  def toplevel (ignore_whitespace=True):
    if ignore_whitespace: skip_whitespace()
    r = do_toplevel()
    if ignore_whitespace: skip_whitespace()
    return r

  def do_toplevel ():
    if maybe("'"):
      return True,quoted_string("'")
    elif maybe('"'):
      return True,quoted_string('"')
    elif maybe(DIGITS):
      return True,number()
    elif maybe("-"):
      expect(DIGITS)
      return True,-number()
    elif maybe("{"):
      l = dict_type()
      need_comma = False
      while True:
        if need_comma and maybe(","):
          need_comma = False
        elif maybe(WHITESPACE):
          pass
        else:
          success,t = toplevel()
          if not success:
            expect("}")
            return True,l
          k = t
          skip_whitespace()
          expect(":")
          skip_whitespace()
          success,t = toplevel()
          if not success:
            fail("dictionary key")
          l[k] = t
          need_comma = True
    elif maybe("[") or maybe("("):
      is_tuple = peek_back() == "("
      l = []
      need_comma = False
      while True:
        if need_comma and maybe(","):
          need_comma = False
        elif maybe(WHITESPACE):
          pass
        else:
          success,t = toplevel()
          if not success:
            if is_tuple:
              expect(")")
              return True,tuple(l)
            else:
              expect("]")
              return True,l
          l.append(t)
          need_comma = True
    elif maybe(ALPHA) or maybe("_"):
      s = peek_back()
      while maybe(ALPHANUM) or maybe("_") or (allow_hyphens and maybe("-")):
        s += peek_back()
      if functions and s in functions and callable(functions[s]):
        f = functions[s]
        skip_whitespace()
        if maybe("("):
          skip_whitespace()
          l = []
          need_comma = False
          while True:
            if need_comma and maybe(","):
              need_comma = False
            elif maybe(WHITESPACE):
              pass
            else:
              success,t = toplevel()
              if not success:
                expect(")")
                return True,f(*l)
              l.append(t)
              need_comma = True
        else:
          return True,f()
      if symbols and s in symbols:
        s = symbols[s]
      elif loose_strings:
        pass
      else:
        fail("symbol")
      return True,s

    return False,None

  result = result_type()

  try:
    if isinstance(result, dict):
      state = 0
      while True:
        while ( (state == 0 and ignore_commas and maybe(","))
                or maybe(WHITESPACE) ):
          pass
        success,t = toplevel()
        if not success:
          if state == 0:
            expect(DONE)
            break
          elif state == 1:
            expect(set(":="))
            state += 1
            continue
          fail("value")
        if state == 0:
          key = t
          state += 1
        elif state == 2:
          result[key] = t
          state = 0
    elif isinstance(result, list):
      while True:
        while (ignore_commas and maybe(",")) or maybe(WHITESPACE):
          pass
        success,t = do_toplevel()
        if not success:
          if maybe(DONE):
            break
          elif maybe(WHITESPACE):
            continue
          elif ignore_commas and maybe(","):
            continue
          elif len(result) and isinstance(result[-1], str):
            # This string extension might end with whitespace or the end of
            # the string.  We try one way and if it fails, try again the
            # other way.
            try:
              push_pos()
              result[-1] += quoted_string(WHITESPACE)
              drop_pos()
            except ParseError as e:
              pop_pos()
              result[-1] += quoted_string(DONE)
            while ignore_commas and result[-1].endswith(","):
              result[-1] = result[-1][:-1]
            continue
          else:
            fail()
        result.append(t)
    else:
      raise RuntimeError("Expected result type to be list or dict")
  except ParseError as e:
    args = list(e.args)
    args[0] = "At %s:%s - " % (pos[1],pos[0]) + e.message
    args[0] += "\n" + text.split("\n")[pos[1]-1]
    args[0] += "\n%s^" % (" " * (pos[0] - 1),)
    e.args = args
    raise

  return result



def eval_one (text, *args, **kw):
  """
  Parses a single item
  """
  # This implementation is a hack until the main function is refactored
  r = eval_list(text, *args, **kw)
  if len(r) != 1:
    raise ValueError("Expected exactly one item, but got %s", r)
  return r[0]



if __name__ == "__main__":
  functions = dict(add=lambda a,b: a+b, num=lambda:42)
  import sys
  for arg in sys.argv[1:]:
    print(arg)
    try:
      r = eval_dict(arg, functions=functions)
      print("DICT:", r)
    except:
      pass
    try:
      r = eval_list(arg, functions=functions)
      print("LIST:", r)
    except:
      raise
      pass
    print()
