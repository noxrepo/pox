# Copyright 2017,2018 James McCauley
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
Loads a config file

Config files have a format like:
  [module_name]
  # A comment line
  flag_argument
  argument_with_value=42
  argument_using_variable=My name is ${name}.
  !special_directive

Special directives include:
  !ignore       Ignore this whole module (easier than commenting it out).
                You can also do "!ignore [true|false]".
  !append       Append arguments to previous module definition instead of
                a new instance of this module
  !set foo=bar  Set variable foo to 'bar' (or just !set for True)
  !unset foo    Unset variable foo
  !gset foo=bar Set global variable foo to 'bar'
  !gunset foo   Unset global variable foo
  [!include x]  Include another config file named 'x' (See below)
  !log[=lvl] .. Log the rest of the line at the given level (or INFO)

You can also do things conditionally depending on whether a variable is
set or not using !ifdef/!elifdef/!ifndef/!elifndef/!else/!endif.

Config file values can have variables set with config.var and referenced
with, e.g., "${var_name}".  For the above, you might use:
  config.var --name=Jane
or
  config.gvar --name=Jane
The difference is that the former is only valid for the next config file
processed.  The latter stays valid for all subsequent config files.

The following special variables are available:
 _CONFIG_DIR_    The directory of the config file being processed.
 _CURRENT_DIR_   The current working directory.
 _POXCORE_DIR_   The directory of pox.core.
"""

from pox.config.var import variables
from pox.config.gvar import gvariables
from pox.boot import _do_launch #TODO: Make this public
from pox.lib.util import str_to_bool
import pox as pox_base
import os


class LogError (RuntimeError):
  pass



def _var_sub (v, allow_bool=False):
  has_bool = None
  if "${" in v:
    o = []
    v = "${}" + v
    v = v.split("${")[1:]
    for s in v:
      #FIXME: No easy way to have literal ${} in string
      if "}" not in s:
        raise LogError("Unterminated variable substitution")
      var,rest = s.split("}", 1)
      default = None
      if "|" in var: var,default = var.split("|", 1)
      var = var.strip()
      if var == "": val = ""
      else: val = variables.get(var,gvariables.get(var, default))
      if val is None:
        raise LogError("Variable '%s' is not set" % (var))
      if val is True or val is False:
        val = str(val)
        has_bool = val
      o.append(val)
      o.append(rest)
    v = "".join(o)
  if allow_bool and has_bool == v: return bool(v)
  return v


def _handle_var_set (line, vs):
  var = line.split(" ", 1)[1].split("=",1)
  if len(var) == 1:
    vs[var[0].strip()] = True
  elif len(var) == 2:
    vs[var[0].strip()] = var[1].strip()


def _handle_var_unset (line, vs):
  var = line.split(" ", 1)[1].split("=",1)
  if len(var) != 1:
    raise LogError("Syntax error")
  vs.pop(var[0].strip(), None)



class IfStack (object):
  def __init__ (self):
    self.stack = [1] # 0 = Unmatched, 1 = Matches-Current, 2 = Done-Matching
    # We start off with 1 as if we were always in an "if True"

  def start_if (self):
    if self.can_execute:
      self.stack.append(0)
    else:
      self.stack.append(2) # Never match

  def set_match (self, matches=True):
    if len(self.stack) == 1:
      raise LogError("Additional conditional without 'if' expression")
    state = self.stack[-1]
    if state == 2:
      return
    elif state == 1:
      self.stack[-1] += 1
    elif state == 0:
      if matches:
        self.stack[-1] += 1

  @property
  def can_execute (self):
    return self.stack[-1] == 1

  def end_if (self, cmd):
    self.stack.pop()
    if not self.stack:
      raise LogError("Unexpected " + cmd)

  def finish (self):
    assert len(self.stack) > 0
    if len(self.stack) != 1:
      raise LogError("Unterminated if statement")



def _careful_set (d, k, v):
  if k in d: return False
  d[k] = v
  return True



def launch (file, __INSTANCE__=None):
  file = os.path.expanduser(file)
  variables['_CONFIG_DIR_'] = os.path.dirname(file)
  _careful_set(gvariables, '_CURRENT_DIR_', os.getcwd())
  _careful_set(gvariables, '_POXCORE_DIR_', os.path.dirname(pox_base.__file__))
  sections = []
  args = None
  lineno = 0
  ifstack = IfStack()
  try:
    for line in open(file, "r"):
      lineno += 1
      line = line.lstrip().replace("\r","\n").rstrip("\n")
      if line.startswith("#"): continue
      if not line: continue

      #TODO: more powerful/general if statements
      if line.startswith("!ifdef "):
        ifstack.start_if()
        var = line.split(None, 1)[-1].strip()
        ifstack.set_match(var in variables or var in gvariables)
        continue
      elif line.startswith("!ifndef "):
        ifstack.start_if()
        var = line.split(None, 1)[-1].strip()
        ifstack.set_match(not (var in variables or var in gvariables))
        continue
      elif line.startswith("!elifdef "):
        var = line.split(None, 1)[-1].strip()
        ifstack.set_match(var in variables or var in gvariables)
        continue
      elif line.startswith("!elifndef "):
        var = line.split(None, 1)[-1].strip()
        ifstack.set_match(not (var in variables or var in gvariables))
        continue
      elif line == "!else":
        ifstack.set_match(True)
        continue
      elif line == "!endif":
        ifstack.end_if(line)
        continue
      elif not ifstack.can_execute:
        continue

      if line.startswith("[") and line.rstrip().endswith("]"):
        section = line.strip()[1:-1].strip()
        if section.startswith("!include "):
          new_file = section.split(" ",1)[1]
          new_file = os.path.join(os.path.dirname(file), new_file)
          sections.append(("config", [("file",new_file)]))
          args = None
          continue
        args = []
        sections.append((section, args))
      elif line.startswith("!set "):
        _handle_var_set(line, variables)
      elif line.startswith("!unset "):
        _handle_var_unset(line, variables)
      elif line.startswith("!gset "):
        _handle_var_set(line, gvariables)
      elif line.startswith("!gunset "):
        _handle_var_unset(line, gvariables)
      elif line.startswith("!log"):
        # Is there a reason why we don't just have pox.core imported?
        import logging
        import pox.core
        # This is dumb and ugly
        level = "INFO"
        if line.startswith("!log="):
          level = line.split("=",1)[-1].split(None,1)[0]
        try:
          level = logging._levelNames.get(level)
        except Exception:
          level = 50 # Default to intense!
        l = pox.core.core.getLogger()
        l.log(level, _var_sub(line.split(None,1)[-1].strip()))
      elif args is None:
        raise LogError("No section specified")
      else:
        if "=" in line:
          k,v = line.split("=", 1)
          assert k, "Expected argument name"
          k = _var_sub(k)
          if v.startswith('"') and v.rstrip().endswith('"'):
            v = v.rstrip()[1:-1]
          v = _var_sub(v, allow_bool=True)
        else:
          k = _var_sub(line.strip())
          v = True

          if k.startswith("!ignore"):
            # Special directive
            k = k[7:]
            if k == '' or k.startswith(' '):
              if k == '' or str_to_bool(_var_sub(k.strip())):
                if not sections or sections[-1][0] is None:
                  raise LogError("Nothing to !ignore")
                sections[-1] = (None,None)
            else:
              raise LogError("Syntax error")
            continue

          if k == "!append":
            cur = sections[-1][0]
            for oldsec,oldargs in sections:
              if oldsec == cur:
                oldargs.extend(args)
                args = oldargs
                break
            continue

        if not k: continue
        if k.startswith("!"):
          raise LogError("Unknown directive '%s'" % (k,))

        args.append((k,v))
        #print('%s="%s"' % (k,v))
    ifstack.finish()
  except LogError as e:
    import pox.core
    l = pox.core.core.getLogger()
    l.error("On line %s of config file '%s':\n%s" % (lineno,file,e.message))
    os._exit(1)
  except Exception:
    import pox.core
    l = pox.core.core.getLogger()
    l.exception("On line %s of config file '%s'" % (lineno,file))
    os._exit(1)
    #print "Error on line %s of config file '%s'." % (lineno,file)

  variables.clear()

  argv = []
  for sname,sargs in sections:
    if sname is None: continue
    argv.append(sname)
    for argname,argval in sargs:
      arg = "--" + argname
      if argval is not True:
        arg += "=" + argval
      argv.append(arg)

  #print "\n".join("  "+x if x.startswith("-") else x for x in argv)

  if _do_launch(argv, skip_startup=True) is False:
    os._exit(1)
