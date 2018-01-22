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
  !set foo=bar  Set variable foo to 'bar'
  !gset foo=bar Set global variable foo to 'bar'
  [!include x]  Include another config file named 'x' (See below)

Config file values can have variables set with config.var and referenced
with, e.g., "${var_name}".  For the above, you might use:
  config.var --name=Jane
"""

from pox.config.var import variables
from pox.config.gvar import gvariables
from pox.boot import _do_launch #TODO: Make this public
from pox.lib.util import str_to_bool
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
      if var == "": val = ""
      else: val = variables.get(var,gvariables.get(var))
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


def _handle_var (line, vs):
  var = line.split(" ", 1)[1].split("=",1)
  if len(var) == 1:
    # Unset
    vs.pop(var[0].strip(), None)
  elif len(var) == 2:
    vs[var[0].strip()] = var[1].strip()



def launch (file, __INSTANCE__=None):
  file = os.path.expanduser(file)
  sections = []
  args = None
  lineno = 0
  try:
    for line in open(file, "r"):
      lineno += 1
      line = line.lstrip().rstrip("\n")
      if line.startswith("#"): continue
      if not line: continue
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
        _handle_var(line, variables)
      elif line.startswith("!gset "):
        _handle_var(line, gvariables)
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
            if not k:
              del sections[-1]
            elif k[0] != ' ':
              raise LogError("Syntax error")
            if str_to_bool(_var_sub(k.strip())):
              del sections[-1]
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
  except LogError as e:
    import pox.core
    l = pox.core.core.getLogger()
    l.error("On line %s of config file '%s':\n%s" % (lineno,file,e.message))
    import sys
    sys.exit(1)
  except Exception:
    import pox.core
    l = pox.core.core.getLogger()
    l.exception("On line %s of config file '%s'" % (lineno,file))
    import sys
    sys.exit(1)
    #print "Error on line %s of config file '%s'." % (lineno,file)

  variables.clear()

  argv = []
  for sname,sargs in sections:
    argv.append(sname)
    for argname,argval in sargs:
      arg = "--" + argname
      if argval is not True:
        arg += "=" + argval
      argv.append(arg)

  _do_launch(argv, skip_startup=True)
