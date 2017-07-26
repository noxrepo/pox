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
Loads a config file

Config files have a format like:
  [module_name]
  # A comment line
  flag_argument
  argument_with_value=42
  argument_using_variable=My name is ${name}.
  !special_directive

Special directives include:
  !ignore    Ignore this whole module (easier than commenting it out)
  !append    Append arguments to previous module definition instead of
             a new instance of this module

Config file values can have variables set with config.var and referenced
with, e.g., "${var_name}".  For the above, you might use:
  config.var --name=Jane
"""

from pox.config.var import variables
from pox.boot import _do_launch #TODO: Make this public


def _var_sub (v):
  if "${" in v:
    o = []
    v = "${}" + v
    v = v.split("${")[1:]
    for s in v:
      #FIXME: No easy way to have literal ${} in string
      if "}" not in s:
        raise RuntimeError("Unterminated variable substitution")
      var,rest = s.split("}", 1)
      if var == "": val = ""
      else: val = variables.get(var)
      if val is None:
        raise RuntimeError("Variable '%s' is not set" % (var))
      o.append(val)
      o.append(rest)
    v = "".join(o)
  return v


def launch (file, __INSTANCE__=None):
  sections = []
  args = None
  for line in open(file, "r"):
    line = line.lstrip().rstrip("\n")
    if line.startswith("#"): continue
    if not line: continue
    if line.startswith("[") and line.rstrip().endswith("]"):
      section = line.strip()[1:-1]
      args = []
      sections.append((section, args))
    elif args is None:
      raise RuntimeError("No section specified")
    else:
      if "=" in line:
        k,v = line.split("=", 1)
        assert k, "Expected argument name"
        k = _var_sub(k)
        if v.startswith('"') and v.rstrip().endswith('"'):
          v = v.rstrip()[1:-1]
        v = _var_sub(v)
      else:
        k = _var_sub(line.strip())
        v = True

        if k == "!ignore":
          # Special directive
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

      args.append((k,v))
      #print('%s="%s"' % (k,v))

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
