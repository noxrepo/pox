# Copyright 2013 James McCauley
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
Attempts to give help on other components
"""

from __future__ import print_function
import pox.boot as boot
from pox.lib.util import first_of
import inspect
import sys

def _show_args (f,name):
  #TODO: Refactor with pox.boot

  if name == "launch": name = "default launcher"

  out = []

  EMPTY = "<Unspecified>"

  argnames,varargs,kws,defaults = inspect.getargspec(f)
  argcount = len(argnames)
  defaults = list((f.__defaults__) or [])
  defaults = [EMPTY] * (argcount - len(defaults)) + defaults

  args = {}
  for n, a in enumerate(argnames):
    args[a] = [EMPTY,EMPTY]
    if n < len(defaults):
      args[a][0] = defaults[n]
  multi = False
  if '__INSTANCE__' in args:
    multi = True
    del args['__INSTANCE__']

  if len(args) == 0:
    if argcount or kws:
      out.append(" Multiple.")
      varargs = kws = None
    else:
      out.append(" None.")
  else:
    out.append(" {0:25} {1:25}".format("Name", "Default"))
    out.append(" {0:25} {0:25}".format("-" * 15))

    for k,v in args.items():
      k = k.replace("_","-")
      out.append(" {0:25} {1:25}".format(k,str(v[0])))

  if len(out):
    out.insert(0, "Parameters for {0}:".format(name))
    out.append("")

  if multi:
    out.append(" Note: This can be invoked multiple times.")
  if varargs or kws:
    out.append(" Note: This can be invoked with parameters not listed here.")

  out = '\n'.join(out)

  return out.strip()


def launch (no_args = False, short = False, **kw):
  """
  Shows help

  Usage: help <args> --component_name
         help <args> --component_name=launcher

  Args are:
    --short    Only summarize docs
    --no-args  Don't show parameter info
  """

  if len(kw) == 0:
    d = boot._help_text
    if short: d = d.split("\n")[0]
    print(d)
    sys.exit(0)

  if len(kw) != 1:
    if len(kw) > 1:
      print()
      print("Didn't understand what you wanted.  "
            "Showing help for help instead.")
    kw = {'help':True}

  component = first_of(kw.keys())
  launcher = first_of(kw.values())

  if component == 'help':
    # Special case!
    name = "pox.help"
  else:
    name = boot._do_import(component)

  if name is False:
    print("No such component:",component)
    sys.exit(1)

  mod = sys.modules[name]

  if launcher is not True and launcher not in mod.__dict__:
    print("No launch function named %s for %s" % (launcher, component))
    sys.exit(1)

  doc = inspect.getdoc(mod) or ''
  if short: doc = doc.split("\n")[0]

  if not doc:
    # Make sure we try to show SOMETHING...
    no_args = False

  launcher_doc = ""

  multi = ''
  args = ''

  if launcher is True and 'launch' in mod.__dict__:
    launcher = 'launch'
  if not no_args and launcher in mod.__dict__:
    f = mod.__dict__[launcher]
    if type(f) is not type(launch):
      # This isn't quite right if they didn't specify a launcher
      print(launch, "in", name, "isn't a function")

    launcher_doc = inspect.getdoc(f) or ''
    if short: launcher_doc = launcher_doc.split("\n")[0]

    if len(launcher_doc):
      launcher_doc = ' ' + launcher_doc.replace('\n', '\n ').strip()
      if launcher  == 'launch':
        launcher_doc = "Default launcher:\n" + launcher_doc
      else:
        launcher_doc = launcher + " launcher:\n" + launcher_doc

    args = _show_args(f,launcher)

  alldoc = [doc,launcher_doc,args,multi]

  alldoc = [x.strip() + "\n\n" for x in alldoc if len(x)]

  alldoc = ''.join(alldoc).strip() or 'No documentation available'

  print()
  print(alldoc)

  sys.exit(0)
