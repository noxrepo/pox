# Copyright 2018 James McCauley
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
Tweak values

This component lets you tweak various values which otherwise you'd need
to write code to do.  For example, lots of classes have default values
stored as class variables, and there isn't always an exposed way to
change them from the commandline or a config file.  With tweak, you
just do:
  misc.tweak=some.thing.Somewhere.value --value=42
"""

import sys
from pox.lib.config_eval import eval_one
from pox.core import core

log = core.getLogger()


def launch (key, value=None, __INSTANCE__=None):
  if "=" in key:
    if value is not None:
      raise RuntimeError("Value specified twice")
    assert value is None
    key,value = key.split("=",1)
  elif value is None:
    raise RuntimeError("You must specify a value with --value=...")

  def try_tweak (mod, obj):
    mod = ".".join(mod)
    if mod not in sys.modules: return False
    m = sys.modules[mod]
    o = m
    prev = None
    for oname in obj:
      prev = o
      if not hasattr(o, oname): return False
      o = getattr(o, oname)

    core.getLogger()
    log.debug("Tweaking %s in %s from %s to %s", ".".join(obj), mod,
              repr(getattr(prev,oname)), repr(value))

    setattr(prev, oname, value)
    return True

  value = eval_one(value)

  modparts = key.split(".")
  for split_at in range(len(modparts)-1,0,-1):
    if try_tweak(modparts[:split_at],modparts[split_at:]): break
