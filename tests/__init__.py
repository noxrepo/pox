# Copyright 2011-2012 James McCauley
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

from pox.core import core
import pox.boot

if core is None:
  import logging
  log = logging.getLogger("tests")
else:
  log = core.getLogger("tests")

_first = True
_tests = []

def _up (e):
  log.info("Starting")
  for test in _tests:
    log.info("Test %s", test)
    if pox.boot._do_import("tests." + test) is True:
      log.error("Test %s not found", test)
      return

def launch (**kw):
  #__main__.cli = False # Disable CLI
  global _first
  if _first:
    core.addListenerByName("UpEvent", _up)
    _first = False
  for k in kw:
    if k not in _tests:
      _tests.append(k)

