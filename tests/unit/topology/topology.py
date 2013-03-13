# Copyright 2011-2012 Colin Scott
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

# TODO: use a unit-testing library for asserts

# invoke with:
#   ./pox.py --script=tests.topology.topology topology
#
# Maybe there is a less awkward way to invoke tests...

from pox.core import core
from pox.lib.revent import *

topology = core.components['topology']

def autobinds_correctly():
  topology.listenTo(core)
  return True

if not autobinds_correctly():
  raise AssertionError("Did no autobind correctly")

