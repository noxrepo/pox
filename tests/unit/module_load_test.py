#!/usr/bin/env python
#
# Copyright 2011-2012 Andreas Wundsam
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

""" A simple nose based test unit test that discovers all modules in the pox directory and tries to load them """

import sys
from os import path
import os

import unittest
SCRIPT_DIR=path.dirname(path.abspath(__file__))
ROOT=path.abspath(path.join(SCRIPT_DIR,"../.."))
sys.path.append(os.path.dirname(__file__) + "/../..")

packages = {}

modules = []

for root, dirs, files in os.walk(ROOT):
  assert root.startswith(ROOT)
  root = root[len(ROOT)+1:]
  if not root.startswith("pox"): continue

  if not path.exists(path.join(root, "__init__.py")):
    continue
  modules.append(root.replace(path.sep,"."))

  files = [f for f in files if f.endswith(".py") and not f.startswith("__init__") and f != "setup.py"]
  #print root
  for f in files:
    packagename = root.replace(path.sep,".")
    modules.append( packagename + "." + f[:-3])

def test_load_modules():
  # This is a test /generator/. It yields a separate loading test for each module
  # Nosetests is required
  for module in modules:
    yield load_module, module

def load_module(module):
  loaded_module = __import__(module)


if __name__ == '__main__':
  import nose
  nose.main(defaultTest=__name__)

