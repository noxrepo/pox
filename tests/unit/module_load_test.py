#!/usr/bin/env python

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

