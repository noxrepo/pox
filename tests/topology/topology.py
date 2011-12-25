# TODO: use a unit-testing library for asserts

from pox.core import core
from pox.lib.revent import *

topology = core.components['topology']

def autobinds_correctly():
  topology.listenTo(core)
  return True

if not autobinds_correctly():
  raise AssertionError("Did no autobind correctly")

