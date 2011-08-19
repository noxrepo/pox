"""
This package contains two L2 learning switches for OpenFlow.

The default, dumb_l2_switch, is written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.

The other, ofcommand_l2_switch, is derived originally from NOX's pyswitch
example.  It is now a demonstration of the ofcommand library for constructing
OpenFlow messages.
"""

def launch ():
  """
  Starts an L2 learning switch.
  """
  import dumb_l2_switch
  from pox.core import core
  core.registerNew(dumb_l2_switch.dumb_l2_switch)
