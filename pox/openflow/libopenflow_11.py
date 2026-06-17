# Copyright 2026 Gabriel Vieira, Rafael Graunke
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
A few OpenFlow 1.1 structures, just enough to build a FlowMod that wraps
its actions in an instruction (the 1.1 way) instead of a flat action list
(the 1.0 way).  We only pack these for sending; we don't parse them.

Coexists with libopenflow_01 -- it isn't touched.
"""

import struct

OFP_VERSION = 0x02

# Action types
OFPAT_OUTPUT = 0

# Instruction types
OFPIT_APPLY_ACTIONS = 4

# A couple of reserved ports (32-bit in 1.1)
OFPP_CONTROLLER = 0xfffffffd

# "send no buffered bytes to the controller"
OFPCML_NO_BUFFER = 0xffff


class ofp_action_output (object):
  """
  OFPAT_OUTPUT action.

  16 bytes in 1.1 -- the port grew to 32 bits, so there's a 6-byte pad to
  keep the 8-byte alignment.
  """
  def __init__ (self, port, max_len = 0):
    self.port = port
    self.max_len = max_len

  def pack (self):
    return struct.pack("!HHIH6x", OFPAT_OUTPUT, len(self),
                       self.port, self.max_len)

  def __len__ (self):
    return 16


class ofp_instruction (object):
  """
  Base for instructions.

  Like ofp_instruction in the spec (a shared type/len header), minus the
  padding -- same idea as ofp_action_base in libopenflow_01.
  """
  type = None


class ofp_instruction_actions (ofp_instruction):
  """
  OFPIT_APPLY_ACTIONS instruction.

  A 4-byte header, 4 bytes of pad, then the packed actions.  'len' covers
  everything, so it can only be filled in once the actions are packed
  """
  def __init__ (self, actions = None, type = OFPIT_APPLY_ACTIONS):
    self.type = type
    self.actions = actions if actions is not None else []

  def pack (self):
    body = b"".join(a.pack() for a in self.actions)
    return struct.pack("!HH4x", self.type, len(self)) + body

  def __len__ (self):
    return 8 + sum(len(a) for a in self.actions)


if __name__ == "__main__":
  # APPLY_ACTIONS { OUTPUT port 2 }
  instr = ofp_instruction_actions(actions=[ofp_action_output(port=2)])
  raw = instr.pack()
  print(len(raw), raw.hex())
  assert len(ofp_action_output(port=2)) == 16
  assert raw.hex() == "000400180000000000000010000000020000000000000000"
  assert len(instr) == 24
  assert len(raw) == len(instr)
