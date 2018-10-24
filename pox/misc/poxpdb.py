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
Allows making POX break into the PDB debugger

Send POX a SIGUSR1 signal and it'll jump into PDB.
"""

from pox.core import core
import signal
import pdb
import os

def _start_pdb (sig, frame):
  import pdb
  pdb.Pdb().set_trace(frame)



def launch ():
  core.getLogger().info("POX PID is %s", os.getpid())
  core.getLogger().debug("To send POX to PDB, use kill -USR1 %s", os.getpid())
  signal.signal(signal.SIGUSR1, _start_pdb)
