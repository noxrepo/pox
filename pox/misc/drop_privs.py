# Copyright 2021 James McCauley
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
This component drops root privileges so that you can run POX as root to
allow it to create tap/tun devices, open reserved port numbers, etc.,
but then not continue running as root.
"""

from pox.core import core
import os
import pwd
import grp

log = core.getLogger()

def _drop (user="nobody", group="nogroup", umask=0o077):
  if os.getuid() != 0:
    log.info("Not root; nothing to do.")
    return

  os.umask(umask)
  os.setgroups([])
  os.setgid(grp.getgrnam(group).gr_gid)
  os.setuid(pwd.getpwnam(user).pw_uid)

  log.info("Dropped root privileges (user:%s group:%s umask:%s)",
           user, group, oct(umask))


def launch (user="nobody", group="nogroup", umask=0o077):
  """
  This component drops root privileges when POX goes up.
  """
  if isinstance(umask, str):
    conv = {"0x":16,"0o":8,"0b":2}.get(umask[:2], None)
    if conv is not None:
      umask = int(umask, conv)
    elif umask.startswith("0"):
      umask = int(umask, 8)
    else:
      umask = int(umask)

  def _handle_UpEvent (*args):
    _drop(user=user, group=group, umask=umask)

  core.add_listener(_handle_UpEvent)
