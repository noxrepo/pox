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
