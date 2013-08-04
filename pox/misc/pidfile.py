# Copyright 2013 James McCauley
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
Component to create PID files for running POX as a service
"""

from pox.core import core

import os
import atexit

_files = set()
_first_init = False


def _del_pidfiles ():
  if not _files: return
  try:
    msg = "Cleaning up %i pidfile" % (len(_files),)
    if len(_files) != 1: msg += 's'
    log.debug(msg)
  except:
    pass

  for f in list(_files):
    shortname = f
    if os.path.abspath(os.path.basename(f)) == f:
      shortname = os.path.basename(f)
    try:
      os.remove(f)
    except:
      msg = "Couldn't delete pidfile '%s'" % (shortname,)
      try:
        log.exception(msg)
      except:
        print(msg)
    _files.remove(f)


def _handle_DownEvent (event):
  _del_pidfiles()


def launch (file, force = False, __INSTANCE__ = None):
  global log
  log = core.getLogger()

  absfile = os.path.abspath(file)

  if absfile in _files:
    log.warn("pidfile '%s' specified multiple times", file)
    return

  global _first_init

  if not _first_init:
    try:
      atexit.register(_del_pidfiles)
    except:
      log.info('atexit not available')
    core.addListenerByName("DownEvent", _handle_DownEvent)
    _first_init = True

  if os.path.exists(absfile) and not force:
    log.error("Aborting startup: pidfile '%s' exists "
              "(use --force to override)", file)
    return False

  try:
    f = open(absfile, 'w')
    f.write("%s\n" % (os.getpid(),))
  except:
    log.exception("Failed to create pidfile '%s'", file)
    return False
  f.close()

  _files.add(absfile)
