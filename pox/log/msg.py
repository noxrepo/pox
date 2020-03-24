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
Logs a message

This is a simple module which just allows you to log messages.  It's
useful for putting in config files to explain what's going on and/or
show configuration information.

Example:
  [log.msg]
  level=WARN
  msg=This configuration is only known to work in Debian sid!
"""

import pox.core
import logging
import string

def get_level_by_name (level):
  try:
    return int(level)
  except Exception:
    pass

  if not isinstance(level, str):
    return None
  if (len(level) == 0) or (len(level.strip(string.ascii_uppercase)) != 0):
    return None

  l = getattr(logging, level, None)
  if not isinstance(l, int):
    return None
  return l


def launch (msg, level="INFO", logger=None, __INSTANCE__=None):
  """
  Logs a message
  """
  if logger:
    log = pox.core.core.getLogger(logger)
  else:
    log = pox.core.log

  level = get_level_by_name(level)
  if level is None: level = logging.CRITICAL

  log.log(level, "%s", msg)
