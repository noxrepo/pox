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

from pox.core import core
import logging
import string

def launch (__INSTANCE__=None, **kw):
  """
  Allows configuring log levels from the commandline.

  For example, to turn off the verbose web logging, try:
  pox.py web.webcore log.level --web.webcore=INFO
  """
  for k,v in kw.items():
    if v is True:
      # This means they did something like log.level --DEBUG
      v = k
      k = "" # Root logger
    try:
      v = int(v)
    except:
      old = v
      v = logging.DEBUG
      def dofail ():
        core.getLogger(k).error("Bad log level: %s. Defaulting to DEBUG.", old)

      if (len(old) == 0) or (len(old.strip(string.ascii_uppercase)) != 0):
        dofail()
      else:
        vv = getattr(logging, old, None)
        if not isinstance(vv, int):
          dofail()
        else:
          v = vv

    core.getLogger(k).setLevel(v)
