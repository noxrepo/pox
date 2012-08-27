# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

from pox.core import core

def launch (**kw):
  """
  Allows configuring log levels from the commandline.

  For example, to turn off the verbose web logging, try:
  pox.py web.webcore log.level --web.webcore=INFO
  """
  for k,v in kw.iteritems():
    if v is True:
      # This means they did something like log.level --DEBUG
      v = k
      k = "" # Root logger
    core.getLogger(k).setLevel(v)

