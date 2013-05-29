# Copyright 2012-2013 James McCauley
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
This is a very simple component which provides some kind of nice
log formatting.

It demonstrates launching another component (there should eventually
be a nice interface for doing this), and formatting color log messages.

Also, any arguments are passed to log.level, so you can use it as a
shortcut for that too.
"""

def launch (**kw):
  import pox.log.color
  pox.log.color.launch()
  import pox.log
  pox.log.launch(format="[@@@bold@@@level%(name)-23s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
  import pox.log.level
  pox.log.level.launch(**kw)
