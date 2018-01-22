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
Allows setting of config file global variables

Variables are specified with parameters, e.g., --key=value.
These can then be used in a config file with ${key}.

Global variables apply to all config files.
See also: config.var
"""

gvariables = {}

def launch (__INSTANCE__=None, **kw):
  for k,v in kw.items():
    gvariables[k] = v
