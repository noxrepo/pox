# Copyright (c) 2013 Felician Nemeth
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
A simple knowledgebase for querying apriori configuration.

The knowledgebase module stores some aspects of the intended
configuration of or other apriori information about the controlled
network.  (Whereas, for example, the topology module collects the
current/actual view of the network.)

It takes one "file" commandline argument, e.g.,
  knowledgebase --file=db.csv

Example of db.csv:
  hostname,ip,mac,dpid,routing
  h1,10.0.0.1,,,
  h2,10.0.0.2,22:22:22:22:22:22,,
  ,,3,forwarding.l2_learning
  ,,4,forwarding.hub

Knowledgebase stores values as strings.  Should type be specified in
the header row, e.g., "mac:EthAddr,ip:IPAddr,name:str"?

The file format is disputable (json, yaml, ...), but it might be a
good idea to be somewhat compatible with mininet (once mininet defines
its own format).  See: https://github.com/mininet/mininet/pull/157

In your code, you can query Knowledgebase like this:
  if hasattr(core, 'Knowledgebase'):
    result = core.Knowledgebase.query(ip='10.0.0.1')
  else:
    log.warn('knowledgebase is not loaded')
See Knowledgebase.query for details.

Knowledgebase is potentially used by:
  proto.dns_responder
"""

from csv import DictReader
from pox.core import core

log = core.getLogger()

class Knowledgebase ():
  def __init__ (self, file=None):
    self._filename=file
    self._db = {}
    self._read_db()

  def _read_db (self):
    """Read database from a CSV file."""
    try:
      with open(self._filename) as f:
        self._db = [d for d in DictReader(f)]
    except IOError as e:
      log.error('IOError:%s' % e)
    log.debug('db:%s' % self._db)

  def query (self, **kw):
    """
    Query the knowledgebase.  Returns a list of dictionaries that
    contains all the key-vaule pairs of 'kw'.  Examples:

    # simple query
    core.Knowledgebase.query(ip='10.0.0.1')

    # select one of many interfaces
    core.Knowledgebase.query(hostname='h1', ip='10.0.0.1')

    # or
    i = {'hostname': 'h1', 'ip': '10.0.0.1'}
    core.Knowledgebase.query(**i)
    """
    result = []
    for item in self._db:
      for k, v in kw.iteritems():
        if v != item.get(k):
          break
      else:
        result.append(item)

    # For the sake of extensibility, here we could emit a
    # KnowledgebaseQuery event asking other modules to append their
    # answers if they can.

    return result

def launch (file=None):
  core.registerNew(Knowledgebase, file)
