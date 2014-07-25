#!/usr/bin/env python

import urllib2
import inspect
import os
import sys
import string

### POX is one directory up from tools
_pox_root = os.path.dirname(os.path.dirname(os.path.abspath(inspect.stack()[0][1])))

resources = {}

resources["IEEE OUI Database"] = {
  "url" : "http://standards.ieee.org/develop/regauth/oui/oui.txt",
  "content" : None,
  "header" : "",
  "footer" : "",
  "outputfile" : "pox/lib/oui.txt"
}

resources["IANA IP Protocols Database"] = {
  "url" : "http://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv",
  "content" : None,
  "header" : """### See http://www.iana.org/assignments/protocol-numbers for details
### Permission to use this file does not constitute an endorsement of this
### software by IANA or ICANN""",
  "footer" : "",
  "outputfile" : "pox/lib/packet/protocol-numbers-1.csv"
}

for k in resources.keys():
  r = resources[k]

  ### split outputfile on /, then rejoin with os.sep before composing abspath
  o = os.sep.join(string.split(r["outputfile"],"/"))
  r["abspath"] = os.path.join(_pox_root,o)

  try:
    print "Writing [{0}] ...".format(k)
    u = urllib2.urlopen(r["url"])
    f = open(r["abspath"],"w")
    f.write(r["header"])
    f.write(u.read())
    f.write(r["footer"])
    f.close()

  except:
    print "Error writing ""{0}"" {1} ---> {2}".format(k,r["url"],r["abspath"])

  
