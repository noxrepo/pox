"""
Allows configuring log levels from the commandline.

For example, to turn off the verbose web logging, try:
pox.py web.webcore log --web.webcore=INFO
"""
import core

def launch (**kw):
  for k,v in kw.iteritems():
    core.getLogger(k).setLevel(v)


