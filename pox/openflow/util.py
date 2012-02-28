'''
Created on Feb 27, 2012

@author: rcs
'''

import pox.openflow.libopenflow_01 as of

# See "classes"
def make_type_to_class_table ():
  classes = {}
  max = -1
  d = of.__dict__
  for k in d.keys():
    if k.startswith('OFPT_'):
      c = 'ofp' + k[4:].lower()
      cls = (d[c])
      num = d[k]
      classes[num] = cls
      if num > max: max = num

  if len(classes) != max + 1:
    raise "Bad protocol to class mapping"

  return [classes[i] for i in range(0, max)]