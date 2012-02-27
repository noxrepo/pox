#!/usr/bin/env python

from fnmatch import fnmatchcase
import hashlib
from optparse import OptionParser
import sys
from os import path
import os
import re
import stat
from string import Template

SCRIPT_DIR=path.dirname(path.abspath(sys.modules['__main__'].__file__))
ROOT=path.abspath(path.join(SCRIPT_DIR,".."))
UNIT_TEST=path.join(ROOT, "tests/unit")

parser = OptionParser(usage="usage: %prog [--force] <module_glob> [<module_glob>...]",
    description="Generates skeleton unit tests for pox modules",
    epilog="Arguments:\nmodule_glob: fully qualified python module name, e.g., pox.openflow.topology. Supports shell-type globs, e.g., pox.openflow.*\n")
parser.add_option("-f", "--force", help="force overwriting existing unit tests, even when no valid autogeneration signature is found", action="store_true", dest="force", default=False)

(options, args) = parser.parse_args()

if len(args) == 0:
  parser.print_usage()
  exit(10)

modules=[]

for root, dirs, files in os.walk(ROOT):
  assert root.startswith(ROOT)
  root = root[len(ROOT)+1:]
  if not root.startswith("pox"): continue

  files = [f for f in files if f.endswith(".py")]
  #print root
  for f in files:
    packagename = root.replace(path.sep,".")
    modules.append(packagename + "." + f[:-3])

def mkdir(d):
  if not os.path.exists(d):
    print "mkdir %s" % d
    os.makedirs(d)
  else:
    print "mkdir %s [exists]" % d

template = Template(
"""#!/usr/bin/env python

import itertools
import os.path
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), *itertools.repeat("..", ${path_depth})))

from ${module} import *

class ${test_class_name}(unittest.TestCase):
  pass

""")

def generate_test(module):
  print "Generating test for module: %s" % module
  lastdot = module.rfind(".")
  package = module[0:lastdot] if lastdot > 0 else ""
  name = module[lastdot+1:]
  test_package = re.sub(r'^pox\.', '', package)

  dst_dir = path.join(UNIT_TEST, *test_package.split('.'))
  mkdir(dst_dir)
  camel_name = re.sub(r'(_|^)+(.)', lambda(m): m.group(2).upper(), name)
  test_class_name = camel_name + "Test"
  test_file = path.join(dst_dir, name + "_test.py")

  test = template.substitute( {
    'path_depth' : 1 + module.count("."),
    'module' : module,
    'test_class_name' : test_class_name
    })

  def sha1(msg):
    s = hashlib.sha1()
    s.update(msg)
    return s.hexdigest()

  sha1sum = sha1(test)
  hashed_test = re.sub(r'\n', "\n### auto generate sha1: "+sha1sum + "\n", test, 1)

  def write_test(update=False):
    with open(test_file, "w") as f:
      f.write(hashed_test)
      f.close()
    os.chmod(test_file, stat.S_IWUSR|stat.S_IRUSR|stat.S_IXUSR|stat.S_IXGRP|stat.S_IRGRP|stat.S_IXOTH|stat.S_IROTH)

  if not os.path.exists(test_file) or options.force:
    print "Creating test %s in %s" % (test_class_name, test_file)
    write_test()
  else:
    f = open(test_file, "r")
    existing = f.read()
    f.close()
    genline = existing.split("\n")[1]
    match = re.match(r'### auto generate sha1: ([a-f0-9]+)', genline)
    if match:
      read_sha1 =  match.group(1)
      existing_non_hashed = re.sub(r'\n[^\n]*\n', '\n', existing, 1)
      calculated_sha1 = sha1(existing_non_hashed)
      if read_sha1 == calculated_sha1:
        print "Updating test %s in %s" % (test_class_name, test_file)
        write_test(True)
      else:
        print "Test for %s in %s already exists (and sha1 sums don't match: %s<=>%s)" % (test_class_name, test_file, read_sha1, calculated_sha1)
    else:
      print "Test for %s in %s already exists (and not autogeneration sig found)" % (test_class_name, test_file)

for module in modules:
  if any(map(lambda(glob): fnmatchcase(module, glob), args)):
    generate_test(module)


