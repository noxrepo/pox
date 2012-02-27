#!/usr/bin/env python

import sys
from os import path
import os
DOC=path.dirname(path.abspath(sys.modules['__main__'].__file__))

ROOT=path.abspath(path.join(DOC,".."))

packages = {}

os.chdir(DOC)

if len(sys.argv) >= 2:
  force = sys.argv[1] == "-f"
else:
  force = False


for root, dirs, files in os.walk(ROOT):
  assert root.startswith(ROOT)
  root = root[len(ROOT)+1:]
  if not root.startswith("pox"): continue

  files = [f for f in files if f.endswith(".py")]
  #print root
  for f in files:
    packagename = root.replace(path.sep,".")
    if packagename not in packages:
      packages[packagename] = (root,[])
    packages[packagename][1].append(f[:-3])


def suck_file (filename):
  f = open(filename, "r")
  s = f.read()
  f.close()
  return s

def is_clean (filename):
  f = suck_file(filename).rstrip("\n")
  f,lastline = f.rsplit("\n",1)
  if lastline.startswith(".. md5 "):
    check = lastline[7:].strip().lower()
  else:
    return False
  c = md5(f)
  return c == check

def md5 (s):
  import hashlib
  return hashlib.md5(s).hexdigest()

def maybe_write (filename, s):
  assert s[-1] == "\n"
  s += "\n"
  s = s + ".. md5 " + md5(s) + "\n"

  if path.exists(filename):
    if not is_clean(filename):
      old = suck_file(filename)
      if old == s:
        # It's the same as we'd write if we could
        return True
      print "!",filename,"differs"
      if not force: return False
  print "  write",filename
  f = open(filename, "w")
  f.write(s)
  f.close()



def skeleton_module_base (filename, other_filename, package, module):
  o = ""
  title = module
  if title == "__init__":
    title = package
  else:
    title = package + "." + title
  o += "=" * len(title) + "\n"
  o += title + "\n"
  o += "=" * len(title) + "\n\n"

  o += ".. include :: _" + module + ".rst\n"
  maybe_write(filename, o)

def skeleton_module (filename, package, module):
  #print " ",package + "." + module,filename
  o = ""

  """
  title = module
  if title == "__init__":
    title = package
  else:
    title = package + "." + title
  
  o += "=" * len(title) + "\n"
  o += title + "\n"
  o += "=" * len(title) + "\n\n"
  """

  o += ".. automodule:: " + package + "." + module + "\n"
  o += "    :members:\n"
  o += "    :undoc-members:\n"
  o += "    :special-members:\n"
  o += "    :show-inheritance:\n"
  maybe_write(filename, o)

def skeleton_index (filename, package):
  #print " index",package
  o = ""
  o += ".. include :: __init__.rst\n"
  o += ".. include :: _toc.rst\n"
  maybe_write(filename, o)

def skeleton_toc (filename, package, modules):
  #print " TOC"
  o = ""
  o += ".. toctree::\n"
#  o += "   :maxdepth: 2\n\n"
  for m in modules:
    if m == "__init__": continue

    o += "   " + m + "\n"
  maybe_write(filename, o)

for package,(dirname,modules) in packages.iteritems():
  if not path.isdir(dirname):
    if path.exists(dirname):
      print dirname,"exists and is not a directory!"
      continue
    os.makedirs(dirname)

for package,(dirname,modules) in packages.iteritems():
  if not path.isdir(dirname):
    continue

  f = path.join(dirname,"_index.rst")
  skeleton_index(f,package)

  f = path.join(dirname,"_toc.rst")
  skeleton_toc(f,package, modules)

  for module in modules:
    real = path.join(dirname,module+".rst")
    f = path.join(dirname,"_"+module+".rst")
    skeleton_module(f,package,module)
    skeleton_module_base(real,f,package,module)
    #skeleton_module(real,package,module)

o = ""
o += ".. toctree::\n"
o += "   :maxdepth: 2\n\n"
keys = sorted(packages.keys())
for package in keys:
  (dirname,modules) = packages[package]
  if not path.isdir(dirname):
    continue
  o += "   "
  o += package
  o += " <"
  o += dirname + "/_index"
  o += ">\n"

maybe_write("_index.rst", o)

maybe_write("index.rst", ".. include :: _index.rst\n")
