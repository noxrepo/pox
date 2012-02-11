#!/usr/bin/env python

import sys
from os import path
import os
DOC=path.dirname(path.abspath(sys.modules['__main__'].__file__))

ROOT=path.abspath(path.join(DOC,".."))

packages = {}

os.chdir(DOC)

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




def skeleton_module (filename, package, module):
  print " ",package + "." + module
  f = open(filename, "w")

  title = module
  if title == "__init__":
    title = package
  else:
    title = package + "." + title
  f.write("=" * len(title) + "\n")
  f.write(title + "\n")
  f.write("=" * len(title) + "\n\n")

  f.write(".. automodule:: " + package + "." + module + "\n")
  f.write("    :members:\n")
  f.close()

def skeleton_index (filename, package):
  print " index",package
  f = open(filename, "w")
  f.write(".. include:: __init__.rst\n")
  f.write(".. include:: _toc.rst\n")

def skeleton_toc (filename, package, modules):
  print " TOC"
  f = open(filename, "w")
  f.write(".. toctree::\n")
#  f.write("   :maxdepth: 2\n\n")
  for m in modules:
    f.write("   ")
    f.write(m)
    f.write("\n")
  f.close()

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
  if not path.exists(f):
    skeleton_index(f,package)

  f = path.join(dirname,"_toc.rst")
  if not path.exists(f):
    skeleton_toc(f,package, modules)

  for module in modules:
    f = path.join(dirname,module+".rst")
    if not path.exists(f):
      skeleton_module(f,package,module)

f = file("index.rst", "w")
f.write(".. toctree::\n")
f.write("   :maxdepth: 2\n\n")
keys = sorted(packages.keys())
for package in keys:
  (dirname,modules) = packages[package]
  if not path.isdir(dirname):
    continue
  f.write("   ")
  f.write(package)
  f.write(" <")
  f.write(dirname + "/_index")
  f.write(">\n")
  """
  for m in modules:
    f.write("   ")
    f.write(package + "." + m)
    f.write(" <")
    f.write(dirname + "/" + m)
    f.write(">\n")
  """
f.close()
