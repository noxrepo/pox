from distutils.core import setup, Extension
import os

try:
  import __pypy__
  is_pypy = True
except:
  is_pypy = False


def make_args (selectable_fd = True):
  kw = {}
  macros = []
  kw["define_macros"] = macros
  if os.name == "nt":
    kw["include_dirs"] = ["WpdPack\\Include"]
    kw["library_dirs"] = ["WpdPack\\Lib"]
    kw["libraries"] = ["wpcap", "Packet"]
    macros.append(("WIN32", None))
  else:
    kw["libraries"] = ["pcap"]
    if selectable_fd:
      macros.append(("HAVE_PCAP_GET_SELECTABLE_FD", None))

  if is_pypy:
    macros.append(("NO_BYTEARRAYS", None))

  return kw


def attempt (**kwargs):
  kw = make_args(**kwargs)

  main = Extension("pxpcap",["pxpcap.cpp"],**kw)

  setup(name = 'pxpcap',
        version = '3.0',
        description = 'pcap for Python',
        ext_modules = [main])

try:
  attempt()
except:
  print("Trying again without selectable FD")
  attempt(selectable_fd = False)
