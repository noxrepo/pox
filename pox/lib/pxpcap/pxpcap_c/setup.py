from distutils.core import setup, Extension
import os


def make_args (selectable_fd = True):
  kw = {}
  if os.name == "nt":
    kw["include_dirs"] = ["WpdPack\\Include"]
    kw["library_dirs"] = ["WpdPack\\Lib"]
    kw["define_macros"] = [("WIN32", None)]
    kw["libraries"] = ["wpcap", "Packet"]
  else:
    kw["libraries"] = ["pcap"]
    if selectable_fd:
      kw["define_macros"] = [("HAVE_PCAP_GET_SELECTABLE_FD", None)]
  return kw


def attempt (**kwargs):
  kw = make_args(**kwargs)

  main = Extension("pxpcap",["pxpcap.cpp"],**kw)

  setup(name = 'pxpcap',
        version = '1.1',
        description = 'pcap for Python',
        ext_modules = [main])

try:
  attempt()
except:
  print "Trying again without selectable FD"
  attempt(selectable_fd = False)
