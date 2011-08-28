from distutils.core import setup, Extension
import os

kw = {}
if os.name == "nt":
  kw["include_dirs"] = ["WpdPack\\Include"]
  kw["library_dirs"] = ["WpdPack\\Lib"]
  kw["define_macros"] = [("WIN32", None)]
  kw["libraries"] = ["wpcap", "Packet"]
else:
  kw["libraries"] = ["pcap"]
  
main =  Extension("pxpcap",["pxpcap.cpp"],**kw)

setup (name = 'pxpcap',
       version = '1.0',
       description = 'pcap for Python',
       ext_modules = [main])
