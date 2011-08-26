from distutils.core import setup, Extension

setup (name = 'pxpcap',
       version = '1.0',
       description = 'pcap for Python',
       ext_modules = [
         Extension("pxpcap",["pxpcap.cpp"],libraries=["pcap"])
       ])
