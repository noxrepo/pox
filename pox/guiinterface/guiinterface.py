"""
This is the communication interface between POX and the GUI.
The gui backend component acts as a proxy between other components and the GUI.

GUI --> POX component:
If we want to trigger component functionality through the GUI, the component
must exposes that functionality through its API. The "backend" should just call
that API when ith gets input from the GUI (for example, think monitoring).

POX component --> GUI
If the component wants to send something to the GUI, it just raises events.
The backend listens to those events and packs them up and sends them to the GUI.

Note: log messages are treated separately, and use their own communication
channel
"""

from pox.lib.revent.revent import *
from pox.lib.recoco.recoco import *
import pox.core
from pox.core import core as core
import json

log = pox.core.getLogger()
