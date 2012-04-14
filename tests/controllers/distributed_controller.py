# Assumes you invoked with:
#  ./pox.py --script=tests.controllers.distributed_controller controllers.nom_server controllers.distributed_controller

# TODO: need a better way to specify dependencies

from pox.core import core

import time
import signal
import random

def sigint_handler(signum, frame):
  import os
  os._exit(signum)

signal.signal(signal.SIGINT, sigint_handler)

nom_client = core.components['Controller']

while True:
  # test read operation
  nom_client.nom.items()
  # test write operation 
  nom_client.nom[random.randint(0,100)] = random.randint(0,100)
  time.sleep(random.randint(0,4))
