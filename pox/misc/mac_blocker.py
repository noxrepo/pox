# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Gives a GUI for blocking individual MAC addresses.

Meant to work with reactive components like l2_learning or l2_pairs.

Start with --no-clear-tables if you don't want to clear tables on changes.
"""

from pox.core import core
from pox.lib.revent import EventHalt
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of

from tkinter import *

# Sets of blocked and unblocked MACs
blocked = set()
unblocked = set()

# Listbox widgets
unblocked_list = None
blocked_list = None

# If True, clear tables on every block/unblock
clear_tables_on_change = True

def add_mac (mac):
  if mac.is_multicast: return
  if mac.is_bridge_filtered: return
  if mac in blocked: return
  if mac in unblocked: return
  unblocked.add(mac)
  core.tk.do(unblocked_list.insert, None, END, str(mac))

def packet_handler (event):
  # Note the two MACs
  add_mac(event.parsed.src)
  add_mac(event.parsed.dst)

  # Check for blocked MACs
  if event.parsed.src in blocked:
    return EventHalt
  if event.parsed.dst in blocked:
    return EventHalt

def get (l):
  """ Get an element from a listbox """
  try:
    i = l.curselection()[0]
    mac = l.get(i)
    return i,mac
  except:
    pass
  return None,None

def clear_flows ():
  """ Clear flows on all switches """
  for c in core.openflow.connections:
    d = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    c.send(d)

def move_entry (from_list, from_set, to_list, to_set):
  """ Move entry from one list to another """
  i,mac = get(from_list)
  if mac is None: return
  from_list.delete(i)
  to_list.insert(END, mac)
  mac = EthAddr(mac)
  to_set.add(mac)
  from_set.remove(mac)

  if clear_tables_on_change:
    # This is coming from another thread, so don't just send -- use
    # callLater so that it happens from the coop thread.
    core.callLater(clear_flows)

def do_block ():
  """ Handle clicks on block button """
  move_entry(unblocked_list, unblocked, blocked_list, blocked)

def do_unblock ():
  """ Handle clicks on unblock button """
  move_entry(blocked_list, blocked, unblocked_list, unblocked)

def setup ():
  """ Set up GUI """
  global unblocked_list, blocked_list
  top = Toplevel()
  top.title("MAC Blocker")

  # Shut down POX when window is closed
  top.protocol("WM_DELETE_WINDOW", core.quit)

  box1 = Frame(top)
  box2 = Frame(top)
  l1 = Label(box1, text="Allowed")
  l2 = Label(box2, text="Blocked")
  unblocked_list = Listbox(box1)
  blocked_list = Listbox(box2)
  l1.pack()
  l2.pack()
  unblocked_list.pack(expand=True,fill=BOTH)
  blocked_list.pack(expand=True,fill=BOTH)

  buttons = Frame(top)
  block_button = Button(buttons, text="Block >>", command=do_block)
  unblock_button = Button(buttons, text="<< Unblock", command=do_unblock)
  block_button.pack()
  unblock_button.pack()

  opts = {"side":LEFT,"fill":BOTH,"expand":True}
  box1.pack(**opts)
  buttons.pack(**{"side":LEFT})
  box2.pack(**opts)

  core.getLogger().debug("Ready")

def launch (no_clear_tables = False):
  global clear_tables_on_change
  clear_tables_on_change = not no_clear_tables

  def start ():
    core.openflow.addListenerByName("PacketIn",packet_handler,priority=1)
    core.tk.do(setup)

  core.call_when_ready(start, ['openflow','tk'])
