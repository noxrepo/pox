# Copyright 2012 Andreas Wundsam
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This module provides a MockSocket that can be used to fake TCP
connections inside of the simulator
"""

class MockSocket (object):
  """
  A mock socket that works on a sending and a receiving message channel.
  Use MockSocket.pair() to get a pair of connected MockSockets

  TODO: model failure modes
  """
  def __init__(self, receiving, sending):
    self.receiving = receiving
    self.sending = sending

  def send (self, data):
    """
    Send data out on this socket.
    
    Data will be available for reading at the receiving socket pair.
    Note that this currently always succeeds and never blocks (unlimited
    receive buffer size)
    """
    return self.sending.send(data)

  def recv (self, max_size=None):
    """
    receive data on this sockect.
    
    If no data is available to be received, return "".
    Note that this is non-standard socket behavior and should be
    changed to mimic either blocking on non-blocking socket semantics
    """
    return self.receiving.recv(max_size)

  def set_on_ready_to_recv (self, on_ready):
    """
    set a handler function on_ready(socket, size) to be called when
    data is available for reading at this socket
    """
    self.receiving.on_data = lambda channel, size: on_ready(self, size)

  def ready_to_recv (self):
    return not self.receiving.is_empty()

  def ready_to_send (self):
    return self.sending.is_full()

  def shutdown (self, sig=None):
    """
    shutdown a socket.
    Currently a no-op on this MockSocket object.
    """
    pass
    #TODO: implement more realistic closing semantics

  def close (self):
    """
    close a socket. Currently a no-op on this MockSocket object.
    """
    pass
    #TODO: implement more realistic closing semantics

  def fileno (self):
    """
    return the pseudo-fileno of this Mock Socket.
    Currently always returns -1.
    """
    return -1
    #TODO: assign unique pseudo-filenos to mock sockets,
    #      so apps don't get confused.

  @classmethod
  def pair (cls):
    """ Return a pair of connected sockets """
    a_to_b = MessageChannel()
    b_to_a = MessageChannel()
    a = cls(a_to_b, b_to_a)
    b = cls(b_to_a, a_to_b)
    return (a,b)

class MessageChannel (object):
  """
  A undirectional reliable in order byte stream message channel
  (think TCP half-connection)
  """
  def __init__ (self):
    # Single element queue
    self.buffer = ""
    self.on_data = None
    self.on_data_running = False
    self.pending_on_datas = 0

  def send (self, msg):
    self.buffer += msg
    self._trigger_on_data()
    return len(msg)

  def _trigger_on_data (self):
    self.pending_on_datas += 1
    if self.on_data_running:
      # avoid recursive calls to on_data
      return

    while self.pending_on_datas > 0 and len(self.buffer) > 0:
      self.pending_on_datas -= 1
      if self.on_data:
        self.on_data_running = True
        self.on_data(self, len(self.buffer))
        self.on_data_running = False
      else:
        break

  def recv (self, max_size=None):
    """
    retrieve and return the data stored in this channel's buffer.
    If buffer is empty, return ""
    """
    if max_size and max_size < len(self.buffer):
      msg = self.buffer[0:max_size]
      self.buffer = self.buffer[max_size:]
    else:
      msg = self.buffer
      self.buffer = ""
    return msg

  def is_empty (self):
    return len(self.buffer) == 0

  def is_full (self):
    #  buffer length not constrained currently
    return False

  def __len__ (self):
    return len(self.buffer)
