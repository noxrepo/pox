# Copyright 2011 James McCauley
# Copyright 2008 (C) Nicira, Inc.
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

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.

import logging
lg = logging.getLogger('packet')

from pox.lib.util import initHelper

class packet_base (object):
    """
    TODO: This description is somewhat outdated and should be fixed.

    Base class for packets.

    Classes that perform packet manipulation (parsing and contruction)
    should derive from this class.

    The general layout of such a subclass is as follows:

    class foo (packet_base):

        def __init__(data=None, prev=None):
          packet_base.__init__(self)

          # data: is the data for the packet as a "bytes" object.
          # prev: is a pointer to the previous header
          # which is expected to be of type packet_base
          self.parsed = False
          self.prev = prev

          # define field variables here
          self.bar = 0

          if arr != None:
              self.data = data # Phasing out?
              self.parse(data)

        def parse(self, data):
            # parse packet here and set member variables
            self.parsed = True # signal that packet was succesfully parsed

        def hdr(self, payload):
            # return fields as a string
            return struct.pack('!I',self.bar)

        def __str__(self):
            # optionally convert to human readable string
    """
    def __init__ (self):
        self.next = None
        self.prev = None
        self.parsed = False
        self.raw = None

    def _init (self, kw):
        if 'payload' in kw:
          self.set_payload(kw['payload'])
          del kw['payload']
        initHelper(self, kw)

    def msg(self, *args):
        """ Shortcut for logging """
        #TODO: Remove?
        lg.info(*args)

    def err(self, *args):
        """ Shortcut for logging """
        #TODO: Remove?
        lg.error(*args)

    def warn(self, *args):
        """ Shortcut for logging """
        #TODO: Remove?
        lg.warning(*args)

    def __nonzero__(self):
        return self.parsed is True

    def __len__(self):
        return len(self.pack())

    def __str__(self):
        return "%s: Undefined representation" % self.__class__.__name__

    def find(self, proto):
        """
        Find the specified protocol layer based on its class type or name.
        """
        if not isinstance(proto, str):
            proto = proto.__name__
        if self.__class__.__name__ == proto and self.parsed:
            return self
        else:
            if self.next and isinstance(self.next, packet_base):
                return self.next.find(proto)
            else:
                return None

    @property
    def payload (self):
        """
        The packet payload property.
        Reading this property is generally the same as the "next" field.
        Setting this generally sets this packet's "next" field, as well as
        setting the new payload's "prev" field to point back to its new
        container (the same as the set_payload() method).
        """
        return self.next

    @payload.setter
    def payload (self, new_payload):
      self.set_payload(new_payload)

    def set_payload(self, payload):
        '''
        Set the packet payload.  Expects bytes or a packet_base subclass.
        '''
        if isinstance(payload, packet_base):
            self.next    = payload
            payload.prev = self
        elif type(payload) == bytes:
            self.next = payload
        else:
            raise TypeError("payload must be string or packet subclass")

    def parse(self, raw):
        '''Override me with packet parsing code'''
        raise NotImplementedError("parse() not implemented")

    def pre_hdr(self):
        '''Override to prepare before payload is packed'''
        pass

    def hdr(self, payload):
        '''Override me to return packet headers'''
        raise NotImplementedError("hdr() not implemented")

    @classmethod
    def unpack (cls, raw, prev=None):
        return cls(raw=raw, prev=prev)

    def pack(self):
        '''Convert header and payload to bytes'''

        self.pre_hdr()

        if self.next == None:
            return self.hdr(b'')
        elif isinstance(self.next, packet_base):
            rest = self.next.pack()
        else:
            rest = self.next

        return self.hdr(rest) + rest
