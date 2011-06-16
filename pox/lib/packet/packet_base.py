# Copyright 2008 (C) Nicira, Inc.
# 
# This file is part of NOX.
# 
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
# NOX packet model (Python)
#
# Classes that perform packet manipulation (parsing and contruction)
# should derive from class packet_base below. The general layout of
# a pasers is as follows:
#
# class foo (packet_base):
#
#     def __init__(arr=None, prev=None):
#       # arr: is either an array or a string of
#       # the data for the packet 
#       # prev: is a pointer to the previous header
#       # which is expected to be of type packet_base 
#       self.prev = prev
#       if type(arr) == type(''):
#           arr = array('B', arr)
#       
#       # define field variables here
#       self.bar = 0
#       if arr != None:
#           assert(type(arr) == array)
#           self.arr = arr
#           self.parse()
#
#     def parse(self):
#         # parse packet here and set member variables
#         self.parsed = True # signal that packet was succesfully parsed
#
#     def hdr(self):
#         # return fields as a string       
#         return struct.pack('!I',self.bar)
#
#     def __str__(self):
#         # optionally convert to human readable string
#         
#

import logging
lg = logging.getLogger('packet')

class packet_base:
    next = None 
    prev = None 
    parsed = False

    def msg(self, *args):
        lg.info(*args)

    def err(self, *args):
        lg.error(*args)

    def warn(self, *args):
        lg.warning(*args)

    def __nonzero__(self):
        return self.parsed == True

    def __len__(self):
        return len(self.tostring())

    def __str__(self):
        return "%s: Undefined representation" % self.__class__.__name__

    def find(self, proto):
        '''Find the specified protocol layer based on the class name'''
        if self.__class__.__name__ == proto and self.parsed:
            return self
        else:
            if self.next and isinstance(self.next, packet_base):
                return self.next.find(proto)
            else:
                return None

    def set_payload(self, payload):
        '''Set the packet payload.  Expects a string, array to packet of type packet_base'''
        if isinstance(payload, packet_base):
            self.next    = payload
            payload.prev = self 
        elif type(payload) == type(''):
            self.next = payload
        elif type(payload) == array.array:
            self.next = payload.tostring()
        else:    
            self.msg('warning, payload must be string, array or type packet_base')

    def parse(self):
        '''Override me with packet parsing code'''
        self.err('** error ** no parse method defined')

    def hdr(self):
        '''Override me to return packet headers'''
        self.err('** error ** no hdr method defined')
        return ''

    def tostring(self):
        '''Convert header and payload to str'''
        buf = self.hdr()

        if self.next == None:
            return buf
        elif isinstance(self.next, packet_base):    
            return ''.join((buf, self.next.tostring()))
        else:    
            return ''.join((buf, self.next))
