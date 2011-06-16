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
class BadPacket(Exception):
    "Bad packet data exception"
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class IncompletePacket(Exception):
    "Packet data incomplete"

    def __init__(self, l2):
        self.l2 = l2

    def __str__(self):
        return repr('')
