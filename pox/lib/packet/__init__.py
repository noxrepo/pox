# Copyright 2011,2013 James McCauley
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
The POX packet library for packet parsing and creation.

This is based heavily on NOX's packet library, though it has undergone
some signficant change, particularly with regard to making packet
assembly easier.

Could still use more work.
"""

# None of this is probably that big, and almost all of it gets loaded
# under most circumstances anyway.  Let's just load all of it.
import arp as ARP
import dhcp as DHCP
import dns as DNS
import eap as EAP
import eapol as EAPOL
import ethernet as ETHERNET
import ipv4 as IPV4
import ipv6 as IPV6
import icmp as ICMP
import icmpv6 as ICMPV6
import lldp as LLDP
import tcp as TCP
import udp as UDP
import vlan as VLAN
import mpls as MPLS
import llc as LLC
import rip as RIP
import gre as GRE
import vxlan as VXLAN

from gre import *
from vxlan import *
from rip import *
from arp import *
from dhcp import *
from dns import *
from eap import *
from eapol import *
from ethernet import *
from ipv6 import *
from ipv4 import *
from icmpv6 import *
from icmp import *
from lldp import *
from tcp import *
from udp import *
from vlan import *
from mpls import *
from llc import *

__all__ = [
  'rip',
  'arp',
  'dhcp',
  'dns',
  'eap',
  'eapol',
  'ethernet',
  'ipv4',
  'ipv6',
  'icmp',
  'icmpv6',
  'lldp',
  'tcp',
  'tcp_opt',
  'udp',
  'vlan',
  'mpls',
  'llc',

  'RIP',
  'ARP',
  'DHCP',
  'DNS',
  'EAP',
  'EAPOL',
  'ETHERNET',
  'IPV4',
  'IPV6',
  'ICMP',
  'ICMPV6',
  'LLDP',
  'TCP',
  'UDP',
  'VLAN',
  'MPLS',
  'LLC',
]
