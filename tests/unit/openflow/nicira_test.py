# Copyright 2011-2013 James McCauley
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

import unittest
import sys
import os.path
sys.path.append(os.path.dirname(__file__) + "/../../..")

import pox.openflow.nicira as nx
from pox.lib.addresses import EthAddr, IPAddr
import pox.openflow.libopenflow_01 as of

class basics_test (unittest.TestCase):
  """
  Do some tests on the Nicira extensions

  This isn't totally comprehensive (that is, we don't currently try every
  combination of masked/unmasked, etc.  But it should serve as a basic
  sanity test.
  """
  longMessage = True

  # Add an _init_action_XXXX method to override action creation
  # (otherwise they're initialized with no arguments).
  def _init_action_nx_reg_move (self, cls):
    return cls(dst=nx.NXM_NX_REG1,src=nx.NXM_NX_REG2,nbits=3,src_ofs=2)

  def _init_action_nx_reg_load (self, cls):
    return cls(dst=nx.NXM_NX_REG3,value=42,nbits=16)

  def _init_action_nx_output_reg (self, cls):
    return cls(reg=nx.NXM_NX_TUN_ID,nbits=16)

  def _init_action_nx_action_resubmit (self, cls):
    # Use a factory method
    return cls.resubmit_table()

  def _init_action_nx_action_set_tunnel (self, cls):
    return cls(tun_id=101)

  def _init_action_nx_action_set_tunnel64 (self, cls):
    return cls(tun_id=101)

  def _init_action_nx_action_learn (self, cls):
    learn = self._make_learn_action()
    assert type(learn)==cls
    return learn

  def _init_action_nx_action_pop_mpls (self, cls):
    return cls(ethertype=101)

  def _init_action_nx_action_mpls_label (self, cls):
    return cls(label=0)

  def _init_action_nx_action_mpls_tc (self, cls):
    return cls(tc=0)

  def test_unpack_weird_header (self):
    """
    Test the unpacking of a header we don't have a class for
    """
    # Make a weird header...
    class nxm_weird (nx._nxm_maskable, nx._nxm_numeric_entry):
      _nxm_type = nx._make_type(0xdead,0x42)
      _nxm_length = 4
    original = nx.nx_reg_load(dst=nxm_weird,value=42,nbits=32)

    original_packed = original.pack()

    # Currently, the action unpacking API still sucks...
    unoriginal = nx.nx_reg_load()
    offset = unoriginal.unpack(original_packed, 0)
    self.assertEqual(offset, len(original_packed),
                     "Didn't unpack entire entry")
    unoriginal_packed = unoriginal.pack()

    self.assertEqual(unoriginal.dst.__name__, "NXM_UNKNOWN_dead_42",
                     "Didn't generate new class correctly?")

    self.assertEqual(original_packed, unoriginal_packed, "Pack/Unpack failed")


  def test_action_pack_unpack (self):
    """
    Pack and unpack a bunch of actions
    """
    for name in dir(nx):
      a = getattr(nx, name)
      if not nx._issubclass(a, of.ofp_action_vendor_base): continue
      print("Trying",name,"...", end=' ')
      init = getattr(self, "_init_action_" + name, lambda c: c())
      original = init(a)
      original_packed = original.pack()
      #print len(original_packed)

      # Currently, the action unpacking API still sucks...
      unoriginal = a()
      offset = unoriginal.unpack(original_packed, 0)
      self.assertEqual(offset, len(original_packed),
                       "Didn't unpack entire entry " + name)
      unoriginal_packed = unoriginal.pack()

      self.assertEqual(original, unoriginal,
                       "Pack/Unpack failed for " + name)
      print("Success!")


  def test_nxm_ip (self):
    """
    Test the check for nonzero bits of a masked entry
    """
    def try_bad ():
      e = nx.NXM_OF_IP_SRC(IPAddr("192.168.56.1"),IPAddr("255.255.255.0"))
      e.pack()
    self.assertRaisesRegexp(AssertionError, '^nonzero masked bits$',
        try_bad)


  def _make_learn_action (self):
    fms = nx.flow_mod_spec.new
    learn = nx.nx_action_learn(table_id=1,hard_timeout=10)
    learn.spec.append(fms( field=nx.NXM_OF_VLAN_TCI, n_bits=12 ))
    learn.spec.append(fms( field=nx.NXM_OF_ETH_SRC, match=nx.NXM_OF_ETH_DST ))
    learn.spec.append(fms( field=nx.NXM_OF_IN_PORT, output=True ))

    #learn.spec = [
    #    nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_OF_VLAN_TCI),
    #                     n_bits=12),
    #    nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_OF_ETH_SRC),
    #                     dst=nx.nx_learn_dst_match(nx.NXM_OF_ETH_DST)),
    #    nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_OF_IN_PORT),
    #                     dst=nx.nx_learn_dst_output())
    #]

    #learn.spec.chain(
    #  field=nx.NXM_OF_VLAN_TCI, n_bits=12).chain(
    #  field=nx.NXM_OF_ETH_SRC, match=nx.NXM_OF_ETH_DST).chain(
    #  field=nx.NXM_OF_IN_PORT, output=True)

    return learn


  def test_flow_mod_spec (self):
    """
    Check flow_mod_specs are correct

    Not comprehensive.
    """
    learn = self._make_learn_action()
    good = """00 0c 00 00 08 02 00 00  00 00 08 02 00 00
              00 30 00 00 04 06 00 00  00 00 02 06 00 00
              10 10 00 00 00 02 00 00""".split()
    good = bytes(int(x,16) for x in good)
    self.assertEqual(good, b''.join(x.pack() for x in learn.spec))


  def test_match_pack_unpack (self):
    """
    Pack and unpack a bunch of match entries
    """

    # Note that this does not currently really take into account constraints
    # on masks (e.g., EthAddr masks only having broadcast bit).

    for nxm_name,nxm_type in nx._nxm_name_to_type.items():
      nxm_class = nx._nxm_type_to_class[nxm_type]
      mask = None

      #print nxm_name

      # If more exotic nxm types are added (e.g., with different types for
      # values and masks), we'll need to add additional if statements here...
      if issubclass(nxm_class, nx._nxm_numeric_entry):
        value = 0x0a
        mask  = 0x0f
      elif issubclass(nxm_class, nx._nxm_numeric):
        value = 0x0a
      elif issubclass(nxm_class, nx._nxm_raw):
        value = 'aabb'
        # Currently never check mask for raw
      elif issubclass(nxm_class, nx._nxm_ipv6):
        import pox.lib.addresses as addresses
        #self.assertFalse('IPAddr6' in dir(addresses), 'IPv6 is available, '
        #                 'so this test needs to be fixed.')
        value = 'ff02::/126'
      elif issubclass(nxm_class, nx._nxm_ip):
        value = IPAddr('192.168.56.0')
        mask  = IPAddr('255.255.255.0')
      elif issubclass(nxm_class, nx._nxm_ether):
        value = EthAddr('01:02:03:04:05:06')
        # Currently never check mask for ether
      else:
        self.fail("Unsupported NXM type for " + nxm_name)

      if not issubclass(nxm_class, nx._nxm_maskable):
        mask = None

      original = nxm_class(value, mask)
      original_packed = original.pack()

      offset,unoriginal = nx.nxm_entry.unpack_new(original_packed, 0)
      self.assertEqual(offset, len(original_packed),
                       "Didn't unpack entire entry " + nxm_name)
      unoriginal_packed = unoriginal.pack()

      self.assertEqual(original, unoriginal,
                       "Pack/Unpack failed for " + nxm_name)


if __name__ == '__main__':
  unittest.main()
