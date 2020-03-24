# Copyright 2013 James McCauley
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
A total unstructured mishmash which leads to a telnet server

There's stuff in here for curses, line editing, the socket server, telnet
option negotiation and so on.  No particular claims of completeness,
bug-freeness, or anything else.

You can implement your own telnet servers by creating a TelnetServer instance
and passing it your own subclass of TelnetPersonality.

The default personality provides a Python prompt, similar to the "py"
component (but remote, multi-instance, and executing cooperatively).
"""

from pox.core import core
from pox.lib.ioworker.workers import *
from pox.lib.ioworker import *
from pox.lib.revent import *

from collections import defaultdict


# IOLoop for our IO workers
_ioloop = None

# Log
log = None


def _chr (opt):
  """
  A more permissive chr()

  Like chr(), but if the value is already a string, simply returns it.
  """
  if isinstance(opt, bytes):
    return opt
  else:
    return bytes([opt])


def _ctrl (char):
  """
  Makes a control character

  Give it a string like "J" and it'll return b'\n'
  """
  return bytes([char.encode()[0] - 64])


def _process_caps (caps):
  """
  Process textual lists of curses caps into list of pairs
  """
  return [(x.strip().split()) for x in caps.strip().split("\n")]


# I don't know a way to get these via Python's curses when you're not actually
# *using* curses, so I'm including them here.
_curses_str_caps = _process_caps("""
  acs_chars                               acsc
  back_tab                                cbt
  bell                                    bel
  carriage_return                         cr
  change_char_pitch                       cpi
  change_line_pitch                       lpi
  change_res_horz                         chr
  change_res_vert                         cvr
  change_scroll_region                    csr
  char_padding                            rmp
  clear_all_tabs                          tbc
  clear_margins                           mgc
  clear_screen                            clear
  clr_bol                                 el1
  clr_eol                                 el
  clr_eos                                 ed
  column_address                          hpa
  command_character                       cmdch
  create_window                           cwin
  cursor_address                          cup
  cursor_down                             cud1
  cursor_home                             home
  cursor_invisible                        civis
  cursor_left                             cub1
  cursor_mem_address                      mrcup
  cursor_normal                           cnorm
  cursor_right                            cuf1
  cursor_to_ll                            ll
  cursor_up                               cuu1
  cursor_visible                          cvvis
  define_char                             defc
  delete_character                        dch1
  delete_line                             dl1
  dial_phone                              dial
  dis_status_line                         dsl
  display_clock                           dclk
  down_half_line                          hd
  ena_acs                                 enacs
  enter_alt_charset_mode                  smacs
  enter_am_mode                           smam
  enter_blink_mode                        blink
  enter_bold_mode                         bold
  enter_ca_mode                           smcup
  enter_delete_mode                       smdc
  enter_dim_mode                          dim
  enter_doublewide_mode                   swidm
  enter_draft_quality                     sdrfq
  enter_insert_mode                       smir
  enter_italics_mode                      sitm
  enter_leftward_mode                     slm
  enter_micro_mode                        smicm
  enter_near_letter_quality               snlq
  enter_normal_quality                    snrmq
  enter_protected_mode                    prot
  enter_reverse_mode                      rev
  enter_secure_mode                       invis
  enter_shadow_mode                       sshm
  enter_standout_mode                     smso
  enter_subscript_mode                    ssubm
  enter_superscript_mode                  ssupm
  enter_underline_mode                    smul
  enter_upward_mode                       sum
  enter_xon_mode                          smxon
  erase_chars                             ech
  exit_alt_charset_mode                   rmacs
  exit_am_mode                            rmam
  exit_attribute_mode                     sgr0
  exit_ca_mode                            rmcup
  exit_delete_mode                        rmdc
  exit_doublewide_mode                    rwidm
  exit_insert_mode                        rmir
  exit_italics_mode                       ritm
  exit_leftward_mode                      rlm
  exit_micro_mode                         rmicm
  exit_shadow_mode                        rshm
  exit_standout_mode                      rmso
  exit_subscript_mode                     rsubm
  exit_superscript_mode                   rsupm
  exit_underline_mode                     rmul
  exit_upward_mode                        rum
  exit_xon_mode                           rmxon
  fixed_pause                             pause
  flash_hook                              hook
  flash_screen                            flash
  form_feed                               ff
  from_status_line                        fsl
  goto_window                             wingo
  hangup                                  hup
  init_1string                            is1
  init_2string                            is2
  init_3string                            is3
  init_file                               if
  init_prog                               iprog
  initialize_color                        initc
  initialize_pair                         initp
  insert_character                        ich1
  insert_line                             il1
  insert_padding                          ip
  key_a1                                  ka1
  key_a3                                  ka3
  key_b2                                  kb2
  key_backspace                           kbs
  key_beg                                 kbeg
  key_btab                                kcbt
  key_c1                                  kc1
  key_c3                                  kc3
  key_cancel                              kcan
  key_catab                               ktbc
  key_clear                               kclr
  key_close                               kclo
  key_command                             kcmd
  key_copy                                kcpy
  key_create                              kcrt
  key_ctab                                kctab
  key_dc                                  kdch1
  key_dl                                  kdl1
  key_down                                kcud1
  key_eic                                 krmir
  key_end                                 kend
  key_enter                               kent
  key_eol                                 kel
  key_eos                                 ked
  key_exit                                kext
  key_f0                                  kf0
  key_f1                                  kf1
  key_f10                                 kf10
  key_f11                                 kf11
  key_f12                                 kf12
  key_f13                                 kf13
  key_f14                                 kf14
  key_f15                                 kf15
  key_f16                                 kf16
  key_f17                                 kf17
  key_f18                                 kf18
  key_f19                                 kf19
  key_f2                                  kf2
  key_f20                                 kf20
  key_f21                                 kf21
  key_f22                                 kf22
  key_f23                                 kf23
  key_f24                                 kf24
  key_f25                                 kf25
  key_f26                                 kf26
  key_f27                                 kf27
  key_f28                                 kf28
  key_f29                                 kf29
  key_f3                                  kf3
  key_f30                                 kf30
  key_f31                                 kf31
  key_f32                                 kf32
  key_f33                                 kf33
  key_f34                                 kf34
  key_f35                                 kf35
  key_f36                                 kf36
  key_f37                                 kf37
  key_f38                                 kf38
  key_f39                                 kf39
  key_f4                                  kf4
  key_f40                                 kf40
  key_f41                                 kf41
  key_f42                                 kf42
  key_f43                                 kf43
  key_f44                                 kf44
  key_f45                                 kf45
  key_f46                                 kf46
  key_f47                                 kf47
  key_f48                                 kf48
  key_f49                                 kf49
  key_f5                                  kf5
  key_f50                                 kf50
  key_f51                                 kf51
  key_f52                                 kf52
  key_f53                                 kf53
  key_f54                                 kf54
  key_f55                                 kf55
  key_f56                                 kf56
  key_f57                                 kf57
  key_f58                                 kf58
  key_f59                                 kf59
  key_f6                                  kf6
  key_f60                                 kf60
  key_f61                                 kf61
  key_f62                                 kf62
  key_f63                                 kf63
  key_f7                                  kf7
  key_f8                                  kf8
  key_f9                                  kf9
  key_find                                kfnd
  key_help                                khlp
  key_home                                khome
  key_ic                                  kich1
  key_il                                  kil1
  key_left                                kcub1
  key_ll                                  kll
  key_mark                                kmrk
  key_message                             kmsg
  key_move                                kmov
  key_next                                knxt
  key_npage                               knp
  key_open                                kopn
  key_options                             kopt
  key_ppage                               kpp
  key_previous                            kprv
  key_print                               kprt
  key_redo                                krdo
  key_reference                           kref
  key_refresh                             krfr
  key_replace                             krpl
  key_restart                             krst
  key_resume                              kres
  key_right                               kcuf1
  key_save                                ksav
  key_sbeg                                kBEG
  key_scancel                             kCAN
  key_scommand                            kCMD
  key_scopy                               kCPY
  key_screate                             kCRT
  key_sdc                                 kDC
  key_sdl                                 kDL
  key_select                              kslt
  key_send                                kEND
  key_seol                                kEOL
  key_sexit                               kEXT
  key_sf                                  kind
  key_sfind                               kFND
  key_shelp                               kHLP
  key_shome                               kHOM
  key_sic                                 kIC
  key_sleft                               kLFT
  key_smessage                            kMSG
  key_smove                               kMOV
  key_snext                               kNXT
  key_soptions                            kOPT
  key_sprevious                           kPRV
  key_sprint                              kPRT
  key_sr                                  kri
  key_sredo                               kRDO
  key_sreplace                            kRPL
  key_sright                              kRIT
  key_srsume                              kRES
  key_ssave                               kSAV
  key_ssuspend                            kSPD
  key_stab                                khts
  key_sundo                               kUND
  key_suspend                             kspd
  key_undo                                kund
  key_up                                  kcuu1
  keypad_local                            rmkx
  keypad_xmit                             smkx
  lab_f0                                  lf0
  lab_f1                                  lf1
  lab_f10                                 lf10
  lab_f2                                  lf2
  lab_f3                                  lf3
  lab_f4                                  lf4
  lab_f5                                  lf5
  lab_f6                                  lf6
  lab_f7                                  lf7
  lab_f8                                  lf8
  lab_f9                                  lf9
  label_format                            fln
  label_off                               rmln
  label_on                                smln
  meta_off                                rmm
  meta_on                                 smm
  micro_column_address                    mhpa
  micro_down                              mcud1
  micro_left                              mcub1
  micro_right                             mcuf1
  micro_row_address                       mvpa
  micro_up                                mcuu1
  newline                                 nel
  order_of_pins                           porder
  orig_colors                             oc
  orig_pair                               op
  pad_char                                pad
  parm_dch                                dch
  parm_delete_line                        dl
  parm_down_cursor                        cud
  parm_down_micro                         mcud
  parm_ich                                ich
  parm_index                              indn
  parm_insert_line                        il
  parm_left_cursor                        cub
  parm_left_micro                         mcub
  parm_right_cursor                       cuf
  parm_right_micro                        mcuf
  parm_rindex                             rin
  parm_up_cursor                          cuu
  parm_up_micro                           mcuu
  pkey_key                                pfkey
  pkey_local                              pfloc
  pkey_xmit                               pfx
  plab_norm                               pln
  print_screen                            mc0
  prtr_non                                mc5p
  prtr_off                                mc4
  prtr_on                                 mc5
  pulse                                   pulse
  quick_dial                              qdial
  remove_clock                            rmclk
  repeat_char                             rep
  req_for_input                           rfi
  reset_1string                           rs1
  reset_2string                           rs2
  reset_3string                           rs3
  reset_file                              rf
  restore_cursor                          rc
  row_address                             vpa
  save_cursor                             sc
  scroll_forward                          ind
  scroll_reverse                          ri
  select_char_set                         scs
  set_attributes                          sgr
  set_background                          setb
  set_bottom_margin                       smgb
  set_bottom_margin_parm                  smgbp
  set_clock                               sclk
  set_color_pair                          scp
  set_foreground                          setf
  set_left_margin                         smgl
  set_left_margin_parm                    smglp
  set_right_margin                        smgr
  set_right_margin_parm                   smgrp
  set_tab                                 hts
  set_top_margin                          smgt
  set_top_margin_parm                     smgtp
  set_window                              wind
  start_bit_image                         sbim
  start_char_set_def                      scsd
  stop_bit_image                          rbim
  stop_char_set_def                       rcsd
  subscript_characters                    subcs
  superscript_characters                  supcs
  tab                                     ht
  these_cause_cr                          docr
  to_status_line                          tsl
  tone                                    tone
  underline_char                          uc
  up_half_line                            hu
  user0                                   u0
  user1                                   u1
  user2                                   u2
  user3                                   u3
  user4                                   u4
  user5                                   u5
  user6                                   u6
  user7                                   u7
  user8                                   u8
  user9                                   u9
  wait_tone                               wait
  xoff_character                          xoffc
  xon_character                           xonc
  zero_motion                             zerom
""")

_curses_bool_caps = _process_caps("""
  auto_left_margin                        bw
  auto_right_margin                       am
  back_color_erase                        bce
  can_change                              ccc
  ceol_standout_glitch                    xhp
  col_addr_glitch                         xhpa
  cpi_changes_res                         cpix
  cr_cancels_micro_mode                   crxm
  dest_tabs_magic_smso                    xt
  eat_newline_glitch                      xenl
  erase_overstrike                        eo
  generic_type                            gn
  hard_copy                               hc
  hard_cursor                             chts
  has_meta_key                            km
  has_print_wheel                         daisy
  has_status_line                         hs
  hue_lightness_saturation                hls
  insert_null_glitch                      in
  lpi_changes_res                         lpix
  memory_above                            da
  memory_below                            db
  move_insert_mode                        mir
  move_standout_mode                      msgr
  needs_xon_xoff                          nxon
  no_esc_ctlc                             xsb
  no_pad_char                             npc
  non_dest_scroll_region                  ndscr
  non_rev_rmcup                           nrrmc
  over_strike                             os
  prtr_silent                             mc5i
  row_addr_glitch                         xvpa
  semi_auto_right_margin                  sam
  status_line_esc_ok                      eslok
  tilde_glitch                            hz
  transparent_underline                   ul
  xon_xoff                                xon
""")


import curses

class CursesCodes (object):

  @staticmethod
  def strip_timing (v):
    o = b''
    i = 0
    swallow = False
    while i < len(v):
      c = v[i:i+1]
      nc = v[i+1:i+2] if i+1 < len(v) else b''

      if swallow:
        i += 1
        if c == b'>':
          swallow = False
        continue

      if c == b'$' and nc == b'$':
        if not swallow: o += b'$'
        i += 2
        continue
      elif c == b'$' and nc == b'<':
        swallow = True
        i += 2
        continue

      o += c
      i += 1

    return o

  def __init__ (self, term = "vt100"):
    try:
      curses.setupterm(term)
    except:
      # Sleazy, but let's try...
      oldout = sys.stdout
      sys.stdout = sys.__stdout__
      try:
        curses.setupterm(term)
      finally:
        sys.stdout = oldout

    self._code_to_name = {} # code -> short,long
    caps = []
    # We should do something better for ones with parameters...
    for desc,n in _curses_str_caps:
      v = curses.tigetstr(n)
      if v is None:
        setattr(self, n, None)
      else:
        v = self.strip_timing(v)
        setattr(self, n, v)
        #print n,repr(v)

        if desc.startswith('key_'): caps.append(v)
        self._code_to_name[v] = n,desc
        #print n,repr(v)

    # Get all prefixes
    self._kprefixes = {} # chars -> False if prefix, True if complete
    for cap in caps:
      self.add_key(cap)

  def add_key (self, cap, fake=False):
      for c in (cap[:n] for n in range(1, len(cap))):
        #print repr(c)
        #assert self._prefixes.get(c,False) is not True,"%s %s" % (self.get_name(cap),repr(c))
        if c not in self._kprefixes:
          self._kprefixes[c] = False
      #print repr(cap), "<<"
      self._kprefixes[cap] = True
      if fake:
        try:
          n,desc = fake
        except:
          n,desc = fake,fake
        self._code_to_name[cap] = n,desc

  def check_key (self, data):
    """
    Checks if data is a key sequence

    Returns True if yes, False if no, None if indeterminate.
    If indeterminate, you should add more data.
    """
    #print repr(data)
    #print [x.replace("\x1b","$") for x in self._prefixes.keys()]
    r = self._kprefixes.get(data)
    if r is True: return True
    if r is False: return None
    if r is None: return False
    raise RuntimeError()

  def get_name (self, code):
    if code not in self._code_to_name:
      return "unnamed"
    return self._code_to_name[code][0]

  def get_long_name (self, code):
    if code not in self._code_to_name:
      return "unnamed"
    return self._code_to_name[code][1]


class ServerWorker (TCPServerWorker, RecocoIOWorker):
  """
  Worker to accept connections
  """
  pass


class StateMachine (object):
  """
  Generic state machine framework

  Implement states as functions like _state_NAME.
  When exiting a state, _exit_state(old, new) is called as
  well as _exit_OLD-NAME(old, new) if it exists.
  When entering a state, _enter_state(old, new) and
  _enter_NEW-NAME(old, new) are called.

  Set the ._state property to switch states.  If done while
  in a state handler, this will cause the new state to be
  run immediately.

  If a state handler returns True, the state handler will be
  run again.

  _process() runs the state machine.
  """
  _cur_state = None

  def _enter_state (self, old_state, new_state):
    pass

  def _exit_state (self, old_state, new_state):
    pass

  @property
  def _state (self):
    return self._cur_state

  @_state.setter
  def _state (self, new_state):
    if self._cur_state:
      n = self._cur_state.__name__
      assert n.startswith('_state_')
      n = n[7:]
      f = getattr(self, '_exit_' + n, None)
      if f:
        f(self._cur_state, new_state)
    self._exit_state(self._cur_state, new_state)
    old = self._cur_state
    self._cur_state = new_state
    self._enter_state(old, new_state)
    n = self._cur_state.__name__
    assert n.startswith('_state_')
    n = n[7:]
    f = getattr(self, '_enter_' + n, None)
    if f:
      f(old, new_state)

  def _process (self):
    if self._cur_state is None:
      self._cur_state = getattr(self, '_state_default')
      self._enter_state(None, self._cur_state)

    while True:
      pre = self._state
      r = self._state()
      post = self._state
      if pre != post: continue
      if r: continue
      break


# Command char -> (name, desc)
_codename = {}

# Option char -> name
_optname = {}

def _make_consts ():
  c = """IAC, DONT, DO, WONT, WILL, SE (Subnegotiation End),
    NOP (No Operation), DM (Data Mark), BRK (Break), IP (Interrupt process),
    AO (Abort output), AYT (Are You There), EC (Erase Character),
    EL (Erase Line), GA (Go Ahead), SB (Subnegotiation Begin)"""
  cmds = [x.strip() for x in c.split(",")]
  import telnetlib
  global _codename
  for c in cmds:
    c = c.split(None, 1)
    dsc = c[0]
    if len(c) > 1: dsc = c[1][1:-1].replace(" ","")
    c = c[0]
    v = getattr(telnetlib, c)
    globals()[c] = v
    _codename[v] = c,dsc

  # Add some options from the telnet lib
  opts = "TTYPE SGA LINEMODE BINARY ECHO SUPPRESS_LOCAL_ECHO"
  opts = opts.split()
  for o in opts:
    v = getattr(telnetlib, o)
    globals()[o] = v
    _optname[v] = o

#  for k,v in vars(telnetlib).iteritems():
#    if k == k.upper():
#      if isinstance(v, basestring):
#        if len(v) == 1:
#          globals()[k] = v

_make_consts()


# Used by TTYPE
IS = _chr(0)
SEND = _chr(1)


# Handy definitions
ESC = _chr(27)
BELL = _chr(7)

# RFC1143 stuff
WANTYES = object()
WANTNO = object()
YES = object()
NO = object()
EMPTY = object()
OPPOSITE = object()


class TelnetHandler (StateMachine):
  def __init__ (self):
    super(TelnetHandler,self).__init__()
    self.__buf = b''

  def _rx_telnet (self, msg):
    #self.log.info(" ".join("%02x" % (ord(x),) for x in msg))
    print(" ".join("%02x" % (x,) for x in msg), end=' ')

  @property
  def log (self):
    """
    Get something that can be used to log messages.

    Overridable.
    """
    class O (object):
      pass
    def pr (fmt, *args):
      print(fmt % args)
    def nopr (*args):
      pass
    o = O()
    o.warn = nopr
    o.debug = nopr
    o.error = nopr
    o.info = nopr

    #o.warn = pr
    #o.debug = pr
    #o.error = pr
    #o.info = pr
    return o

  def __unread (self, data):
    self.__buf = data + self.__buf

  def __read (self, c=1):
    r = self.__buf[:c]
    self.__buf = self.__buf[c:]
    return r

  def _state_default (self):
    data = b''
    while True:
      r = self.__read()
      if r == b'':
        break
      if r == IAC:
        self._state = self._state_iac
        return True
      data += r
    self._rx_telnet(data)

  def _state_iac (self):
    r = self.__read()
    if r == b'': return
    if r == NOP:
      pass
    elif r == BRK:
      self._break()
    elif r == AO:
      self._abort_output()
    elif r == AYT:
      self._are_you_there()
    elif r == EC:
      self._erase_character()
    elif r == EL:
      self._erase_line()
    elif r == GA:
      self._go_ahead()
    elif r == IAC:
      self._rx_telnet(r)
    elif r in (WILL, WONT, DO, DONT):
      opt = self.__read()
      if opt == b'':
        # Try again later
        self.__unread(r)
        return
      #opt = ord(opt)
      if r == WILL:
        self._handle_will(opt)
      elif r == WONT:
        self._handle_wont(opt)
      elif r == DO:
        self._handle_do(opt)
      elif r == DONT:
        self._handle_dont(opt)
      self.log.debug("%s %s", _codename[r][1],_optname.get(opt,opt))
    elif r == SB:
      self._state = self._state_sb
      return
    else:
      self._error("Unknown command: %08x", r)
      return

    self._state = self._state_default

  def _state_error (self):
    """
    State for when we don't know what to do.

    We never recover from this state -- the conneciton is dead.
    """
    pass

  def _error (self, msg):
    """
    Called when there is an error processing the stream
    """
    self.log.error("ERROR: " + msg)
    self._state = self._state_error

  def _state_sb (self):
    """
    State during subnegotiation
    """
    b = self.__buf
    o = b''
    i = 0
    while i < len(b):
      c = b[i:i+1]
      n = b[i+1:i+2]
      if c == IAC:
        if n == IAC:
          i += 2
          o += IAC
          continue
        elif n == SE:
          # Yay!
          self._sb(o)
          self.__buf = self.__buf[i+2:]
          self._state = self._state_default
          return
      o += c
      i += 1
    return

  def _sb (self, sub):
    """
    Called after receiving subnegotiation information
    """
    s = "[SB|"
    s += " ".join("%02x" % (x,) for x in sub)
    s += "|" + repr(sub) + "]"
    self.log.debug(s)

  def _break (self):
    """
    Called when we recieve a telnet BREAK
    """
    pass

  def _abort_output (self):
    """
    Called when we recieve a telnet AO
    """
    pass

  def _are_you_there (self):
    """
    Called when we recieve a telnet AYT
    """
    self.send("(Yes, I'm here.)\n\r")

  def _erase_character (self):
    """
    Called when we recieve a telnet erase character command
    """
    pass

  def _erase_line (self):
    """
    Called when we recieve a telnet erase line command
    """
    pass

  def _go_ahead (self):
    """
    Called when we recieve a telnet GA
    """
    pass

  def _handle_do (self, opt):
    """
    Called when we recieve a telnet DO
    """
    pass

  def _handle_dont (self, opt):
    """
    Called when we recieve a telnet DONT
    """
    pass

  def _handle_will (self, opt):
    """
    Called when we recieve a telnet WILL
    """
    pass

  def _handle_wont (self, opt):
    """
    Called when we recieve a telnet WONT
    """
    pass

  def push (self, data):
    """
    Pushes telnet stream data in
    """
    self.__buf += data
    self._process()

  def startup (self):
    """
    Should be called when stream is starting
    """
    super(TelnetHandler,self).startup()
    pass

  def send_do (self, opt):
    self.log.debug(">DO %s", _optname.get(opt, opt))
    self.send(IAC + DO + _chr(opt))

  def send_dont (self, opt):
    self.log.debug(">DONT %s", _optname.get(opt, opt))
    self.send(IAC + DONT + _chr(opt))

  def send_will (self, opt):
    self.log.debug(">WILL %s", _optname.get(opt, opt))
    self.send(IAC + WILL + _chr(opt))

  def send_wont (self, opt):
    self.log.debug(">WONT %s", _optname.get(opt, opt))
    self.send(IAC + WONT + _chr(opt))


class QTelnetHandler (TelnetHandler):
  """
  TelnetHandler subclass which implements RFC1143 (mostly)

  This is also known as "the Q method".  This implementation could be cleaner,
  and I'm also not positive it's correct.  It's not one of the clearer RFCs,
  and I don't feel like spending TOO much time on telnet right now. :)

  RFC1143 discusses how to handle telnet option negotiation in such a way as
  to not cause loops.  This attempts to implement what it says using the
  single queue model (extension to multiple would be nice).

  us/usq/him/himq are the states described in the RFC.

  _can_he_enable and _can_he_disable can be overridden in subclasses to
  control how to respond to suggestions from the other side.

  _ask_for and _ask_for_not allow us to ask the other side to enable
  some option.

  _ask_to and _ask_to_not allow us to indicate to the other side that we
  want to enable some option.
  """

  def __init__ (self, **kw):
    self.us = defaultdict(lambda: NO)
    self.usq = defaultdict(lambda: EMPTY)
    self.him = defaultdict(lambda: NO)
    self.himq = defaultdict(lambda: EMPTY)
    super(QTelnetHandler,self).__init__(**kw)

  def _can_he_enable (self, opt):
    """
    Is called when other side wants to enable an option.

    Returning True means we'll accept the other side's suggestion.

    Overridable.
    """
    return True

  def _can_he_disable (self, opt):
    """
    Is called when other side wants to disable an option.

    Returning True means we'll accept the other side's suggestion.

    Overridable.
    """
    return True

  def _can_we_enable (self, opt):
    """
    Is called when other side wants us to enable an option.

    Returning True means we'll accept the other side's suggestion.

    Overridable.
    """
    return True

  def _can_we_disable (self, opt):
    """
    Is called when other side wants us to disable an option.

    Returning True means we'll accept the other side's suggestion.

    Overridable.
    """
    return True

  def _notify_us (self, opt, enabled):
    """
    Called when we switch state

    Overridable.
    """
    pass

  def _notify_him (self, opt, enabled):
    """
    Called when the other side switches state

    Overridable.
    """
    pass

  def _handle_will (self, opt):
    """
    Handle WILL commands according to RF1143
    """
    if self.him[opt] == NO:
      if self._can_he_enable(opt):
        self.him[opt] = YES
        self.send_do(opt)
        self._notify_him(opt, True)
      else:
        self.send_dont(opt)
    elif self.him[opt] == YES:
      pass
    elif self.him[opt] == WANTNO:
      if self.himq[opt] == EMPTY:
        # Error
        self.him[opt] = NO
      elif self.himq[opt] == OPPOSITE:
        # Error
        self.him[opt] = YES
        self.himq[opt] = EMPTY
    elif self.him[opt] == WANTYES:
      if self.himq[opt] == EMPTY:
        self.him[opt] = YES
      elif self.himq[opt] == OPPOSITE:
        self.him[opt] = WANTNO
        self.himq[opt] = EMPTY
        self.send_dont(opt)

  def _handle_wont (self, opt):
    """
    Handle WONT commands according to RF1143 (mostly)
    """
    if self.him[opt] == NO:
      pass
    elif self.him[opt] == YES:
      if self._can_he_disable(opt):
        self.him[opt] = NO
        self.send_dont(opt)
        self._notify_him(opt, False)
      else:
        self.send_do(opt) # Not in RFC1143
    elif self.him[opt] == WANTNO:
      if self.himq[opt] == EMPTY:
        self.him[opt] = NO
      elif self.himq[opt] == OPPOSITE:
        self.him[opt] = WANTYES
        self.himq[opt] = EMPTY # NONE!?
        self.send_do(opt)
    elif self.him[opt] == WANTYES:
      if self.himq[opt] == EMPTY:
        self.him[opt] = NO
      elif self.himq[opt] == OPPOSITE:
        self.him[opt] = NO
        self.himq[opt] = EMPTY

  def _handle_do (self, opt):
    """
    Handle DO commands according to RF1143
    """
    if self.us[opt] == NO:
      if self._can_we_enable(opt):
        self.us[opt] = YES
        self.send_will(opt)
        self._notify_us(opt, True)
      else:
        self.send_wont(opt)
    elif self.us[opt] == YES:
      pass
    elif self.us[opt] == WANTNO:
      if self.usq[opt] == EMPTY:
        # Error
        self.us[opt] = NO
      elif self.usq[opt] == OPPOSITE:
        # Error
        self.us[opt] = YES
        self.usq[opt] = EMPTY
    elif self.us[opt] == WANTYES:
      if self.usq[opt] == EMPTY:
        self.us[opt] = YES
      elif self.usq[opt] == OPPOSITE:
        self.us[opt] = WANTNO
        self.usq[opt] = EMPTY
        self.send_wont(opt)

  def _handle_dont (self, opt):
    """
    Handle DONT commands according to RF1143
    """
    if self.us[opt] == NO:
      pass
    elif self.us[opt] == YES:
      if self._can_we_disable(opt):
        self.us[opt] = NO
        self.send_wont(opt)
        self._notify_us(opt, False)
      else:
        self.send_will(opt) # Not in RFC1143
    elif self.us[opt] == WANTNO:
      if self.usq[opt] == EMPTY:
        self.us[opt] = NO
      elif self.usq[opt] == OPPOSITE:
        self.us[opt] = WANTYES
        self.usq[opt] = EMPTY # NONE!?
        self.send_will(opt)
    elif self.us[opt] == WANTYES:
      if self.usq[opt] == EMPTY:
        self.us[opt] = NO
      elif self.usq[opt] == OPPOSITE:
        self.us[opt] = NO
        self.usq[opt] = EMPTY

  def _ask_for (self, opt):
    """
    Ask him to...
    """
    if self.him[opt] == NO:
      self.him[opt] = WANTYES
      self.send_do(opt)
    elif self.him[opt] == YES:
      # Already enabled
      pass
    elif self.him[opt] == WANTNO:
      if self.himq[opt] == EMPTY:
        #NOTE: This isn't actually following RFC1143.
        self.himq[opt] = OPPOSITE
      elif self.himq[opt] == OPPOSITE:
        # Already asking for this
        pass
    elif self.him[opt] == WANTYES:
      if self.himq[opt] == EMPTY:
        # Already negotiating
        pass
      elif self.himq[opt] == OPPOSITE:
        self.himq[opt] = EMPTY

  def _ask_for_not (self, opt):
    """
    Ask him not to...
    """
    if self.him[opt] == NO:
      # Already disabled
      pass
    elif self.him[opt] == YES:
      self.him[opt] = WANTNO
      self.send_dont(opt)
    elif self.him[opt] == WANTNO:
      if self.himq[opt] == EMPTY:
        # Already trying to disable
        pass
      elif self.himq[opt] == OPPOSITE:
        self.himq[opt] = EMPTY
    elif self.him[opt] == WANTYES:
      if self.himq[opt] == EMPTY:
        #NOTE: This isn't actually following RFC1143.
        self.himq[opt] = OPPOSITE
      elif self.himq[opt] == OPPOSITE:
        # Already tryign to disable
        pass

  def _ask_to (self, opt):
    """
    We want to...
    """
    if self.us[opt] == NO:
      self.us[opt] = WANTYES
      self.send_will(opt)
    elif self.us[opt] == YES:
      # Already enabled
      pass
    elif self.us[opt] == WANTNO:
      if self.usq[opt] == EMPTY:
        #NOTE: This isn't actually following RFC1143.
        self.usq[opt] = OPPOSITE
      elif self.usq[opt] == OPPOSITE:
        # Already asking for this
        pass
    elif self.us[opt] == WANTYES:
      if self.usq[opt] == EMPTY:
        # Already negotiating
        pass
      elif self.usq[opt] == OPPOSITE:
        self.usq[opt] = EMPTY

  def _ask_to_not (self, opt):
    """
    We don't want to...
    """
    if self.us[opt] == NO:
      # Already disabled
      pass
    elif self.us[opt] == YES:
      self.us[opt] = WANTNO
      self.send_wont(opt)
    elif self.us[opt] == WANTNO:
      if self.usq[opt] == EMPTY:
        # Already trying to disable
        pass
      elif self.usq[opt] == OPPOSITE:
        self.usq[opt] = EMPTY
    elif self.us[opt] == WANTYES:
      if self.usq[opt] == EMPTY:
        #NOTE: This isn't actually following RFC1143.
        self.usq[opt] = OPPOSITE
      elif self.usq[opt] == OPPOSITE:
        # Already tryign to disable
        pass


class OptTelnetHandler (QTelnetHandler):
  """
  TelnetHandler with simple option interface

  Express your desires by setting want_to/want_to_not (things we want to do
  or not do on our side) and want_for/want_for_not (things we want or don't
  want the other side to do).
  """

  #want_to = set()
  #want_to_not = set()
  #want_for = set()
  #want_for_not = set()

  def _init_wants (self, want_to = None, want_to_not = None,
                   want_for = None, want_for_not = None):
    def s (v):
      if not v: return set()
      return set(v)
    self.want_to = s(want_to)
    self.want_to_not = s(want_to_not)
    self.want_for = s(want_for)
    self.want_for_not = s(want_for_not)

  def startup (self):
    for x in self.want_to:
      self._ask_to(x)
    for x in self.want_to_not:
      self._ask_to_not(x)
    for x in self.want_for:
      self._ask_for(x)

  def _can_he_enable (self, opt):
    if opt in self.want_for: return True
    return FALSE

  def _can_he_disable (self, opt):
    if opt in self.want_for: return False
    return True


class MyTelnetHandler (OptTelnetHandler):
  def startup (self):
    self._init_wants(
        want_to = set([SGA, BINARY, ECHO]),
        want_to_not = set([LINEMODE]),
        want_for = set([SGA, SUPPRESS_LOCAL_ECHO, BINARY, TTYPE]),
        )
    OptTelnetHandler.startup(self)

    # Should wait until we see this enabled but whatever.
    self.send(IAC + SB + TTYPE + SEND + IAC + SE)


class LineEdit (object):
  def __init__ (self, **kw):
    super(LineEdit,self).__init__(**kw)
    self.__hist = []
    self.__pos = None
    self.__current = b''
    self.__cursor = 0
    self.password_mode = False

  def _accept_line (self, line):
    pass

  def ctrlc (self):
    pass

  def do_commit (self):
    #self.erase()
    self.password_mode = False
    line = self.__current
    if self.__current.strip():
      self.__hist.append(self.__current)
    self.__current = b''
    self.__cursor = 0
    self.__pos = None
    self._accept_line(line)

  def do_text (self, text):
    for c in text:
      self._do_char(bytes((c,)))

  def _do_char (self, c):
    if c == b'\x7f' or c == b'\x08':
      if self.__cursor == 0:
        self.send(BELL)
      else:
        self.__cursor -= 1
        self.__current = (self.__current[:self.__cursor] +
                          self.__current[self.__cursor+1:])
        self.redraw(1)
    elif c == b'\r':
      #self.erase()
      #self.send(">" + self.__current + "<\n\r")
      self.do_commit()
    elif c == b'\n':
      pass
    elif c == b'\x03':
      self.ctrlc()
    elif c == b'\x01': # ctrl-a
      self.send(self.term.cub1 * self.__cursor)
      self.__cursor = 0
    elif c == b'\x05': # ctrl-e
      r = len(self.__current) - self.__cursor
      self.__cursor = len(self.__current)
      self.send(self.term.cuf1 * r)
    elif c == _ctrl("W"):
      self.erase()
      c = self.__cursor
      if c >= len(self.__current): c -= 1
      while c >= 0 and self.__current[c] != b' ':
        c -= 1
      while c >= 0 and self.__current[c] == b' ':
        c -= 1
      c += 1
      if c == self.__cursor:
        self.send(BELL)
      else:
        self.__current = self.__current[:c] + self.__current[self.__cursor:]
        self.__cursor = c

      self.redraw(erase=False)
    elif c == _ctrl('K'):
      self.erase()
      self.__current = self.__current[:self.__cursor]
      self.redraw(erase=False)
    elif c < b' ': # control characters
      pass
    else:
      self.__current = (self.__current[:self.__cursor] + c +
                        self.__current[self.__cursor:])
      self.__cursor += 1
      if self.__cursor == len(self.__current):
        if self.password_mode:
          self.send(b"*")
        else:
          self.send(c)
      else:
        self.redraw(-1)

  def erase (self, o=0):
    self.send(self.term.cub1 * (self.__cursor+o))
    self.send(b" " * (len(self.__current)+o))
    self.send(self.term.cub1 * (len(self.__current)+o))

  def redraw (self, o=0, erase=True):
    # Totally hacky and sloppy
    if erase: self.erase(o)
    if self.password_mode:
      self.send(b"*" * len(self.__current))
    else:
      self.send(self.__current)
    self.send(self.term.cub1 * len(self.__current))
    self.send(self.term.cuf1 * self.__cursor)

  def do_ctl (self, c, n):
    if isinstance(n, bytes): n = n.decode()
    if n == 'kcuu1':
      if self.__pos is None:
        if not self.__hist:
          self.send(BELL)
        else:
          self.erase()
          self.__pos = len(self.__hist) - 1
          self.__current = self.__hist[self.__pos]
          self.__cursor = len(self.__current)
          self.redraw(erase=False)
      else:
        if self.__pos == 0:
          self.send(BELL)
        else:
          self.erase()
          self.__pos -= 1
          self.__current = self.__hist[self.__pos]
          self.__cursor = len(self.__current)
          self.redraw(erase=False)
    elif n == 'kcud1':
      if self.__pos is None:
        self.send(BELL)
      elif self.__pos == len(self.__hist) - 1:
        self.erase()
        self.__pos = None
        self.__current = b''
        self.__cursor = 0
        self.redraw(erase=False)
      else:
        self.erase()
        self.__pos += 1
        self.__current = self.__hist[self.__pos]
        self.__cursor = len(self.__current)
        self.redraw(erase=False)
    elif n == 'kcub1':
      if self.__cursor == 0:
        self.send(BELL)
      else:
        self.__cursor -= 1
        self.send(self.term.cub1)
    elif n == 'kcuf1':
      if self.__cursor == len(self.__current):
        self.send(BELL)
      else:
        self.__cursor += 1
        self.send(self.term.cuf1)
    elif n == 'kdch1':
      if self.__cursor == len(self.__current):
        self.send(BELL)
      else:
        self.erase()
        self.__current = (self.__current[:self.__cursor] +
                          self.__current[1+self.__cursor:])
        self.redraw(erase=False)


class TelnetWorker (RecocoIOWorker, MyTelnetHandler, LineEdit):
  """
  Telnet Worker
  """
  def __init__ (self, personality_class, personality_kwargs,
                *args, **kw):
    super(TelnetWorker, self).__init__(*args, **kw)
    self._connecting = True
    self.__tbuf = b''
    self.term = CursesCodes()

    # The del key seems to often be set to this, but it's not in the terminfo,
    # so we'll just jam it in here and hope for the best.
    self.term.add_key(b"\x1b[3~", fake='kdch1')

    self.personality = personality_class(self, **personality_kwargs)

  def _sb (self, sub):
    if sub.startswith(TTYPE + IS):
      #print "TERMINAL:",sub[2:]
      try:
        self.term = CursesCodes(sub[2:])
        self.term.add_key(b"\x1b[3~", fake='kdch1') # See above
      except:
        pass
      if self.term.smkx: self.send(self.term.smkx)
      #self.send("\x1b[?67l") # Switch DEL mode?
    else:
      super(TelnetWorker,self)._sub(sub)

  def _handle_close (self):
    log.info("Client disconnect")
    super(TelnetWorker, self)._handle_close()
    #clients.discard(self)

  def _handle_connect (self):
    log.info("Client connect")
    super(TelnetWorker, self)._handle_connect()
    self.startup()
    #clients.add(self)
    self.personality._handle_connect()

  def _accept_line (self, line):
    if self.personality.decoding:
      try:
        line = line.decode(self.personality.decoding)
        self.personality._handle_line(line)
      except Exception:
        self.personality._handle_bad_line(line)

  def _rx_telnet (self, data):
    for nc in data:
      self.__tbuf += bytes((nc,))
      r = self.term.check_key(self.__tbuf)
      if r is True:
        #print "<",self.term.get_name(self.__tbuf),">",
        n = self.term.get_name(self.__tbuf)
        self.do_ctl(self.__tbuf, n)
        self.__tbuf = b''
      elif r is False:
        #print self.__tbuf,
        #print repr(self.__tbuf)
        self.do_text(self.__tbuf)
        self.__tbuf = b''

  def _handle_rx (self):
    self.push(self.read())


class TelnetServer (EventMixin):
  """
  Telnet server base
  """

  worker = TelnetWorker

  def __init__ (self, personality, personality_kwargs = {}, port=2323):
    global log
    if log is None:
      log = core.getLogger()

    global _ioloop
    if _ioloop is None:
      _ioloop = RecocoIOLoop()
      #_ioloop.more_debugging = True
      _ioloop.start()

    kw = {'personality_class':personality,
          'personality_kwargs':personality_kwargs}

    w = ServerWorker(child_worker_type=self.worker, port=port, child_args=kw)
    self.server_worker = w
    _ioloop.register_worker(w)

    log.debug("%s running on port %s", personality.__name__, port)


class TelnetPersonality (object):
  """
  Base class for telnet server "personalities"

  A personality determines how the server behaves.

  You can add keyword arguments to __init__ as long as you pass the values
  into TelnetServer's personality_kwargs.
  """
  encoding = "utf-8"
  decoding = "utf-8"
  crlf = True

  def __init__ (self, worker):
    self.worker = worker

  def send (self, msg):
    """
    Send to client
    """
    if self.encoding and isinstance(msg, str): msg = msg.encode(self.encoding)
    if self.crlf: msg = msg.replace(b"\n", b"\n\r")
    self.worker.send(msg)

  def erase (self):
    """
    Erase input data
    """
    self.worker.erase()

  def _handle_connect (self):
    """
    Called when session is connected

    You can override this
    """
    #self.send(core.banner + "\n")
    pass

  def _handle_line (self, line):
    """
    Called when a line of input has been received

    You can override this
    """
    pass

  def _handle_bad_line (self, line):
    """
    Called when a line of input has been received but has bad encoding

    You can override this

    If a line is received and the personality specifies a .decoding, then
    we attempt to decode it with that character encoding.  If this fails,
    this method is called with the raw line.
    """
    pass


class PythonTelnetPersonality (TelnetPersonality):
  """
  A default telnet "personality"

  This one is a pretty good personality, really, if you like Python.
  Be careful; this executes on the cooperative thread!

  TODO: It'd be nice to factor out the password part of this.
  """

  _auto_password = None
  ps1 = 'POX> '
  ps2 = '...> '

  def __init__ (self, worker, username, password, timeout=2):
    self.worker = worker
    self.buf = ''
    import code
    local = {'__name__':'__telnetconsole__'}
    local['_telnet_timeout'] = timeout # Command execution timeout
    self.variables = local
    self.interp = code.InteractiveInterpreter(local)
    self.interp.write = self.send
    self.timeout = timeout

    self.username = username
    if self.username is None:
      self.username = 'pox'

    if self.username == '':
      self.logged_in = True
      self.password = ''
    else:
      self.logged_in = False
      if password is None:
        if PythonTelnetPersonality._auto_password is None:
          import random, string
          self.password = ''.join(random.choice(string.ascii_uppercase)
                                  for x in range(random.randint(5,10)))
          log.info("Telnet user/pass: %s/%s", self.username, self.password)
          PythonTelnetPersonality._auto_password = self.password
        else:
          self.password = PythonTelnetPersonality._auto_password
      else:
        self.password = password
        #log.debug("Telnet user: %s", self.username)

    self.user = None

  def _handle_connect (self):
    self.send(core.banner + "\n")
    if self.logged_in:
      self.send(self.ps1)
    else:
      self.send("Username: ")

  def _handle_bad_line (self, line):
    log.warn("Bad input")
    self.send("\nBad input!  Try again.\n")

  def _handle_line (self, line):
    if not self.logged_in:
      if self.user is None:
        self.user = line
        self.send("\nPassword: ")
        self.worker.password_mode = True
        return
      else:
        user = self.user
        self.user = None
        if user == self.username:
          if line == self.password:
            log.debug("User %s logged in", user)
            self.send("\n\nWelcome!\n" + self.ps1)
            self.logged_in = True
            return
        log.warn("Failed login attempt.")
        self.send("\nSorry!\n\nUsername: ")
      return

    self.send("\n")
    self.buf += line + "\n"
    import code
    try:
      t = self.buf.lstrip()
      if t and t[-1] == '\n': t = t[:-1]
      o = code.compile_command(t, "<telnet>")
    except:
      self.buf = ''
      self.send("?Syntax Error\n" + self.ps1)
      return
    if o is None:
      self.send(self.ps2)
      return
    self.buf = ''

    import sys

    # Okay, we do something wacky here.  We don't want a telnet user
    # to accidentally lock up the cooperative thread by, say, doing
    # an infinite loop.  So we try to turn on the Python tracing
    # feature.  Usually this is used for implementing debuggers, but
    # for us, the upshot is that it calls a function when various
    # events occur.  We don't actually do any real tracing there; we
    # simply check to see whether a timeout interval has elapsed.
    # If it has, we raise an exception, which kills whatever was
    # hanging us up.
    # The code here appears a bit arcane.  What it's attempting to
    # protect us from is the fact that gettrace()/settrace() are
    # implementation specific and may not exist.
    try:
      gettrace = getattr(sys, 'gettrace')
      settrace = getattr(sys, 'settrace')
      if gettrace(): raise RuntimeError() # Someone already tracing
    except:
      gettrace = lambda : None
      settrace = lambda f : None

    class TimeoutError (RuntimeError):
      pass

    import time
    try:
      timeout = self.variables.get('_telnet_timeout', 1)
      if timeout is not None:
        timeout = timeout + time.time()
    except:
      timeout = time.time() + 1

    def check_timeout (frame, event, arg):
      if timeout and time.time() > timeout:
        raise TimeoutError("\n\n ** Code took too long to complete! **\n"
            "\n (Adjust _telnet_timeout if desired.)\n")
      if event == 'call': return check_timeout

    settrace(check_timeout)

    # Redirect standard IO to the telnet session.  May not play nicely
    # with multiple threads.
    # Note that we also set stdin to an empty StringIO.  This is because
    # otherwise doing something that tried to read would try to read from
    # the controlling terminal, which isn't what we want at all.  So this
    # effectively disables input.  I think the only way we could add it in
    # would be to run the Python code in a separate thread (blocking the
    # cooperative one except during input).  I've actually been thinking
    # about doing this for the "py" module for a long time (so that code
    # from the CLI runs in the cooperative context), but haven't ever
    # gotten around to it.  Note that this doesn't appear to work in PyPy,
    # but I haven't looked into why yet.

    oldout = sys.stdout
    olderr = sys.stderr
    oldin = sys.stdin
    from io import StringIO
    sys.stdout = StringIO()
    sys.stderr = sys.stdout
    # Sometime in the future something like this may be more useful...
    #sys.stdout.write = self.send
    #sys.stderr.write = self.send
    sys.stdin = StringIO()
    try:
      self.interp.runcode(o)
      r = sys.stdout.getvalue()
      self.send(r)
    except TimeoutError as e:
      # I think this will only actually catch the exception if it happens at
      # the first scope.  Otherwise, it triggers a stack trace elsewhere.
      # Either way is fine since both stop execution.  Just be aware that
      # this exception handler may well not get called.
      # We print the traceback instead of just a message so that it looks
      # more similar to when it *doesn't* get caught here.
      import traceback
      self.send(traceback.format_exc())
    except Exception:
      pass
    except SystemExit:
      self.send("Bye bye!\n")
      self.worker.shutdown()
      return
    finally:
      settrace(None)
      sys.stdout = oldout
      sys.stderr = olderr
      sys.stdin = oldin

    self.send(self.ps1)


def launch (username = "pox", password = None, port = 2323):
  """
  Launch the telnet server with a default Python shell personality

  Note that this is dangerous!
  """
  # Set up logging
  global log
  log = core.getLogger()

  kw = {'username':username, 'password':password}

  # Register as a component
  core.registerNew(TelnetServer, personality = PythonTelnetPersonality,
                   personality_kwargs = kw, port = int(port))

