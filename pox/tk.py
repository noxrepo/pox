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
Lets you use Tk with POX.

Highly experimental.
"""

from collections import deque
from pox.core import core

log = core.getLogger()

#TODO: Bind revent events across thread

class MessageBoxer (object):
  def __init__ (self, tk):
    import tkinter.messagebox, tkinter.colorchooser, tkinter.simpledialog
    import tkinter.filedialog
    fields = "ERROR INFO QUESTION WARNING ABORTRETRYIGNORE OKCANCEL "
    fields += "RETRYCANCEL YESNO YESNOCANCEL ABORT RETRY IGNORE OK "
    fields += "CANCEL YES NO"
    for f in fields.split():
      setattr(self, f, getattr(tkMessageBox, f))

    methods = "showinfo showwarning showerror askquestion "
    methods += "askokcancel askyesno askretrycancel"
    self._addmethods(tkMessageBox, methods, tk)

    methods = "askinteger askfloat askstring"
    self._addmethods(tkSimpleDialog, methods, tk)

    methods = "askcolor"
    self._addmethods(tkColorChooser, methods, tk)

    methods = "askopenfilename asksaveasfilename"
    self._addmethods(tkFileDialog, methods, tk)

  def _addmethods (self, module, methods, tk):
    for m in methods.split():
      def f (m):
        def f2 (*args, **kw):
          return getattr(module, m)(*args,**kw)
        def f4 (*args, **kw):
          _ = kw.pop('_', None)
          tk.do_ex(getattr(module, m), rv = _, args=args, kw=kw)
        def f5 (_, *args, **kw):
          tk.do_ex(f2, rv = _, args=args, kw=kw)
        return f4,f5
      a,b = f(m)
      setattr(self, m, a)
      setattr(self, m+"_cb", b)


class Tk (object):
  _core_name = "tk"

  def __init__ (self):
    self._q = deque()
    self.dialog = MessageBoxer(self)
    self.root = None
    self.automatic_quit = True

  def do_ex (self, code, rv=None, args=[], kw={}):
    self._q.append((code, rv, args, kw))
    self._ping()

  def _ping (self):
    if not self.root: return
    self.root.event_generate('<<Ping>>', when='tail')

  def do (__self, __code, __rv=None, *args, **kw):
    __self._q.append((__code, __rv, args, kw))
    __self._ping()

  def _dispatch (self, event):
    while len(self._q):
      self._dispatch_one(*self._q.popleft())

  def _dispatch_one (self, code, rv, args, kw):
    if callable(code):
      r = code(*args, **kw)
    else:
      def f ():
        l = {'self':self}
        l.update(kw)
        exec(code, globals(), l)
      r = f()
    if rv: core.callLater(rv, r)

  def run (self):
    import tkinter
    root = tkinter.Tk()
    root.bind('<<Ping>>', self._dispatch)

    self.root = root

    # Become live once in a while so that signals get handled
    def timer ():
      if self.automatic_quit and core.running == False:
        root.quit()
        return
      root.after(500, timer)
    timer()

    self.root.withdraw()

    self._dispatch(None)

    try:
      root.mainloop()
    except KeyboardInterrupt:
      pass
    log.debug("Quitting")


def launch ():
  from . import boot
  core.registerNew(Tk)
  boot.set_main_function(core.tk.run)

  """
  def pr (msg):
    print "From Tk:", msg
  core.callDelayed(5,lambda: core.tk.dialog.showinfo_cb(pr,
      "Hello", "Hello, World!"))
  """
