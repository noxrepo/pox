from pox.core import core
from pox.messenger.messenger import *

log = pox.core.getLogger()

class MuxConnection (MessengerConnection):
  def __init__ (self, source, channelName, con):
    MessengerConnection.__init__(self, source, ID=str(id(self)))
    self.channelName = channelName
    self.con = con

    claimed = False
    e = core.messenger.raiseEventNoErrors(ConnectionStarted, self)
    if e is not None:
      claimed = e._claimed

    if not claimed:
      # Unclaimed events get forwarded to here too
      self.addListener(MessageRecieved, self._defaultMessageRecieved, priority=-1) # Low priority

    self._newlines = False

  def send (self, whatever, **kw):
    whatever = dict(whatever)
    whatever['_mux'] = self.channelName
    MessengerConnection.send(self, whatever, **kw)

  def sendRaw (self, data):
    self.con.sendRaw(data)


class MuxSource (object):
  def __init__ (self, con):
    self.listenTo(con)
    self.channels = {}

  def _forget (self, connection):
    if connection in self.channels:
      del self.channels[connection.channelName]
    else:
      log.warn("Tried to forget a channel I didn't know")

  def _handle_MessageRecieved (self, event):
    if event.con.isReadable():
      r = event.con.read()
      if type(r) is dict:
        channelName = r.get("_mux", None)
        del r['_mux']
        if channelName is not None:
          if channelName not in self.channels:
            # New channel
            channel = MuxConnection(self, channelName, event.con)
            self.channels[channelName] = channel
          else:
            channel = self.channels[channelName]
        elif r.get("_mux_bye",False):
          event.con.close()
        else:
          log.warn("Message to demuxer didn't specify a channel or valid command")
      else:
        log.warn("Demuxer only handlers dictionaries")
    else:
      self._closeAll()

  def _handle_ConnectionClosed (self, event):
    self._closeAll()

  def _closeAll (self):
    channels = self.channels.values()
    for connection in channels:
      connection._close()


class MuxHub (object):
  """
  """
  def __init__ (self):
    core.messenger.addListener(MessageRecieved, self._handle_global_MessageRecieved)#, weak=True)

  def _handle_global_MessageRecieved (self, event):
    try:
      n = event.con.read()['hello']
      if n['hello'] == 'mux':
        # It's for me!
        event.claim()
        m = MuxSource(event.con)

        print self.__class__.__name__, "- started conversation with", event.con
    except:
      pass


def launch ():
  #  core.register("demux", MessengerHub())
  global hub
  hub = MuxHub()
