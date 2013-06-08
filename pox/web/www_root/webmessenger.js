/*************************************************************************
Copyright 2011,2012 James McCauley

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
**************************************************************************/

/*
This is a little API for communicating with POX's webmessenger
component.  It's pretty awful.  One can do MUCH better with
some better JS, especially with a class framework like qooxdoo.

It also could use some improvements (and some corresponding
improvements to the webmessenger).  In particular, it currently
*detects* various problems, but provides no way to recover from
them.

Please feel free to contribute improvements!
*/

function MessengerChannel (messenger, channelName, config)
{
  this._channelName = channelName;
  this._messenger = messenger;
  this.on_rx = function (data)
  {
    if (console) console.log("Channel " + this._channelName
                             + "rx: " + JSON.stringify(data));
  };
  this.on_disconnect = function () {};

  if (config)
  {
    if (config.on_rx) this.on_rx = config.on_rx;
    if (config.on_disconnect) this.on_disconnect = config.on_disconnect;
  }

  this.send = function (msg)
  {
    // Should probably copy this before sending, but whatever.
    msg['CHANNEL'] = this._channelName;
    this._messenger.send();
  };
}

function WebMessenger (url, user, password, on_connect, on_disconnect, on_rx)
{

  this._reset = function ()
  {
    this._ses = null;
    this._rx_seq = null;
    this._tx_seq = 100;
    this._stopped = false;
  };

  var autorestart;
  if (typeof(url) != 'string' && typeof(url) != 'undefined')
  {
    user = url.user || user;
    password = url.password || password;
    on_connect = url.on_connect || on_connect;
    on_disconnect = url.on_disconnect || on_disconnect;
    on_rx = url.on_rx || on_rx;
    autorestart = url.autorestart;
    url = url.url;
  }

  this._reset();

  this._channels = {};

  /*
  this._ses = null;
  this._rx_seq = null;
  this._tx_seq = 100;
  this._stopped = false;
  */

  if (!url) url = "/_webmsg";
  if (url[url.length-1] != "/") url += "/";
  this._urlBase = url;
  this._auth = [user, password];

  this._output = []; // Queue of outgoing data
  this._output_pending = false;
  this._poll_pending = false;

  this.autorestart = !!autorestart;
  this._restart_pending = false;

  this.stop = function (can_restart)
  {
    this._stopped = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    //TODO: Abort pending connections

    if (can_restart && this.autorestart && !this._restart_pending)
    {
      this._restart_pending = true;
      var self = this;
      setTimeout(function () { self.connect(); }, 5000);
      //TODO: use the timer as _restart_pending (and cancel later)
    }
  };

  this.get_channel = function (channel, extra, channel_config)
  {
    if (channel in this._channels)
    {
      if (console) console.log("Ignored extra join info");
      return this._channels[channel];
    }

    var join = {'CHANNEL':'','cmd':'join_channel','channel':channel};
    for (var x in extra) join[x] = extra[x];
    this.send(join);
    var chan = new MessengerChannel(this, channel, channel_config);
    this._channels[channel] = chan;
    return chan;
  };

  this.process = function (data)
  {
    // You probably want to overload this...
    if ('CHANNEL' in data && data.CHANNEL in this._channels)
    {
      this._channels[data.CHANNEL].on_rx(data);
    }
    else
    {
      this.on_rx(data);
    }
  };

  this.on_connect = function (session_id)
  {
    if (console) console.log("Connect: Session " + session_id);
  };
  if (on_connect) this.on_connect = on_connect;
  this.on_disconnect = function (msg, stat)
  {
    if (!this.autorestart) alert(msg);
  };
  if (on_disconnect) this.on_disconnect = on_disconnect;
  this.on_rx = function (data)
  {
    if (console) console.log("on_rx: " + JSON.stringify(data));
  };
  if (on_rx) this.on_rx = on_rx;

  this._do_disconnect = function (msg, stat)
  {
    if (console) console.log("Disconnect: " + msg);
    for (var c in this._channels)
    {
      c = this._channels[c];
      c.on_disconnect(msg, stat);
      //try { c.on_disconnect(msg); } catch (e) { };
    }
    //try { this.on_disconnect(msg); } catch (e) { };
    this.on_disconnect(msg, stat);
  };

  this._nextTXSeq = function ()
  {
    var r = this._tx_seq;
    if (this._tx_seq === 0x7fFFffFF)
      this._tx_seq = 0;
    else
      this._tx_seq++;
    return r;
  };

  this._handleStateChange = function (req)
  {
    if (this._stopped) return;
    if (req.readyState !== 4) return;
    if (req.status != 200)
    {
      //if (req.status !== 0)
      {
        this._do_disconnect("Communication error (status " + req.status + ")", req.status);
      }
      this.stop(true);
      return;
    }
    var sendPoll = req.isPoll || (this._ses === null);

    var data = JSON.parse(req.responseText);
    if (this._ses === null && console)
    {
      //console.log("Session: " + data.ses);
      this._restart_pending = false;
      this.on_connect(data.ses);
    }
    if (this._ses === null) this._ses = data.ses;
    if (data.ses !== this._ses)
    {
      // Strange!
      this.stop(true);
      this._do_disconnect("Communication error (bad ses)", -1);
      return;
    }
    if (req.isPoll)
    {
      if (this._rx_seq === null) this._rx_seq = data.seq;
      if (data.seq !== this._rx_seq)
      {
        //alert(data.seq + " " + this._rx_seq);
        // Might want to buffer, but for now...
        this.stop(true);
        this._do_disconnect("Communication error (bad seq)", -2);
        return;
      }
      if (this._rx_seq === 0x7FffFFff)
        this._rx_seq = 0;
      else
        this._rx_seq++;

      var payload = data.data;
      for (var i = 0; i < payload.length; i++)
        this.process(payload[i]);
    }

    if (req.isPoll)
      this._poll_pending = false;
    if (sendPoll)
    {
      if (this._ses !== null)
      {
        // We have a session key and want to send a new poll.
        this._sendPoll();
      }
    }
    if (!req.isPoll)
    {
      this._output_pending = false;

      if (this._output.length > 0)
      {
        // Have more data -- send it
        this._sendData();
      }
    }
  };

  try
  {
    this.Xhr = XMLHttpRequest;
  }
  catch (e)
  {
    this.Xhr = ActiveXObject("Msxml2.XMLHTTP");
  }

  //TODO: refactor all the send methods
  this._sendPoll = function ()
  {
    if (this._poll_pending) return;
    if (this._stopped) return;
    this._poll_pending = true;
    var req = new this.Xhr();
    req.isPoll = true;
    var self = this;
    req.onreadystatechange = function () { self._handleStateChange(req); };
    req.open("GET", this._urlBase + (this._ses || "new"), true)
    req.send();
    if (console) console.log("Send poll");
  };

  this.send = function (msg, multiple, initial)
  {
    if (!multiple) msg = [msg];
    this._output = this._output.concat(msg)
    if (initial) this._output = null;
    this._sendData();
  };

  this._sendData = function ()
  {
    if (this._stopped) return;
    var req = new this.Xhr();
    req.isPoll = false;
    var self = this;
    req.onreadystatechange = function () { self._handleStateChange(req); };
    req.open("POST", this._urlBase + (this._ses || "new"), true)

    var msg = {
      seq : this._nextTXSeq(),
    };

    msg.data = this._output;
    this._output = [];

    req.send(JSON.stringify(msg));
    if (console) console.log("Send data: " + JSON.stringify(msg));
  };

  this._timer = null;

  this._sendKeepAlive = function ()
  {
    if (this._stopped) return;
    var req = new this.Xhr();
    req.isPoll = false;
    var self = this;
    req.onreadystatechange = function () { self._handleStateChange(req); };
    req.open("POST", this._urlBase + (this._ses || "new"), true)

    var msg = {
      seq : this._nextTXSeq(),
      data : null,
    };

    req.send(JSON.stringify(msg));
    if (console) console.log("Send KeepAlive");
  };

  this._handleKeepAliveTimer = function ()
  {
    if (this._stopped) return;
    this._sendKeepAlive();
    if (console) console.log("KeepAlive Timer");
  };

  this.connect = function ()
  {
    // Kick it off by sending a dummy message.
    // The response is where we get our session key.
    if (console) console.log("Connecting...");
    this._reset();
    this._sendKeepAlive();
    this._restart_pending = false;
    var self = this;
    this._timer = setInterval(function (){ self._handleKeepAliveTimer(); },
                              60*1000);
  };
}
