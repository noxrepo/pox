/*************************************************************************
Copyright 2011 James McCauley

This file is part of POX.

POX is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

POX is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with POX.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************/

// This class communicates with POX's webmessenger component.
// It could be improved (especially with some tweaks to
// webmessenger.  Feel free to contribute improvements. :)
// (In particular, it currently *detects* problems, but does
// not recover from them.)
function WebMessenger (callback, urlBase, user, password)
{
  this._ses = null;
  this._rx_seq = null;
  this._tx_seq = 100;
  this._stopped = false;

  if (!urlBase) urlBase = "/_webmsg";
  if (urlBase[urlBase.length-1] != "/") urlBase += "/";
  this._urlBase = urlBase
  this._auth = [user, password];

  this._output = []; // Queue of outgoing data
  this._output_pending = false;
  this._poll_pending = false;

  this.stop = function (data)
  {
    this._stopped = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    //TODO: Abort pending connections
  };

  if (callback)
  {
    this.process = callback
  }
  else
  {
    this.process = function (data)
    {
      // You probably want to overload this...
      if (console) console.log("Recv: " + JSON.stringify(data));
    };
  }

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
      if (req.status !== 0)
      {
        alert("Communication error (status " + req.status + ")");
      }
      this.stop();
      return;
    }
    var sendPoll = req.isPoll || (this._ses === null);

    var data = JSON.parse(req.responseText);
    if (this._ses === null && console) console.log("Session: " + data.ses);
    if (this._ses === null) this._ses = data.ses;
    if (data.ses !== this._ses)
    {
      // Strange!
      this.stop();
      alert("Communication error (bad ses)");
      return;
    }
    if (req.isPoll)
    {
      if (this._rx_seq === null) this._rx_seq = data.seq;
      if (data.seq !== this._rx_seq)
      {
        //alert(data.seq + " " + this._rx_seq);
        // Might want to buffer, but for now...
        this.stop();
        alert("Communication error (bad seq)");
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
    this._sendKeepAlive();
    var self = this;
    this._timer = setInterval(function () { self._handleKeepAliveTimer(); }, 60*1000);
  };
}
