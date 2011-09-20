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

/*

Thin wrapper around pcap.
Keep life simple.
Do the tough stuff in Python.
Don't think it can be done in ctypes because of how it
releases and reacquires the GIL for callbacks.

*/

#include <Python.h>
#ifdef WIN32

#include "pcap.h"
#include <time.h>

#else

#include <pcap.h>
#include <netinet/in.h>
#ifdef __APPLE__
#define AF_LINK_SOCKETS 1
#include <net/if_dl.h>
#elif defined (linux)
#define AF_PACKET_SOCKETS 1
//#include <netpacket/packet.h>
#include <linux/if_arp.h>
#endif


#endif

struct num_name_pair
{
  int num;
  const char * name;
};

#define ENTRY(__v) {__v, #__v}
num_name_pair link_types[] =
{
ENTRY(DLT_NULL),
ENTRY(DLT_EN10MB),
ENTRY(DLT_IEEE802),
ENTRY(DLT_ARCNET),
ENTRY(DLT_SLIP),
ENTRY(DLT_PPP),
ENTRY(DLT_FDDI),
ENTRY(DLT_ATM_RFC1483),
ENTRY(DLT_RAW),
ENTRY(DLT_PPP_SERIAL),
ENTRY(DLT_PPP_ETHER),
ENTRY(DLT_C_HDLC),
ENTRY(DLT_IEEE802_11),
ENTRY(DLT_FRELAY),
ENTRY(DLT_LOOP),
ENTRY(DLT_LINUX_SLL),
ENTRY(DLT_LTALK),
ENTRY(DLT_PFLOG),
ENTRY(DLT_PRISM_HEADER),
ENTRY(DLT_IP_OVER_FC),
ENTRY(DLT_SUNATM),
ENTRY(DLT_IEEE802_11_RADIO),
ENTRY(DLT_ARCNET_LINUX),
ENTRY(DLT_LINUX_IRDA),
ENTRY(DLT_LINUX_LAPD),
{0,0},
};
#undef ENTRY

// Assumption that a pointer fits into long int.

#ifdef WIN32
#include <ntddndis.h>

#include "Packet32.h"
bool macForName (char * name, char * mac)
{
  LPADAPTER lpAdapter = PacketOpenAdapter(name);

  if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    return false;

  PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6
   + sizeof(PACKET_OID_DATA));
  if (OidData == NULL)
  {
    PacketCloseAdapter(lpAdapter);
    return false;
  }

  OidData->Oid = OID_802_3_CURRENT_ADDRESS;
  OidData->Length = 6;
  ZeroMemory(OidData->Data, 6);
  if (PacketRequest(lpAdapter, FALSE, OidData))
  {
    memcpy(mac, OidData->Data, 6);
  }
  free(OidData);
  PacketCloseAdapter(lpAdapter);
  return true;
}
#endif


static PyObject * p_findalldevs (PyObject *self, PyObject *args)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t * devs;

  int r = pcap_findalldevs(&devs, errbuf);
  if (r)
  {
    // Hopefully this copies errbuf... it must, right?
    PyErr_SetString(PyExc_RuntimeError, errbuf);
    return NULL;
  }

  PyObject * pdevs = PyList_New(0);

  for (pcap_if_t * d = devs; d != NULL; d = d->next)
  {
    PyObject * addrs = PyList_New(0);
    for (pcap_addr_t * a = d->addresses; a != NULL; a = a->next)
    {
      if (a->addr->sa_family == AF_INET)
      {
        // Assume all members for this entry are AF_INET...
        // Code below is sort of hilarious
        char vd[6];
        vd[0] = 's';
        vd[5] = 0;
        vd[1] = a->addr ? 'i' : 'O';
        vd[2] = a->netmask ? 'i' : 'O';
        vd[3] = a->broadaddr ? 'i' : 'O';
        vd[4] = a->dstaddr ? 'i' : 'O';
        PyObject * addr_entry = Py_BuildValue(vd,
          "AF_INET",
          a->addr ? (PyObject*)((sockaddr_in*)a->addr)->sin_addr.s_addr : Py_None,
          a->netmask ? (PyObject*)((sockaddr_in*)a->netmask)->sin_addr.s_addr : Py_None,
          a->broadaddr ? (PyObject*)((sockaddr_in*)a->broadaddr)->sin_addr.s_addr : Py_None,
          a->dstaddr ? (PyObject*)((sockaddr_in*)a->dstaddr)->sin_addr.s_addr : Py_None);
        PyList_Append(addrs, addr_entry);
        Py_DECREF(addr_entry);
      }
      else if (a->addr->sa_family == AF_INET6)
      {
        //TODO
      }
#ifdef AF_LINK_SOCKETS
      else if (a->addr->sa_family == AF_LINK)
      {
        #define GET_ADDR(__f) a->__f ? (((sockaddr_dl*)a->__f)->sdl_data + ((sockaddr_dl*)a->__f)->sdl_nlen) : "", a->__f ? ((sockaddr_dl*)a->__f)->sdl_alen : 0
        PyObject * epo = Py_BuildValue("ss#", "ethernet", GET_ADDR(addr));
        PyList_Append(addrs, epo);
        Py_DECREF(epo);
        PyObject * addr_entry = Py_BuildValue("ss#s#s#s#",
          "AF_LINK",
          GET_ADDR(addr),
          GET_ADDR(netmask),
          GET_ADDR(broadaddr),
          GET_ADDR(dstaddr));
        #undef GET_ADDR

        PyList_Append(addrs, addr_entry);
        Py_DECREF(addr_entry);
      }
#endif
#ifdef AF_PACKET_SOCKETS
      else if (a->addr->sa_family == AF_PACKET)
      {
        struct sockaddr_ll * dll = (struct sockaddr_ll *)a->addr;
        if (dll->sll_hatype == ARPHRD_ETHER && dll->sll_halen == 6)
        {
          PyObject * epo = Py_BuildValue("ss#", "ethernet", dll->sll_addr, 6);
          PyList_Append(addrs, epo);
          Py_DECREF(epo);
        }
      }
#endif
      else
      {
        //printf("address family: %i %i\n", a->addr->sa_family);
      }
    }

#ifdef WIN32
    {
      char mac[6];
      if (macForName(d->name, mac))
      {
        PyObject * epo = Py_BuildValue("ss#", "ethernet", mac, 6);
        PyList_Append(addrs, epo);
        Py_DECREF(epo);
      }
    }
#endif

    PyObject * entry = Py_BuildValue("ssO", d->name, d->description, addrs);
    PyList_Append(pdevs, entry);
    Py_DECREF(entry);
  }

  pcap_freealldevs(devs);

  return pdevs;
}

static PyObject * p_open_dead (PyObject *self, PyObject *args)
{
  int linktype, snaplen;

  if (!PyArg_ParseTuple(args, "ii", &linktype, &snaplen)) return NULL;

  pcap_t * ppcap = pcap_open_dead(linktype, snaplen);

  if (!ppcap)
  {
    PyErr_SetString(PyExc_RuntimeError, "Could not create");
    return NULL;
  }

  return Py_BuildValue("l", (long)ppcap);
}

static PyObject * p_open_live (PyObject *self, PyObject *args)
{
  char * dev_name;
  int snaplen, promisc, timeout;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (!PyArg_ParseTuple(args, "siii", &dev_name, &snaplen, &promisc, &timeout)) return NULL;

  pcap_t * ppcap = pcap_open_live(dev_name, snaplen, promisc, timeout, errbuf);

  if (!ppcap)
  {
    PyErr_SetString(PyExc_RuntimeError, errbuf);
    return NULL;
  }

  return Py_BuildValue("l", (long)ppcap);
}

struct thread_state
{
  pcap_t * ppcap;
  PyThreadState * ts;
  PyObject * pycallback;
  PyObject * user;
  int exception;
};

static void ld_callback (u_char * my_thread_state, const struct pcap_pkthdr * h, const u_char * data)
{
  thread_state * ts = (thread_state *)my_thread_state;
  PyEval_RestoreThread(ts->ts);
  PyObject * args;
  PyObject * rv;
  args = Py_BuildValue("Os#lli",
      ts->user, data, h->caplen, (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->len);
  rv = PyEval_CallObject(ts->pycallback, args);
  Py_DECREF(args);
  if (rv)
  {
    Py_DECREF(rv);
  }
  else
  {
    ts->exception = 1;
    pcap_breakloop(ts->ppcap);
  }
  Py_DECREF(args);
  ts->ts = PyEval_SaveThread();
}

static PyObject * p_loop_or_dispatch (int dispatch, PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  thread_state ts;
  int cnt;
  int rv;
  if (!PyArg_ParseTuple(args, "liOO", &ppcap, &cnt, &ts.pycallback, &ts.user)) return NULL;
  Py_INCREF(ts.user);

  ts.ppcap = ppcap;
  ts.exception = 0;
  ts.ts = PyEval_SaveThread();

  if (dispatch)
    rv = pcap_loop(ppcap, cnt, ld_callback, (u_char *)&ts);
  else
    rv = pcap_dispatch(ppcap, cnt, ld_callback, (u_char *)&ts);

  PyEval_RestoreThread(ts.ts);

  Py_DECREF(ts.user);

  if (ts.exception) return NULL;

  return Py_BuildValue("i", rv);
}

static PyObject * p_loop (PyObject *self, PyObject *args)
{
  return p_loop_or_dispatch(0, self, args);
}

static PyObject * p_dispatch (PyObject *self, PyObject *args)
{
  return p_loop_or_dispatch(1, self, args);
}

static PyObject * p_next_ex (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  if (!PyArg_ParseTuple(args, "l", &ppcap)) return NULL;

  struct pcap_pkthdr * h;
  const u_char * data;
  int rv;
  Py_BEGIN_ALLOW_THREADS;
  rv = pcap_next_ex(ppcap, &h, &data);
  Py_END_ALLOW_THREADS;
  if (rv != 1) data = NULL;

  return Py_BuildValue("s#llii",
      data, h->caplen, (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->len, rv);
}

static PyObject * p_freecode (PyObject *self, PyObject *args)
{
  bpf_program * fp;
  if (!PyArg_ParseTuple(args, "l", (long*)&fp)) return NULL;
  pcap_freecode(fp);
  delete fp;
  return Py_None;
}

static PyObject * p_compile (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  char * str;
  int optimize;
  bpf_u_int32 netmask;
  if (!PyArg_ParseTuple(args, "lsii", (long int*)&ppcap, &str, &optimize, &netmask)) return NULL;
  bpf_program * fp = new bpf_program;
  int rv = pcap_compile(ppcap, fp, str, optimize, netmask);
  if (rv != 0)
  {
    delete fp;
    PyErr_SetString(PyExc_RuntimeError, pcap_geterr(ppcap));
    return NULL;
  }
  return Py_BuildValue("l", fp);
}

static PyObject * p_set_datalink (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  int dltype;
  if (!PyArg_ParseTuple(args, "li", (long*)&ppcap, &dltype)) return NULL;
  int rv = pcap_set_datalink(ppcap, dltype);
  if (rv != 0)
  {
    PyErr_SetString(PyExc_RuntimeError, pcap_geterr(ppcap));
    return NULL;
  }
  return Py_None;
}

static PyObject * p_setdirection (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  int cap_in, cap_out;
  pcap_direction_t f;
  if (!PyArg_ParseTuple(args, "lii", (long*)&ppcap, &cap_in, &cap_out)) return NULL;
  if (cap_in && cap_out)
    f = PCAP_D_INOUT;
  else if (cap_in)
    f = PCAP_D_IN;
  else
    f = PCAP_D_OUT;
  int rv = pcap_setdirection(ppcap, f);
  if (rv != 0)
  {
    PyErr_SetString(PyExc_RuntimeError, pcap_geterr(ppcap));
    return NULL;
  }
  return Py_None;
}

static PyObject * p_setfilter (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  bpf_program * fp;
  if (!PyArg_ParseTuple(args, "ll", (long*)&ppcap, (long*)&fp)) return NULL;
  int rv = pcap_setfilter(ppcap, fp);
  if (rv != 0)
  {
    PyErr_SetString(PyExc_RuntimeError, pcap_geterr(ppcap));
    return NULL;
  }
  return Py_None;
}

static PyObject * p_stats (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  if (!PyArg_ParseTuple(args, "l", (long int*)&ppcap)) return NULL;
  pcap_stat ps;
  int rv = pcap_stats(ppcap, &ps);
  if (rv != 0)
  {
    PyErr_SetString(PyExc_RuntimeError, pcap_geterr(ppcap));
    return NULL;
  }
  return Py_BuildValue("ll", (long)ps.ps_recv, (long)ps.ps_drop);
}

static PyObject * p_datalink (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  if (!PyArg_ParseTuple(args, "l", (long int*)&ppcap)) return NULL;
  int rv = pcap_datalink(ppcap);
  const char * rvs = NULL;
  for (num_name_pair * nn = link_types; nn->name != NULL; nn++)
  {
    if (nn->num == rv)
    {
      rvs = nn->name;
      break;
    }
  }
  return Py_BuildValue("is", rv, rvs);
}

static PyObject * p_fileno (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  if (!PyArg_ParseTuple(args, "l", (long int*)&ppcap)) return NULL;
  int rv = pcap_fileno(ppcap);
  return Py_BuildValue("i", rv);
}

static PyObject * p_inject (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  u_char * data;
  int len;
  if (!PyArg_ParseTuple(args, "ls#", (long*)&ppcap, &data, &len)) return NULL;
#ifdef WIN32
  int rv = pcap_sendpacket(ppcap, data, len);
  rv = rv ? 0 : len;
#else
  int rv = pcap_inject(ppcap, data, len);
#endif
  return Py_BuildValue("i", rv);
}

static PyObject * p_close (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  if (!PyArg_ParseTuple(args, "l", (long int*)&ppcap)) return NULL;
  pcap_close(ppcap);
  return Py_None;
}

static PyObject * p_breakloop (PyObject *self, PyObject *args)
{
  pcap_t * ppcap;
  if (!PyArg_ParseTuple(args, "l", (long int*)&ppcap)) return NULL;
  pcap_breakloop(ppcap);
  return Py_None;
}

static PyMethodDef pxpcapmethods[] =
{
  {"datalink", p_datalink, METH_VARARGS, "Get data link layer type.\nPass it a ppcap."},
  {"fileno", p_fileno, METH_VARARGS, "Get file descriptor for live capture\nPass it a ppcap."},
  {"close", p_close, METH_VARARGS, "Close capture device or file\nPass it a ppcap"},
  {"loop", p_loop, METH_VARARGS, "Capture packets\nPass it a ppcap, a count, a callback, and an opaque 'user data'.\nCallback params are same as first four of next_ex()'s return value"},
  {"dispatch", p_dispatch, METH_VARARGS, "Capture packets\nVery similar to loop()."},
  {"open_live", p_open_live, METH_VARARGS, "Open a capture device\nPass it dev name, snaplen (max capture length), promiscuous flag (1 for on, 0 for off), timeout milliseconds.\nReturns ppcap."},
  {"open_dead", p_open_dead, METH_VARARGS, "Open a dummy capture device\nPass it a linktype and snaplen (max cap length).\nReturns ppcap."},
  {"findalldevs",  p_findalldevs, METH_VARARGS, "List capture devices\nReturns list of tuple (name, desc, addrs).\naddr are a list of tuple (protocol, address, netmask, broadcast, dest)."},
  {"next_ex",  p_next_ex, METH_VARARGS, "Capture a single packet.\nPass it a ppcap.\nReturns tuple (data, timestamp_seconds, timestamp_useconds, total length, pcap_next_ex return value -- 1 is success)."},
  {"breakloop",  p_breakloop, METH_VARARGS, "Break capture loop.\nPass it a ppcap."},
  {"stats",  p_stats, METH_VARARGS, "Get capture stats.\nPass it a ppcap.\nReturns (packets_received, packets_dropped)."},
  {"compile", p_compile, METH_VARARGS, "Compile filter.\nPass it ppcap, filter string, optimize flag (1=on/0=off), netmask\nReturns pprog."},
  {"setfilter", p_setfilter, METH_VARARGS, "Set filter.\nPass it ppcap, pprogram (from compile())."},
  {"freecode", p_freecode, METH_VARARGS, "Free compiled filter.\nPass it pprogram from compile()."},
  {"inject", p_inject, METH_VARARGS, "Sends a packet.\nPass it a ppcap and data (bytes) to send.\nReturns number of bytes sent."},
  {"setdirection", p_setdirection, METH_VARARGS, "Sets the capture direction.\nTakes a ppcap and two boolean args: Incoming and Outgoing.\nSupport varies by platform."},
  {"set_datalink", p_set_datalink, METH_VARARGS, "Sets the datalink type to capture.\nTakes a ppcap and a datalink type."},
  {NULL, NULL, 0, NULL}
};

#define ADD_CONST(_s) PyModule_AddIntConstant(m, #_s, _s);

PyMODINIT_FUNC initpxpcap (void)
{
  PyObject * m = Py_InitModule("pxpcap", pxpcapmethods);

  //TODO: merge with similar list above
  ADD_CONST(DLT_NULL);
  ADD_CONST(DLT_EN10MB);
  ADD_CONST(DLT_IEEE802);
  ADD_CONST(DLT_ARCNET);
  ADD_CONST(DLT_SLIP);
  ADD_CONST(DLT_PPP);
  ADD_CONST(DLT_FDDI);
  ADD_CONST(DLT_ATM_RFC1483);
  ADD_CONST(DLT_RAW);
  ADD_CONST(DLT_PPP_SERIAL);
  ADD_CONST(DLT_PPP_ETHER);
  ADD_CONST(DLT_C_HDLC);
  ADD_CONST(DLT_IEEE802_11);
  ADD_CONST(DLT_FRELAY);
  ADD_CONST(DLT_LOOP);
  ADD_CONST(DLT_LINUX_SLL);
  ADD_CONST(DLT_LTALK);
  ADD_CONST(DLT_PFLOG);
  ADD_CONST(DLT_PRISM_HEADER);
  ADD_CONST(DLT_IP_OVER_FC);
  ADD_CONST(DLT_SUNATM);
  ADD_CONST(DLT_IEEE802_11_RADIO);
  ADD_CONST(DLT_ARCNET_LINUX);
  ADD_CONST(DLT_LINUX_IRDA);
  ADD_CONST(DLT_LINUX_LAPD);
}


