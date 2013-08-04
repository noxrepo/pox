POX is a networking software platform written in Python

POX started life as an OpenFlow controller, but can now also function
as an OpenFlow switch, and can be useful for writing networking software
in general.

POX officially requires Python 2.7 (though much of it will work fine
fine with Python 2.6), and should run under Linux, Mac OS, and Windows.
(And just about anywhere else -- we've run it on Android phones,
under FreeBSD, Haiku, and elsewhere.  All you need is Python!)
You can place a pypy distribution alongside pox.py (in a directory
named "pypy"), and POX will run with pypy (this can be a significant
performance boost!).

POX currently communicates with OpenFlow 1.0 switches and includes
special support for the Open vSwitch/Nicira extensions.

pox.py boots up POX. It takes a list of module names on the command line,
locates the modules, calls their launch() function (if it exists), and
then transitions to the "up" state.

Modules are looked for everywhere that Python normally looks, plus the
"pox" and "ext" directories.  Thus, you can do the following:

  ./pox.py forwarding.l2_learning

You can pass options to the modules by specifying options after the module
name.  These are passed to the module's launch() funcion.  For example,
to set the address or port of the controller, invoke as follows:

  ./pox.py openflow.of_01 --address=10.1.1.1 --port=6634

pox.py also supports a few command line options of its own which should
be given first:
 --verbose      print stack traces for initialization exceptions
 --no-openflow  don't start the openflow module automatically
