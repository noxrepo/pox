# POX

POX is a networking software platform written in Python.

POX started life as an OpenFlow controller, but can now also function as an
OpenFlow switch, and can be useful for writing networking software in
general.  It currently supports OpenFlow 1.0 and includes special support
for the Open vSwitch/Nicira extensions.

POX versions are named.  Starting with POX "gar", POX officially requires
Python 3.  The last version with support for Python 2 was POX "fangtooth".
POX should run under Linux, Mac OS, and Windows.  (And just about anywhere
else -- we've run it on Android phones, under FreeBSD, Haiku, and elsewhere.
All you need is Python!)  Some features are not available on all platforms.
Linux is the most featureful.

This README contains some information to get you started, but is purposely
brief.  For more information, please see the full documentation.


## Running POX

`pox.py` boots up POX. It takes a list of component names on the command line,
locates the components, calls their `launch()` function (if it exists), and
then transitions to the "up" state.

If you run `./pox.py`, it will attempt to find an appropriate Python 3
interpreter itself.  In particular, if there is a copy of PyPy in the main
POX directory, it will use that (for a potentially large performance boost!).
Otherwise it will look for things called `python3` and fall back to `python`.
You can also, of course, invoke the desired Python interpreter manually
(e.g., `python3 pox.py`).

The POX commandline optionally starts with POX's own options (see below).
This is followed by the name of a POX component, which may be followed by
options for that component.  This may be followed by further components
and their options.

  ./pox.py [pox-options...] [component] [component-options...] ...

### POX Options

While components' options are up to the component (see the component's
documentation), as mentioned above, POX has some options of its own.
Some useful ones are:

 | Option        | Meaning                                                   |
 | ------------- | --------------------------------------------------------- |
 |`--verbose`    | print stack traces for initialization exceptions          |
 |`--no-openflow`| don't start the openflow module automatically             |


## Components

POX components are basically Python modules with a few POX-specific
conventions.  They are looked for everywhere that Python normally looks, plus
the `pox` and `ext` directories.  Thus, you can do the following:

  ./pox.py forwarding.l2_learning

As mentioned above, you can pass options to the components by specifying
options after the component name.  These are passed to the corresponding
module's `launch()` funcion.  For example, if you want to run POX as an
OpenFlow controller and control address or port it uses, you can pass those
as options to the openflow._01 component:

  ./pox.py openflow.of_01 --address=10.1.1.1 --port=6634


## Further Documentation

The full POX documentation is available on GitHub at
https://noxrepo.github.io/pox-doc/html/
