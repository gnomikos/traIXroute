Introduction
------------
`traIXroute <https://github.com/gnomikos/traIXroute>`_ is a tool that detects if and where a traceroute path crosses an IXP fabric. It uses multiple criteria to verify IXP crossings in the light of replies from third-party interfaces or inaccuracies in the available data about IP addresses assigned to IXPs. These discrepancies mislead simple heuristics based solely on the IP address prefixes allocated to IXPs. The detection uses data from  PeeringDB, Packet Clearing House and RouteViews. In addition, ``traIXroute`` uses in the background the standard `traceroute <https://en.wikipedia.org/wiki/Traceroute>`_ tool or the `scamper <https://www.caida.org/tools/measurement/scamper/>`_ tool, which implements the Paris traceroute technique to deal with inaccurate paths due to load balancers [1]_. It is open source under GPLv3. 

The heuristics used by traIXroute and their evaluation are described in the following paper:

- G\. Nomikos, X. Dimitropoulos. **"traIXroute: Detecting IXPs in traceroute paths"**. In Proceedings of the Passive and Active Measurements Conference (PAM'16) 31 March - 1 April 2016, Heraklion, Greece.

- G\. Nomikos, X. Dimitropoulos. `"Detecting IXPs in Traceroute Paths Using traIXroute" <https://labs.ripe.net/Members/george_nomikos/detecting-ixps-in-traceroute-paths-using-traixroute>`_. RIPE Labs, 3 Aug 2016.

``traIXroute`` enhances for the first time its features interoperating with the `Remote Peering Jedi tool <http://inspire.edu.gr/rp/index.html>`_. For now, only data for DE-CIX (Frankfurt), Any2 (Los Angeles), AMS-IX, France-IX, LINX and MSK-IX are included.

Installation
------------
The program has been tested on Linux and Mac OS X. Detailed installation instructions can be found in the INSTALL file in the repository. You can install all the necessary packages running:

The latest version is available on `pypi <https://pypi.python.org/pypi/traixroute>`_, the Python Package Index:

::

$ pip3 install traixroute
$ scamper-install (To enable probes using scamper)
$ traixroute (To build the configuration files in the home directory)
$ traixroute --help

It is also possible to download the latest archive from github:

::

$ curl -L https://github.com/gnomikos/traIXroute/archive/v2.3.tar.gz | tar zx
$ sh traIXroute-2.3/setup/install.sh
$ ./traIXroute-2.3/bin/traixroute

If using `git`:

::

$ git clone https://github.com/gnomikos/traIXroute.git
$ sh traIXroute/setup/install.sh
$ ./traIXroute/bin/traixroute

IMPORTANT
---------
In case you run Mac OS X, ensure you have installed the Xcode command line developer tools before. To install run:

::

$ xcode-select --install

A software update popup window will appear. You need to install only the command line developer tools by clicking the "Install" button and then agree to the Terms of Service. This process will download and install the Command Line Tools package.

If you have problems, please contact George Nomikos (gnomikos [at] ics.forth.gr).

Dependencies
------------
- `Python 3 <https://www.python.org/downloads/>`_ —  ``traIXroute`` requires Python 3.5 or greater.
- `Scamper <https://www.caida.org/tools/measurement/scamper/>`_ — A tool provided by CAIDA for probing the Internet in parallel, so that bulk data can be collected in a timely fashion. 
- `Traceroute <https://en.wikipedia.org/wiki/Traceroute>`_ — A diagnostic tool for measuring Internet paths and their per hop delay.
- `Click here for other dependencies. <https://github.com/gnomikos/traIXroute/blob/v2.3/setup/requirements.txt>`_

Documentation
-------------
Documentation can be found `here <https://github.com/gnomikos/traIXroute/blob/v2.1/Documentation/traIXroutedocumentationv.2.1.pdf>`_. The documentation covers the available command line options, how to extend or overwrite the data from PeeringDB and the Packet Clearing House with user-provided data, how to customize or extend traIXroute detection rules, and a diagram of its modules.

Licence
-------
The source code of ``traIXroute`` is released under the GNU General Public License, version 3. A copy can be found in the LICENSE file.

Copyright © traIXroute, 2016.

Authors
-------
``traIXroute`` was written by Michalis Bamiedakis (mbam [at] ics [dot] forth [dot] gr), Dimitris Mavrommatis (mavromat [at] ics [dot] forth [dot] gr) and George Nomikos (gnomikos [at] ics [dot] forth [dot] gr) from the INternet Security, Privacy, and Intelligence REsearch (`INSPIRE <http://www.inspire.edu.gr/>`_
) Group in the Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH). The research was supervised by Prof. Xenofontas Dimitropoulos (fontas [at] ics [dot] forth [dot] gr).

**Contact Author: George Nomikos (gnomikos [at] ics [dot] forth [dot] gr)**

Acknowledgements
----------------
The research that led to ``traIXroute`` was supported by the European Research Council (ERC) Grant 338402 - The NetVolution Project (`www.netvolution.eu <http://www.netvolution.eu/>`_).

References
----------
.. [1]	Augustin, B., Friedman, T. and Teixeira, R., "Multipath tracing with Paris traceroute." *In End-to-End Monitoring Techniques and Services, 2007. Workshop on, pp. 1-8.* IEEE, 2007.
