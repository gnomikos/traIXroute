[![License](https://img.shields.io/pypi/l/traixroute.svg)](https://github.com/gnomikos/traIXroute/blob/master/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/traixroute.svg)](https://pypi.python.org/pypi/traixroute)
[![PyPI Downloads](https://img.shields.io/pypi/dm/traixroute.svg)](https://pypi.python.org/pypi/traixroute)
[![PyPI Status](https://img.shields.io/pypi/status/traixroute.svg)](https://pypi.python.org/pypi/traixroute)
[![PyPI Wheel](https://img.shields.io/pypi/wheel/traixroute.svg)](https://pypi.python.org/pypi/traixroute)
## Introduction

[traIXroute](https://github.com/gnomikos/traIXroute) is a tool that detects if and where a traceroute path crosses an IXP fabric. It uses multiple criteria to verify IXP crossings in the light of replies from third-party interfaces or inaccuracies in the available data about IP addresses assigned to IXPs. These discrepancies mislead simple heuristics based solely on the IP address prefixes allocated to IXPs. The detection uses data from  PeeringDB, Packet Clearing House and RouteViews. In addition, **traIXroute** uses in the background the standard  [traceroute](https://en.wikipedia.org/wiki/Traceroute) tool or the [scamper](https://www.caida.org/tools/measurement/scamper/) tool, which implements the Paris traceroute technique to deal with inaccurate paths due to load balancers [1]. It is open source under GPLv3. 

The heuristics used and their evaluation are described in the following paper:

* G. Nomikos, X. Dimitropoulos. **"traIXroute: Detecting IXPs in traceroute paths".** In Proceedings of the Passive and Active Measurements Conference (PAM'16) 31 March - 1 April 2016, Heraklion, Greece.

* G. Nomikos, X. Dimitropoulos. [**"Detecting IXPs in Traceroute Paths Using traIXroute"**](https://labs.ripe.net/Members/george_nomikos/detecting-ixps-in-traceroute-paths-using-traixroute). RIPE Labs, 3 Aug 2016.

**traIXroute enhances for the first time its features interoperating with the [Remote Peering Jedi tool](http://inspire.edu.gr/rp/index.html). For now, only data for DE-CIX (Frankfurt), Any2 (Los Angeles), AMS-IX, France-IX, LINX and MSK-IX are included.**

## Installation
The program has been tested on Linux and Mac OS X. Detailed installation instructions can be found in the INSTALL file in the repository. You can install all the necessary packages running:

The latest version is available on [`pypi`](https://pypi.python.org/pypi/traixroute), the Python Package Index:

```sh
$ pip3 install traixroute
$ scamper-install (To enable probes using scamper)
$ traixroute --help
```

It is also possible to download the latest archive from github:

```sh
$ curl -L https://github.com/gnomikos/traIXroute/archive/v2.1.1.tar.gz | tar zx
$ sh traIXroute-2.1.1/setup/install.sh
$ ./traIXroute-2.1.1/bin/traixroute
```

If using `git`:

```sh
$ git clone https://github.com/gnomikos/traIXroute.git
$ sh traIXroute/setup/install.sh
$ ./traIXroute/bin/traixroute
```

## IMPORTANT
In case you run Mac OS X, ensure you have installed the Xcode command line developer tools before. To install run:

```sh
$ xcode-select --install
```

A software update popup window will appear. You need to install only the command line developer tools by clicking the "Install" button and then agree to the Terms of Service. This process will download and install the Command Line Tools package.

If you have problems, please contact George Nomikos (gnomikos [at] ics.forth.gr).

## Dependencies

* [Python 3](https://www.python.org/downloads/)   —  **traIXroute** requires Python 3.4 or 3.5.
* [PySubnetTree](https://www.bro.org/downloads/release/pysubnettree-0.24.tar.gz)  —  A Python module for CIDR lookups.
* [Scamper](https://www.caida.org/tools/measurement/scamper/)  —  A tool provided by CAIDA for probing the Internet in parallel, so that bulk data can be collected in a timely fashion.
* [Traceroute](https://en.wikipedia.org/wiki/Traceroute)  —  A diagnostic tool for measuring Internet paths and their per hop delay.

## Documentation

Documentation can be found [here](https://github.com/gnomikos/traIXroute/). The documentation covers the available command line options, how to extend or overwrite the data from PeeringDB and the Packet Clearing House with user-provided data, how to customize or extend detection rules, and a diagram of its modules.

## Licence

The source code of **traIXroute** is released under the GNU General Public License, version 3. A copy can be found in the LICENSE file.

Copyright © traIXroute, 2016.

## Authors

**traIXroute** was written by Michalis Bamiedakis (mbam [at] ics [dot] forth [dot] gr), Dimitris Mavrommatis (mavromat [at] ics [dot] forth [dot] gr) and George Nomikos (gnomikos [at] ics [dot] forth [dot] gr) from the INternet Security, Privacy, and Intelligence REsearch ([INSPIRE](http://www.inspire.edu.gr/)) Group in the Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH). The research was supervised by Prof. Xenofontas Dimitropoulos (fontas [at] ics [dot] forth [dot] gr).

**Contact Author:** George Nomikos (gnomikos [at] ics [dot] forth [dot] gr)

## Acknowledgements

The research that led to **traIXroute** was supported by the European Research Council (ERC) Grant 338402 - The NetVolution Project ([www.netvolution.eu](http://www.netvolution.eu/)).

## References
[1]	Augustin, B., Friedman, T. and Teixeira, R., "Multipath tracing with Paris traceroute." *In End-to-End Monitoring Techniques and Services, 2007. Workshop on, pp. 1-8.* IEEE, 2007.
