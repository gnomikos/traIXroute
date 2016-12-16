
# traIXroute

**traIXroute** is a tool that detects if and where a traceroute path crosses an IXP fabric. It uses multiple criteria to verify IXP crossings in the light of replies from third-party interfaces or inaccuracies in the available data about IP addresses assigned to IXPs. These discrepancies mislead simple heuristics based solely on the IP address prefixes allocated to IXPs. The detection uses data from  PeeringDB, Packet Clearing House and RouteViews. In addition, **traIXroute** uses in the background the standard  [traceroute](https://en.wikipedia.org/wiki/Traceroute) tool or the [scamper](https://www.caida.org/tools/measurement/scamper/) tool, which implements the Paris traceroute technique to deal with inaccurate paths due to load balancers [1]. It is open source under GPLv3. 

The heuristics used by traIXroute and their evaluation are described in the following paper:

 - G. Nomikos, X. Dimitropoulos. **“traIXroute: Detecting IXPs in traceroute paths".** In Proceedings of the Passive and Active Measurements Conference (PAM'16) 31 March - 1 April 2016, Heraklion, Greece.

 - G. Nomikos, X. Dimitropoulos. [**“Detecting IXPs in Traceroute Paths Using traIXroute"**](https://labs.ripe.net/Members/george_nomikos/detecting-ixps-in-traceroute-paths-using-traixroute). RIPE Labs, 3 Aug 2016.

**traIXroute enhances for the first time its features interoperating with the [Remote Peering Jedi tool](http://inspire.edu.gr/rp/index.html).**

##Download
The source code is available in the traIXroute github [repository](https://github.com/gnomikos/traIXroute). You can download it directly from [here](https://github.com/gnomikos/traIXroute). The first version of traIXroute was released in May 2016. 
##Installation

**traIXroute** has been tested on Linux and Mac OS X. Detailed installation instructions can be found in the README file in the traIXroute repository. You can install traIXroute with all the necessary packages running:

>$ sudo bash ./Setup/install.sh


####IMPORTANT
In case you run Mac OS X, ensure you have installed the Xcode command line developer tools before. To install run:

>$ xcode-select --install

A software update popup window will appear. You need to install only the command line developer tools by clicking the "Install" button and then agree to the Terms of Service. This process will download and install the Command Line Tools package.

If you have problems, please contact George Nomikos (gnomikos [at] ics.forth.gr).
##Dependencies
traIXroute has the following dependencies:

[Python 3](https://www.python.org/downloads/)   —  **traIXroute** requires Python 3.4 or newer. <br />
[PySubnetTree](https://www.bro.org/downloads/release/pysubnettree-0.24.tar.gz)  —  A Python module for CIDR lookups. <br />
[Scamper](https://www.caida.org/tools/measurement/scamper/)  —  A tool provided by CAIDA for probing the Internet in parallel, so that bulk data can be collected in a timely fashion. <br />
[Traceroute](https://en.wikipedia.org/wiki/Traceroute)  —  A diagnostic tool for measuring Internet paths and their per hop delay. <br />

##Documentation
**traIXroute** is thoroughly documented [here](http://www.inspire.edu.gr/traIXroute/traIXroute_documentation.pdf). The documentation covers the available command line options, how to extend or overwrite the data from PeeringDB and the Packet Clearing House with user-provided data, how to customize or extend traIXroute detection rules, and a diagram of its modules.

##Licence
The source code of **traIXroute** is released under the GNU General Public License, version 3. A copy can be found in the COPYING file.

Copyright © traIXroute, 2016.

##Authors
**traIXroute** was written by Michalis Bamiedakis (mbam [at] ics [dot] forth [dot] gr), Dimitris Mavrommatis (mavromat [at] ics [dot] forth [dot] gr) and George Nomikos (gnomikos [at] ics [dot] forth [dot] gr) from the INternet Security, Privacy, and Intelligence REsearch ([INSPIRE](http://www.inspire.edu.gr/)) Group in the Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH). The research was supervised by Prof. Xenofontas Dimitropoulos (fontas [at] ics [dot] forth [dot] gr).

**Contact Author:** George Nomikos (gnomikos [at] ics [dot] forth [dot] gr)

##Acknowledgements
The research that led to **traIXroute** was supported by the European Research Council (ERC) Grant 338402 - The NetVolution Project ([www.netvolution.eu](http://www.netvolution.eu/)).

## References
[1]	Augustin, B., Friedman, T. and Teixeira, R., "Multipath tracing with Paris traceroute." *In End-to-End Monitoring Techniques and Services, 2007. Workshop on, pp. 1-8.* IEEE, 2007.


