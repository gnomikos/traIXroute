# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis and George Nomikos
#
# Contact Email: gnomikos [at] ics.forth.gr
#
# This file is part of traIXroute.
#
# traIXroute is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# traIXroute is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with traIXroute.  If not, see <http://www.gnu.org/licenses/>.

To run traIXroute, Python 3, SubnetTree, Scamper and Traceroute must be installed. 
For this reason, the setup scripts in the setup directory automate the whole installation process to properly run the tool. 
In case, you choose to manually install all the required packages follow the instructions below:

--------------------------------------------------------------------
For Linux:
0) Update the database
$ sudo apt-get update

1) Install Python 3
$ sudo apt-get install python3 python3-dev

2) Install Subnet Tree
$ sudo apt-get install python3-setuptools
$ sudo apt-get install g++
--Download from: https://pypi.python.org/pypi/pysubnettree/0.23
$ sudo python3 setup.py install  (in subnet tree directory)

3) Install Scamper
--Download from: https://www.caida.org/tools/measurement/scamper/
--To install Scamper follow the inner instructions

4) Install Traceroute
$ sudo apt-get install traceroute

----------------------------------------------------------------------
For Mac OS X:
1) Install Python 3
--Download and Install the Python 3 package from: https://www.python.org/downloads

2) Install the command line developer tools
$ xcode-select --install

3) Install Subnet Tree
--Download from: https://pypi.python.org/pypi/pysubnettree/0.23
$ sudo python3 setup.py install  (in subnet tree directory)

4) Install Scamper
--Download from: https://www.caida.org/tools/measurement/scamper/
--To install Scamper follow the inner instructions