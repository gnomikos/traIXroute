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

To install traIXroute with all the necessary packages follow the instructions as they seem below:

1) In terminal change your current directory to the setup folder in traIXroute package.

2) Run the two script files to install all the necessary packages for the traIXroute (see also README in the setup folder before running the scripts):

    --> Firstly you have to run:
    $ sudo bash install_dependencies.sh
    
    In case you run Mac OS X, a software update popup window will appear. To install only the command line developer tools choose "Install", then agree to the Terms of Service.

    --> Secondly, you have to run:
    $ sudo python3 setup.py 

3) After finishing the installation process move on the documentation to run the tool with all the proper arguments.

4) Check your firewall in case you filter certain types of packets to avoid getting unresponsive traces. Otherwise, traIXroute will not run properly.

The tool has been tested in Ubuntu 12.04, 14.04 and 16.04  and Mac OS X. 