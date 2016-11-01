#!/bin/bash

# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis, Dimitris Mavrommatis and George Nomikos
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

OS=$(uname)
cur_dir=$(dirname $0)

# Install dependencies for OS X.
if [ $OS = 'Darwin' ]; then

    ls /Library/Developer/CommandLineTools/ &>/dev/null;
    installed="$?"

    if [ $installed -ne 0 ]; then
        echo 'No developer tools were found. Install Xcode Command Line Tools before setup.'
        echo 'To install Xcode tools run: xcode-select --install'
        echo 'Exit.'
    elif [ $installed -eq 0 ]; then 
        echo 'Xcode Command Line Tools are installed.'
        python3 -V &>/dev/null;
        if [ $? -ne 0 ]; then
            echo 'Python 3 is not installed.'
            installer -pkg $cur_dir/python-3.4.4-macosx10.6.pkg -target /
        else
            python3 -c "import sys; exit(float(sys.version[0:3])>=3.4)"
            if [ $? -eq 1 ]; then
                echo 'Python version is >= 3.4.'
                echo 'Installing dependencies for OS X.'
                if ! hash scamper 2>/dev/null; then
                    python3 $cur_dir/setup.py
                fi
                pip3 install --upgrade pip
                pip3 install --upgrade -r $cur_dir/requirements.txt 
            else 
                echo 'Python vesrion is < 3.4. You need to upgrade.'
            fi
        fi
    fi
# Install dependencies for Linux.
elif [ $OS = 'Linux' ]; then
    echo 'Installing dependencies for Linux.'
    apt-get update
    apt-get -y install g++
    apt-get -y install gcc
    apt-get -y install python3
    apt-get -y install python3-setuptools
    apt-get -y install python3-dev
    apt-get -y install traceroute
    apt-get -y install python3-pip
    apt-get -y install libssl-dev
    if ! hash scamper 2>/dev/null; then
        python3 $cur_dir/setup.py
    fi
    pip3 install --upgrade pip
    pip3 install --upgrade -r $cur_dir/requirements.txt

# Not supported OS.
else
	echo 'The OS is not supported.'
fi
