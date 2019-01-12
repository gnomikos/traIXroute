#!/bin/bash

# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis, Dimitris Mavrommatis and George Nomikos
#
# Contact Author: George Nomikos
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

additional(){

    sudo pip3 install --upgrade -r $cur_dir/requirements.txt

    if ! hash scamper 2>/dev/null; then
        sudo python3 $cur_dir/../lib/traixroute/downloader/install_scamper.py
    fi
}

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
            echo 'Installing dependencies for OS X.'
            additional
        else
            python3 -c "import sys; exit(float(sys.version[0:3])>=3.4)"
            if [ $? -eq 1 ]; then
                echo 'Python version is >= 3.4.'
                echo 'Installing dependencies for OS X.'
                additional
            else 
                echo 'Python vesrion is < 3.4. You need to upgrade and then run again the install script.'
            fi
        fi
    fi
# Install dependencies for Linux.
elif [ $OS = 'Linux' ]; then
    echo 'Installing dependencies for Linux.'
    sudo apt-get update
    sudo apt-get install g++ gcc traceroute libssl-dev libffi-dev -y
    additional

# Not supported OS.
else
	echo 'The OS is not supported.'
fi
