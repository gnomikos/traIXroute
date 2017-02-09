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

import subprocess
import sys
import os
import shutil
from urllib.request import urlretrieve


def main():
    mypath = os.path.expanduser("~")

    #--------------------SCAMPER---------------------------
    # Download Scamper
    try:
        urlretrieve(
            'https://www.caida.org/tools/measurement/scamper/code/scamper-cvs-20141211d.tar.gz', mypath + '/scamper.tar')
    except:
        print('Scamper has not been downloaded. Exiting.')
        sys.exit(0)

    # Untar Scamper
    try:
        subprocess.call('tar -xvzf ' + mypath +
                        '/scamper.tar -C' + mypath, shell=True)
    except:
        print('Scamper has not been unzipped. Exiting.')
        sys.exit(0)

    # Install Scamper
    if os.path.exists(mypath + '/scamper-cvs-20141211d'):
        os.chdir(mypath + '/scamper-cvs-20141211d')
        subprocess.call('./configure', shell=True)
        subprocess.call('make', shell=True)
        subprocess.call('make install', shell=True)

        os.chdir(mypath)
        shutil.rmtree(mypath + '/scamper-cvs-20141211d')
        os.remove(mypath + '/scamper.tar')

        print('Scamper has been installed successfully.')
    else:
        print('Scamper has not been installed. Exiting.')
        sys.exit(0)

if __name__ == '__main__':
    main()
