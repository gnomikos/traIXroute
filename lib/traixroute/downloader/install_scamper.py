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
    version = 'scamper-cvs-20141211g'

    #--------------------SCAMPER---------------------------
    # Download Scamper
    try:
        urlretrieve(
            'https://www.caida.org/tools/measurement/scamper/code/'+version+'.tar.gz', mypath + '/scamper.tar')
        print('Scamper has been downloaded successfully.')
    except:
        print('Scamper has not been downloaded. Exiting.')
        sys.exit(0)

    # Untar Scamper
    try:
        subprocess.call('tar -xvzf ' + mypath +
                        '/scamper.tar -C' + mypath, shell=True)
        print('Scamper has been unzipped successfully.')
    except:
        print('Scamper has not been unzipped. Exiting.')
        sys.exit(0)

    # Install Scamper
    if os.path.exists(mypath + '/' + version):
        os.chdir(mypath + '/' + version)
        subprocess.call('./configure', shell=True)
        subprocess.call('make clean', shell=True)
        subprocess.call('make', shell=True)
        subprocess.call('make install', shell=True)

        os.chdir(mypath)
        shutil.rmtree(mypath + '/' + version)
        os.remove(mypath + '/scamper.tar')

        print('Scamper has been installed successfully.')
    else:
        print('Scamper has not been installed. Exiting.')
        sys.exit(0)

if __name__ == '__main__':
    main()
