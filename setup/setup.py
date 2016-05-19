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

import subprocess,sys,os,shutil
from urllib.request import urlretrieve
mypath=sys.path[0]

 
#--------------------SubnetTree---------------------------
# Download SubnetTree
try:
    urlretrieve('https://www.bro.org/downloads/release/pysubnettree-0.24.tar.gz',mypath+'/pysubnettree.tar')
except:
    print('SubnetTree was not downloaded. Exiting.')
    exit(0)

# Unrar Subnet Tree
try:
    subprocess.call('tar -xvzf '+mypath+'/pysubnettree.tar',shell=True)
except:
    print('SubnetTree was not downloaded. Exiting.')
    exit(0)    
if os.path.exists(mypath+'/pysubnettree.tar'):
    os.remove(mypath+'/pysubnettree.tar')

# Install Subnet Tree.
if os.path.exists(mypath+'/pysubnettree-0.24'):
    os.chdir(mypath+'/pysubnettree-0.24')
    subprocess.call('python3 setup.py install',shell=True)
    os.chdir(mypath)
    shutil.rmtree(mypath+'/pysubnettree-0.24')
else:
    print('SubnetTree was not installed. Exiting.')
    exit(0)    


#--------------------SCAMPER---------------------------
# Download Scamper
try:
    urlretrieve('https://www.caida.org/tools/measurement/scamper/code/scamper-cvs-20141211d.tar.gz',mypath+'/scamper.tar') 

except:
    print('Scamper was not downloaded exiting.')
    exit(0)

try:
    subprocess.call('tar -xvzf '+mypath+'/scamper.tar',shell=True)
except:
    print('Scamper was not downloaded')  
if os.path.exists(mypath+'/scamper.tar'):
    os.remove(mypath+'/scamper.tar')

# Install scamper.
if os.path.exists(mypath+'/scamper-cvs-20141211d'):
    os.chdir(mypath+'/scamper-cvs-20141211d')
    subprocess.call('./configure',shell=True)
    subprocess.call('make',shell=True)
    subprocess.call('make install',shell=True)    
    os.chdir(mypath)
    shutil.rmtree(mypath+'/scamper-cvs-20141211d')
else:
    print('scamper was not installed. Exiting.')
    exit(0)    

print('Setup was completed successfully.')