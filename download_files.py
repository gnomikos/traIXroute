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

from urllib.request import urlretrieve, urlopen
import os,shutil,subprocess,json

'''
Downloads the files needed for path analysis.
'''
class download_files():
    
    '''
    This function downloads and checks whether all the needed files have been downloaded successfully.
    Input:
        a) mypath: The traIXroute directory.
    Output:
        a) TRUE if the files have been downloaded successfully, FALSE otherwise.
     '''
    def download_files(self,mypath):
        
        mypath=mypath+'/database'
        if os.path.exists(mypath): shutil.rmtree(mypath)
        os.makedirs(mypath)

        peering = self.download_peering(mypath,0)
        pch = self.download_pch(mypath,0)
        routeviews = self.download_routeviews(mypath)

        if routeviews and (peering and pch):
            return True
        else:
            return False


    '''
    Downloads the peeringdb .json files.
    Input:
        a) mypath: The traIXroute database directory path.
        b) option: Flag to select file(s) to download.
    Output:
        a) TRUE if the files have been downloaded successfully, FALSE otherwise.
     '''
    def download_peering(self,mypath,option):

        try:
            if option==1 or not option:
                request = 'https://peeringdb.com/api/ixpfx'
                response = urlopen(request)
                str_response = response.readall().decode('utf-8')
                obj = json.loads(str_response)

                with open (mypath+'/ixpfx.json','w') as f:
                    json.dump (obj,f)

            if option==2 or not option:
                request = 'https://peeringdb.com/api/ix'
                response = urlopen(request)
                str_response = response.readall().decode('utf-8')
                obj= json.loads(str_response)

                with open (mypath+'/ix.json','w') as f:
                   json.dump (obj,f)

            if option==3 or not option:
                request = 'https://peeringdb.com/api/netixlan'
                response = urlopen(request)
                str_response = response.readall().decode('utf-8')
                obj= json.loads(str_response)

                with open (mypath+'/netixlan.json','w') as f:
                   json.dump (obj,f)

            if option==4 or not option:
                request = 'https://peeringdb.com/api/ixlan'
                response = urlopen(request)
                str_response = response.readall().decode('utf-8')
                obj= json.loads(str_response)

                with open (mypath+'/ixlan.json','w') as f:
                   json.dump (obj,f)
        except:
            print('PDB database has not been updated. Exiting.')
            exit(0)
        print('PDB database has been updated successfully.')
        return True


    '''
    Downloads the PCH files.
    Input:
        a) mypath: The traIXroute database directory path.
        b) option: Flag to select file(s) to download.
    Output:
        a) TRUE if the files have been downloaded successfully, FALSE otherwise.
    '''
    def download_pch(self,mypath,option):
        if option==1 or not option:
            try:   
                urlretrieve('https://prefix.pch.net/applications/ixpdir/download.php?s=subnet',mypath+'/ixp_subnets.csv')
            except:
                print('ixp_subnets.csv has not been updated. Exiting.')
                return False

        if option==2 or not option:
            try:
                urlretrieve('https://prefix.pch.net/applications/ixpdir/download.php?s=exchange',mypath+'/ixp_exchange.csv') 
            except:
                print('ixp_exchange.csv has not been updated. Exiting.')
                return False

        if option==3 or not option:
            try:
                urlretrieve('https://prefix.pch.net/applications/ixpdir/download.php?s=ix_membership',mypath+'/ixp_membership.csv')
            except:
                print('ixp_membership.csv has not been updated. Exiting.')
                return False

        print('PCH database has been updated successfully.')

        return True


    '''
    Downloads the Routeviews AS-to-Subnet file.
    Input:
         a) mypath: The traIXroute database directory path.
    Output:
         a) TRUE if the files have been downloaded successfully, FALSE otherwise.
    '''
    def download_routeviews(self,mypath):
    
        # Downloads the log file to find the last version of the routeviews file.
        try:
            urlretrieve('http://data.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log',mypath+'/caidalog.log') 
        except:
            print('Routeviews database has not been updated. Exiting.')
            return False
        # Parses the log file to find the file name.
        try:
            f2=open(mypath+'/caidalog.log')
        except:
            print('Routeviews has not been updated. Exiting.')
            return False
        
        updates=f2.read()
        f2.close()
        updates=updates.split('\n')
        updates=updates[len(updates)-2].split('\t')[2]
        
        # Downloads and extracts the routeviews file.
        try:
            urlretrieve('http://data.caida.org/datasets/routing/routeviews-prefix2as/'+updates,mypath+'/routeviews.gz') 
        except:
            print('Routeviews has not been updated. Exiting.')
            return False
        try:
            subprocess.call('gunzip '+mypath+'/routeviews.gz',shell=True)
        except:
            print('Routeviews has not been updated. Exiting')
            return False

        if os.path.exists(mypath+'/routeviews.gz'):
            os.remove(mypath+'/routeviews.gz')
        if os.path.exists(mypath+'/caidalog.log'):
            os.remove(mypath+'/caidalog.log')
        print ('Routeviews has been updated successfully.')
        
        return True