#!/usr/bin/env python3

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

from urllib.request import urlretrieve, urlopen
import shutil, ujson, os, shutil, subprocess
import concurrent.futures,sys

class download_files():

    '''
    Downloads all the files to construct the core database appropriate for path analysis.
    '''
    
    def __init__(self,config):
        '''
        Sets the urls to the pdb, pch and routeviews datasets for downloading, imported from the config file.
        Input:
            a) config: Dictionary that contains the data in the config file.
        '''
        self.ixpfx      = config["peering"]["ixp_pfx_link"]
        self.ix         = config["peering"]["ix_link"]
        self.netixlan   = config["peering"]["netixlan_link"]
        self.ixlan      = config["peering"]["ixplan_link"]

        self.ixp_exchange   = config["pch"]["ixp_exchange"]
        self.ixp_ip         = config["pch"]["ixp_ips"]
        self.ixp_subnet     = config["pch"]["ixp_subnet"]
        self.caida_log      = config["caida_log"]


    def download_files(self,mypath):
        '''
        Downloads and checks whether all the needed files have been downloaded successfully.
        Input:
            a) mypath: The traIXroute directory.
        Output:
            a) True if the files have been downloaded successfully, False otherwise.
        '''
            
        mypath=mypath+'/Database/User'
        if os.path.exists(mypath): shutil.rmtree(mypath)
        os.makedirs(mypath)
        os.makedirs(mypath+'/PCH')
        os.makedirs(mypath+'/PDB')
        os.makedirs(mypath+'/RouteViews')
        # Setting shared variables to use multiple processes.
        peering     = False
        pch         = False
        routeviews  = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            peering = executor.submit(self.download_peering, mypath+'/PDB', 0)
            pch = executor.submit(self.download_pch, mypath+'/PCH', 0)
            routeviews = executor.submit(self.download_routeviews, mypath+'/RouteViews')

        if routeviews.result() and peering.result() and pch.result():
            with open(mypath+"/check_update.txt","w") as f:
                f.write("1")
            return True
        else:
            return False


    def download_peering(self,mypath,option):
        '''
        Downloads the peeringdb .json files.
        Input:
            a) mypath: The traIXroute database directory path.
            b) option: Flag to select file(s) to download.
        Output:
            a) True if the files have been downloaded successfully, False otherwise.
         '''

        print('Started downloading PDB dataset.')
        try:
            if option==1 or not option:
                request = self.ixpfx
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj = ujson.loads(str_response)

                with open (mypath+'/ixpfx.json','w') as f:
                    ujson.dump (obj,f)

            if option==2 or not option:
                request = self.ix
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj= ujson.loads(str_response)

                with open (mypath+'/ix.json','w') as f:
                   ujson.dump (obj,f)

            if option==3 or not option:
                request = self.netixlan
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj= ujson.loads(str_response)

                with open (mypath+'/netixlan.json','w') as f:
                   ujson.dump (obj,f)

            if option==4 or not option:
                request = self.ixlan
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj= ujson.loads(str_response)

                with open (mypath+'/ixlan.json','w') as f:
                   ujson.dump (obj,f)
        except Exception as e:
            print('PDB dataset cannot be updated.')
            return False
        print('PDB dataset has been updated successfully.')
        return True


    def download_pch(self,mypath,option):
        '''
        Downloads the PCH files.
        Input:
            a) mypath: The traIXroute database directory path.
            b) option: Flag to select file(s) to download.
        Output:
            a) True if the files have been downloaded successfully, False otherwise.
        '''

        print('Started downloading PCH dataset.')
        if option==1 or not option:
            try:   
                urlretrieve(self.ixp_subnet,mypath+'/ixp_subnets.csv')
            except:
                print('ixp_subnets.csv cannot be updated.')
                return False

        if option==2 or not option:
            try:
                urlretrieve(self.ixp_exchange,mypath+'/ixp_exchange.csv') 
            except:
                print('ixp_exchange.csv cannot be updated.')
                return False

        if option==3 or not option:
            try:
                urlretrieve(self.ixp_ip,mypath+'/ixp_membership.csv')
            except:
                print('ixp_membership.csv cannot be updated.')
                return False

        print('PCH dataset has been updated successfully.')

        return True


    def download_routeviews(self,mypath):
        '''
        Downloads the Routeviews AS-to-Subnet file.
        Input:
             a) mypath: The traIXroute database directory path.
        Output:
             a) True if the files have been downloaded successfully, False otherwise.
        '''
    
        print('Started downloading RouteViews dataset.')
        # Downloads the log file to find the last version of the routeviews file.
        try:
            urlretrieve(self.caida_log,mypath+'/caidalog.log') 
        except:
            print('RouteViews dataset cannot be updated.')
            return False
            
        # Parses the log file to find the file name.
        try:
            f2=open(mypath+'/caidalog.log')
        except:
            print('RouteViews cannot be updated.')
            return False
        
        updates=f2.read()
        f2.close()
        updates=updates.split('\n')
        updates=updates[len(updates)-2].split('\t')[2]
        
        # Downloads and extracts the routeviews file.
        try:
            urlretrieve('http://data.caida.org/datasets/routing/routeviews-prefix2as/'+updates,mypath+'/routeviews.gz') 
        except:
            print('RouteViews cannot be updated.')
            return False

        try:
            subprocess.call(str('gunzip '+mypath+'/routeviews.gz').split(" "),shell=False)
        except:
            print('RouteViews cannot be updated.')
            return False

        if os.path.exists(mypath+'/routeviews.gz'):
            os.remove(mypath+'/routeviews.gz')
        if os.path.exists(mypath+'/caidalog.log'):
            os.remove(mypath+'/caidalog.log')
        print ('Routeviews has been updated successfully.')
        
        return True
        
