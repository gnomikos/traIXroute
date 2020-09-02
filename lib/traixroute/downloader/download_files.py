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
import shutil
import ujson
import os
import shutil
import subprocess
import concurrent.futures
import sys
import json


class download_files():

    '''
    Downloads all the files to construct the core database appropriate for path analysis.
    '''

    def __init__(self, config, destination_path):
        '''
        Sets the urls to the pdb, pch and routeviews datasets for downloading, imported from the config file.
        Input:
            a) config: Dictionary that contains the data in the config file.
        '''
        self.ixpfx = config["peering"]["ixp_pfx_link"]
        self.ix = config["peering"]["ix_link"]
        self.netixlan = config["peering"]["netixlan_link"]
        self.ixlan = config["peering"]["ixplan_link"]

        self.ixp_exchange = config["pch"]["ixp_exchange"]
        self.ixp_ip = config["pch"]["ixp_ips"]
        self.ixp_subnet = config["pch"]["ixp_subnet"]
        self.caida_log = config["caida_log"]

        self.homepath = destination_path

    def start_download(self):
        '''
        Downloads and checks whether all the needed files have been downloaded successfully.
        Output:
            a) True if the files have been downloaded successfully, False otherwise.
        '''

        if os.path.exists(self.homepath + '/database'):
            shutil.rmtree(self.homepath + '/database')
        os.makedirs(self.homepath + '/database')
        os.makedirs(self.homepath + '/database/PCH')
        os.makedirs(self.homepath + '/database/PDB')
        os.makedirs(self.homepath + '/database/RouteViews')
        # Setting shared variables to use multiple processes.
        peering = False
        pch = False
        routeviews = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            peering = executor.submit(
                self.download_peering, 0)
            pch = executor.submit(self.download_pch, 0)
            routeviews = executor.submit(
                self.download_routeviews)

        if routeviews.result() and peering.result() and pch.result():
            with open(self.homepath + "/configuration/check_update.txt", "w") as f:
                f.write("1")
            return True
        else:
            return False

    def download_peering(self, option):
        '''
        Downloads the peeringdb .json files.
        Input:
            b) option: Flag to select file(s) to download.
        Output:
            a) True if the files have been downloaded successfully, False otherwise.
         '''

        print('Started downloading PDB dataset.')
        try:
            if option == 1 or not option:
                request = self.ixpfx
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj = ujson.loads(str_response)

                with open(self.homepath + '/database/PDB/ixpfx.json', 'w') as f:
                    ujson.dump(obj, f)

            if option == 2 or not option:
                request = self.ix
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj = ujson.loads(str_response)

                with open(self.homepath + '/database/PDB/ix.json', 'w') as f:
                    ujson.dump(obj, f)

            if option == 3 or not option:
                request = self.netixlan
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj = ujson.loads(str_response)

                with open(self.homepath + '/database/PDB/netixlan.json', 'w') as f:
                    ujson.dump(obj, f)

            if option == 4 or not option:
                request = self.ixlan
                response = urlopen(request)
                str_response = response.read().decode('utf-8')
                obj = ujson.loads(str_response)

                with open(self.homepath + '/database/PDB/ixlan.json', 'w') as f:
                    ujson.dump(obj, f)
        except Exception as e:
            print(str(e))
            print('PDB dataset cannot be updated.')
            return False
        print('PDB dataset has been updated successfully.')
        return True

    def download_pch(self, option):
        '''
        Downloads the PCH files.
        Input:
            b) option: Flag to select file(s) to download.
        Output:
            a) True if the files have been downloaded successfully, False otherwise.
        '''

        print('Started downloading PCH dataset.')
        if option == 2 or not option:
            try:
                print("Downloading PCH directory datasets")
                urlretrieve(self.ixp_exchange, self.homepath +
                            '/database/PCH/ixp_exchange.csv')
            except Exception as e:
                print(str(e))
                print('ixp_exchange.csv cannot be updated.')
                return False

        if option == 1 or not option:
            try:
                print("Downloading PCH Subnet datasets")
                self.get_subnets()
            except Exception as e:
                print(str(e))
                print('ixp_subnets.csv cannot be updated.')
                return False

        if option == 3 or not option:
            try:
                print("Downloading PCH Membership datasets")
                self.get_membership()
            except Exception as e:
                print(str(e))
                print('ixp_membership.csv cannot be updated.')
                return False

        print('PCH dataset has been updated successfully.')

        return True

    def get_subnets(self):
        # read ixp_exchange file
        # self.homepath + '/database/PCH/ixp_subnets.csv'
        try:
            doc = open(self.homepath + '/database/PCH/ixp_exchange.csv')
            subnets_file = open(self.homepath + '/database/PCH/ixp_subnets.csv', "w")
            subnets_file.write(
                "exchange_point_id, short_name, status, version, multicast, mlpa, subnet, participants \n")  # header

            next(doc)
            for line in doc:
                temp_string = [item.strip() for item in line.split(',')]
                if len(temp_string) > 6:
                    try:
                        urlData = self.ixp_subnet + str(temp_string[0])
                        webURL = urlopen(urlData)
                        data = webURL.read()
                        encoding = webURL.info().get_content_charset('utf-8')
                        json_data = json.loads(data.decode(encoding))

                        for item in json_data:
                            # rebuild the old structure: exchange_point_id, short_name, status, version, multicast, mlpa, subnet, participants
                            line_entry = ','.join(
                                [item["exchange_point_id"], item["short_name"], item["status"], item["version"],
                                 "Unknown", item["mlpa"], item["subnet"], item["participants"]])
                            subnets_file.write(line_entry + "\n")


                    except Exception as e:
                        print("Could not fetch: " + str(urlData))
            return True
        except Exception as e:
            print(self.homepath + '/database/PCH/ixp_exchange.csv' + ' was not found.')
            return False
        finally:
            subnets_file.close()
            doc.close()

    def get_membership(self):
        # read ixp_exchange file
        # self.homepath + '/database/PCH/ixp_subnets.csv'
        try:
            doc = open(self.homepath + '/database/PCH/ixp_exchange.csv')
            memberships_file = open(self.homepath + '/database/PCH/ixp_membership.csv', "w")
            memberships_file.write("subnet, ip, fqdn, asn, organization \n")  # header

            next(doc)
            for line in doc:
                temp_string = [item.strip() for item in line.split(',')]
                if len(temp_string) > 6:
                    try:
                        urlData = "https://www.pch.net/api/ixp/subnet_details/" + str(temp_string[0])
                        webURL = urlopen(urlData)
                        data = webURL.read()
                        encoding = webURL.info().get_content_charset('utf-8')
                        json_data = json.loads(data.decode(encoding))

                        for protocol, prefixes in json_data.items():  # IPv6 & IPv4
                            for prefix, ips in prefixes.items():  # each prefix
                                if not isinstance(ips, list):  # This is when the input is directly a dict
                                    for ip, content in ips.items():  # each ip
                                        # rebuild the old structure: subnet, ip, fqdn, asn, organization
                                        tmp = [prefix, str(content["ip"]), str(content["fqdn"]), str(content["asn"]),
                                               str(content["org"])]
                                        for i in range(len(tmp)):
                                            if tmp[i] == "None": tmp[i] = " "
                                        line_entry = ','.join(tmp)
                                        memberships_file.write(line_entry + "\n")
                                else:  # This is when the input is a list
                                    for ip in ips:  # each ip
                                        # rebuild the old structure: subnet, ip, fqdn, asn, organization
                                        tmp = [prefix, str(ip["ip"]), str(ip["fqdn"]), str(ip["asn"]), str(ip["org"])]
                                        for i in range(len(tmp)):
                                            if tmp[i] == "None": tmp[i] = " "
                                        line_entry = ','.join(tmp)
                                        memberships_file.write(line_entry + "\n")


                    except Exception as e:
                        print("Could not fetch: " + str(urlData))
                        #print(e)
            return True
        except Exception as e:
            print(self.homepath + '/database/PCH/ixp_exchange.csv' + ' was not found.')
            return False
        finally:
            memberships_file.close()
            doc.close()

    def download_routeviews(self):
        '''
        Downloads the Routeviews AS-to-Subnet file.
        Output:
             a) True if the files have been downloaded successfully, False otherwise.
        '''

        print('Started downloading RouteViews dataset.')
        # Downloads the log file to find the last version of the routeviews
        # file.
        try:
            urlretrieve(self.caida_log, self.homepath +
                        '/database/RouteViews/caidalog.log')
        except Exception as e:
            print(str(e))
            print('RouteViews dataset cannot be updated.')
            return False

        # Parses the log file to find the file name.
        try:
            f2 = open(self.homepath + '/database/RouteViews/caidalog.log')
        except Exception as e:
            print(str(e))
            print('RouteViews cannot be updated.')
            return False

        updates = f2.read()
        f2.close()
        updates = updates.split('\n')
        updates = updates[len(updates) - 2].split('\t')[2]

        # Downloads and extracts the routeviews file.
        try:
            urlretrieve('http://data.caida.org/datasets/routing/routeviews-prefix2as/' +
                        updates, self.homepath + '/database/RouteViews/routeviews.gz')
        except Exception as e:
            print(str(e))
            print('RouteViews cannot be updated.')
            return False

        try:
            subprocess.call(
                str('gunzip ' + self.homepath + '/database/RouteViews/routeviews.gz').split(" "), shell=False)
        except Exception as e:
            print(str(e))
            print('RouteViews cannot be updated.')
            return False

        if os.path.exists(self.homepath + '/database/RouteViews/routeviews.gz'):
            os.remove(self.homepath + '/database/RouteViews/routeviews.gz')
        if os.path.exists(self.homepath + '/database/RouteViews/caidalog.log'):
            os.remove(self.homepath + '/database/RouteViews/caidalog.log')
        print('Routeviews has been updated successfully.')

        return True

    def getDestinationPath(self):
        return self.homepath
