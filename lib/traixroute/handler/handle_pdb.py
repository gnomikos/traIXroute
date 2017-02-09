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

from traixroute.handler import dict_merger
from traixroute.downloader import download_files
from traixroute.controller import string_handler
from shutil import copyfile
import ujson
import SubnetTree
import re


class peering_handle():
    '''
    This class imports the peerindb dataset.
    '''

    def __init__(self, downloader, libpath):
        # The config dictionary containing the user imported flags.
        self.downloader = downloader
        self.homepath = downloader.getDestinationPath()
        self.libpath = libpath

        # self.filename_peer_name: The ix.json file from peeringdb.
        self.filename_peer_name = '/PDB/ix.json'
        # self.filename_peer_ip: The netixlan.json file from peeringdb.
        self.filename_peer_ip = '/PDB/netixlan.json'
        # self.filename_peer_pfx: The ixpfx.json file from peeringdb.
        self.filename_peer_pfx = '/PDB/ixpfx.json'
        # self.filename_peer_ixlan: The ixlan.json file from peeringdb.
        self.filename_peer_ixlan = '/PDB/ixlan.json'

    def peering_handle_main(self, add_subnet_tree, reserved_tree, country2cc):
        '''
        Handles all the methods to import IXP related information from peeringdb .json files.
        Input:
            a) filename_peer_name: The ix.json file.
            b) filename_peer_ip: The netixlan.json file.
            c) filename_peer_pfx: The ixpfx.json file.
            d) filename_peer_ixlan: The ixlan.json file.
            e) add_subnet_tree: The SubnetTree containing the user imported IXP Subnets.
            f) mypath: The traIXroute directory.
            f) reserved_tree: The SubnetTree containing the reserved Subnets.
            g) config: Dictionary that contains the config file.
            h) country2cc: A dictionary with {Country}=Country Code.
            i) db_path: The path to the database directory.
        Output: 
            a) sub2names: A dictionary with {IXP Subnet}=[IXP long name, IXP short name].
            b) ip2asn: A dictionary with {IXP IP}=[ASN].
            c) ixp_to_names: A dictionary with {IXP IP}=[IXP long name, IXP short name].
            d) subnet2region: A dictionary with {IXP Subnet}=[IXP country,IXP city].
        '''

        json_names = self.extract_json_data(self.filename_peer_name, 2)
        [id_to_names, id_to_region] = self.extract_names(
            json_names, country2cc)

        json_ixlan = self.extract_json_data(self.filename_peer_ixlan, 4)
        ixlan_dict = self.extract_ixlan(json_ixlan)

        json_pfx = self.extract_json_data(self.filename_peer_pfx, 1)
        (sub2names, temp_subnet_tree, subnet2region) = self.extract_pfx(
            json_pfx, ixlan_dict, id_to_names, reserved_tree, id_to_region)

        json_ip = self.extract_json_data(self.filename_peer_ip, 3)
        (ip2asn) = self.extract_ip(
            json_ip, temp_subnet_tree, add_subnet_tree, reserved_tree)

        return(sub2names, ip2asn, subnet2region)

    def extract_json_data(self, filename, option):
        '''
        Imports .json files from peeringdb and returns a list of dictionaries with all the retrieved IXP information.
        Input: 
            a) filename: A .json file name.
            b) mypath: The directory path of the database.
            c) option: Flag to download the file.
            d) config: Dictionary that contains the config file.
        Ouput: 
            a) A list of dictionaries.
        '''

        try:
            with open(self.homepath + '/database' + filename) as data_file:
                obj = ujson.load(data_file)
        except:
            print(filename + ' was not found.')

            if not self.downloader.download_peering(option):
                print("Could not download " + filename +
                      ". Copying from the default database.")
                try:
                    copyfile(self.libpath + '/database/Default' + filename,
                             self.homepath + '/database' + filename)
                except:
                    print('Could not copy ' + filename +
                          ' from the default database.')

            try:
                with open(self.homepath + '/database' + filename) as data_file:
                    obj = ujson.load(data_file)
            except:
                print('Could not open ' + filename + '. Exiting.')
                exit(0)
        return (obj['data'])

    def extract_ixlan(self, json_ixlan):
        '''
        Extracts a json table and returns a key-to-key dictionary to bind the ix.json with the ixpfx.json via the ixlan.csv file.
        Input:
            a) json_ixlan: A json table with ixlan and ix ids. 
        Ouput: 
            a) ixlan_dict: A dictionary with {ixlan key}=ix key.
        '''

        ixlan_dict = {}

        for node in json_ixlan:
            ixlan_dict[node['id']] = node['ix_id']

        return (ixlan_dict)

    def extract_names(self, json_names, country2cc):
        '''
        Extracts the IXP ID-to-IXP names from the ix.json file.
        Input:
            a) json_names: A json table with ix ids and the IXP long and short names.
            b) country2cc: Country to country code dictionary.
        Output:
            a) names_dict: A dictionary with {ix id}=[IXP long name, IXP short name].
            b) region_dict: A dictionary with {ix id}=[IXP country,IXP city].
        '''

        names_dict = {}
        region_dict = {}
        handle_string = string_handler.string_handler()
        for node in json_names:
            [long_name, short_name] = handle_string.clean_long_short(
                node['name_long'], node['name'])
            if (len(long_name) > len(short_name)):
                names_dict[node['id']] = [long_name, short_name]
            else:
                names_dict[node['id']] = [short_name, long_name]
            country = re.sub('([^\s\w]|_)+', ' ', node['country'].strip())
            country = ' '.join(self.unique_list(country.split()))
            country = re.sub(' +', ' ', country)

            city = re.sub('([^\s\w]|_)+', ' ', node['city'].strip())
            city = ' '.join(self.unique_list(city.split()))
            city = re.sub(' +', ' ', city)
            try:
                region_dict[node['id']] = [country2cc[country], city]
            except KeyError:
                region_dict[node['id']] = [country, city]

        return (names_dict, region_dict)

    def extract_pfx(self, json_pfx, ixlan_dict, id_to_names, reserved_tree, region_dict):
        '''
        Extracts the prefixes from ixpfxs:
        Input:
            a) json_pfx: A json table containing the IXP prefixes and ids to ixlan.
            b) ixlan_dict: A dictionary with {ixlan id}=[ix id] to bind IXP prefixes and IXP names.
            c) id_to_names: A dictionary with {ix id}=[IXP long name, IXP short name]
            d) reserved_tree: The SubnetTree containing the reserved Subnets.
            e) region_dict: A dictionary with {ix id}=[IXP country,IXP city].
        Output:
            a) pfxs_dict: A dictionary with {IXP Subnet}=[IXP long name, IXP short name].
            b) temp_subnet_tree: A Subnet Tree with IXP Subnet-to-ix id.
            c) subnet2region: A dictionary with {IXP Subnet}=[IXP country,IXP city].
        '''

        handler = string_handler.string_handler()
        pfxs_dict = {}
        i = 0
        temp_subnet_tree = SubnetTree.SubnetTree()
        subnet2region = {}
        for node in json_pfx:
            subnet = handler.extract_ip(node['prefix'], 'Subnet')
            for s in subnet:
                if handler.is_valid_ip_address(s, 'Subnet'):
                    ixpfx = s
                    ixlan_id = node['ixlan_id']
                    if ixlan_id in ixlan_dict.keys():
                        ix_id = ixlan_dict[ixlan_id]
                        if ix_id in id_to_names.keys() and s not in pfxs_dict:
                            if id_to_names != ['', '']:
                                pfxs_dict[s] = [id_to_names[ix_id]]
                            else:
                                continue
                            temp_subnet_tree[s] = [id_to_names[ix_id]]
                            subnet2region[s] = region_dict[ix_id]
                        elif s in pfx_dict:
                            assign_tuple = []
                            for IXP in pfx_dict:
                                assign_tuple = assign_tuple + \
                                    handler.assign_names(IXP[1], id_to_names[ix_id][
                                                         1], IXP[0], id_to_names[ix_id][0])
                            pfxs_dict[s] = assign_tuple
                            subnet2regions[s] = region_dict[ix_id]

        return (pfxs_dict, temp_subnet_tree, subnet2region)

    def extract_ip(self, json_ip, temp_subnet_tree, add_subnet_tree, reserved_tree):
        '''
        Extracts the IXP IPs from peeringdb.
        Input: 
            a) json_IP: A json table containing IXP IPs, IXP short names and IXP IDs.
            b) temp_subnet_Tree: The Subnet Tree containing the IXP subnets from peeringdb.
            c) add_subnet_tree: The SubnetTree containing the user input on IXP subnets from additional_info.
            d) reserved_tree: The SubnetTree containing the reserved Subnets.
        Output:
            a) ixp_to_asn: A dictionary with {IXP IP}=[ASN].
        '''

        handler = string_handler.string_handler()
        ixp_to_asn = {}
        dumped_ixps = []

        for node in json_ip:
            if node['ipaddr4'] is None:
                temp = ''
            else:
                temp = node['ipaddr4']
            ips = handler.extract_ip(temp, 'IP')

            for ixpip in ips:
                if handler.is_valid_ip_address(ixpip, 'IP'):
                    if (ixpip not in ixp_to_asn.keys() and ixpip not in dumped_ixps and ixpip not in reserved_tree and ixpip in temp_subnet_tree):
                        ixp_to_asn[ixpip] = [str(node['asn'])]
                    elif ixpip in ixp_to_asn.keys():
                        if ixp_to_asn[ixpip] != [str(node['asn'])]:
                            dumped_ixps.append(ixpip)
                            ixp_to_asn.pop(ixpip, None)

        return ixp_to_asn

    def unique_list(self, l):
        return list(set(l))
