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
from traixroute.controller import string_handler
from collections import defaultdict
from traixroute.downloader import download_files
from shutil import copyfile
import SubnetTree
import sys
import re


class pch_handle():
    '''
    This class imports the PCH dataset.
    '''

    def __init__(self, downloader, libpath):
        # The config dictionary containing the user imported flags.
        self.downloader = downloader
        self.homepath = downloader.getDestinationPath()
        self.libpath = libpath

        # self.filename_subset: The ixp_subnets.csv file from pch.
        self.filename_subset = '/PCH/ixp_subnets'
        # self.filename_excha: The ixp_exchange.csv file from pch
        self.filename_excha = '/PCH/ixp_exchange'
        # self.filename_ixp_membership: The ixp_membership.csv file from pch.
        self.filename_ixp_membership = '/PCH/ixp_membership'

    def pch_handle_main(self, reserved_tree, add_info_tree, country2cc):
        '''
        Handles all the methods to import IXP related information from PCH files.
        Input:
            a) ixp_membership: The ixp_membership.csv file.
            b) ixp_subnet: The ixp_subnets.csv file.
            c) ixp_excha: The ixp_exchange.csv file.
            d) self.homepath: The directory path of the database.
            e) reserved_tree: The SubnetTree containing the reserved Subnets.
            f) add_info_tree: SubnetTree with Subnet to [IXP long name, IXP short name].
            g) country2cc: Dictionary that contains country names to country codes.
            e) db_path: The path to the Database folder.
        Output:
            a) pch_final: A dictionary with {IXP Subnet}=[IXP long name,IXP short name].
            b) ixp_mem: A dictionary with {IXP IP}=[ASN].
            c) pch_region: Dictionary that contains {IXP Subnet}=[IXP country, IXP city].
        '''
        [long_mem, IXP_region] = self.pch_handle_long(country2cc)
        [pch_final, pch_region, Subnet_names] = self.pch_handle_sub(
            reserved_tree, long_mem, IXP_region)
        ixp_mem = self.pch_handle_ixpm(reserved_tree, add_info_tree)

        return (pch_final, ixp_mem, pch_region)

    def pch_handle_ixpm(self, reserved_tree, add_info_tree):
        '''
        Extracts the IXP IPs from PCH.
        Input: 
            a) filename: The ixp_membership.csv file.
            b) self.homepath: The directory path of the database.
            c) reserved_tree: The SubnetTree containing the reserved Subnets.
            d) add_info_tree: The SubnetTree containing user imported IXP prefixes.
        Output:
            a) ixpip2asn: A dictionary with {IXP IP}=[ASN].
        '''

        doc = self.file_opener(self.filename_ixp_membership, 3)
        tree = SubnetTree.SubnetTree()
        ixpip2asn = {}
        sub_to_ixp = {}
        hstring = string_handler.string_handler()
        dumped_ixps = []
        flag = True
        for line in doc:
            if flag:
                flag = False
                continue
            temp_string = line.split(',')
            if len(temp_string) > 1:
                ip = hstring.extract_ip(temp_string[1], 'IP')

                for inode in ip:
                    inode = hstring.clean_ip(inode, 'IP')
                    if hstring.is_valid_ip_address(inode, 'IP') and temp_string[3].replace(' ', '') != '':

                        subnet = hstring.extract_ip(temp_string[0], 'Subnet')
                        for snode in subnet:
                            snode = hstring.clean_ip(snode, 'Subnet')
                            if hstring.is_valid_ip_address(snode, 'Subnet'):
                                tree[snode] = snode
                                if (inode in tree and inode not in ixpip2asn.keys() and inode not in dumped_ixps and inode not in reserved_tree) or (inode in add_info_tree):
                                    ixpip2asn[inode] = [
                                        temp_string[3].replace(' ', '')]
                                elif inode in ixpip2asn.keys():
                                    if ixpip2asn[inode] != [temp_string[3].replace(' ', '')]:
                                        ixpip2asn.pop(inode, None)
                                        dumped_ixps.append(inode)
                                tree.remove(snode)
        doc.close()
        return ixpip2asn

    def pch_handle_sub(self, reserved_tree, long_mem, IXP_region):
        '''
        Extracts the IXP keys-to-Subnets from the ixp_subnets.csv file.
        Input:
            a) filename: The ixp_subnets.csv file.
            b) self.homepath: The directory path of the database.
            c) reserved_tree: The SubnetTree containing the reserved Subnets.
            d) long_mem: Dictionary containing id to long names.
            e) IXP_region: Dictionary containing {IXP Subnet} = [IXP country, IXP city].
        Output: 
            a) subnets: A dictionary with {IXP Subnet}=[IXP long name, IXP short name].
            b) IXP_cc: A dictionary with {IXP Subnet}=[IXP country,IXP region].
            c) Subnet_names: SubnetTree with Subnet to [IXP long name, IXP short name].
        '''

        handled_string = string_handler.string_handler()
        doc = self.file_opener(self.filename_subset, 1)
        IXP_cc = {}
        subnets = {}
        Subnet_names = SubnetTree.SubnetTree()
        flag = True
        for line in doc:
            if flag:
                flag = False
                continue
            temp_string = line.split(',')
            if len(temp_string) > 5:
                mykey = temp_string[0]
                myip = temp_string[6]
                myip = handled_string.extract_ip(myip, 'Subnet')
                for ips in myip:
                    ips = handled_string.clean_ip(ips, 'Subnet')
                    if ips != '' and handled_string.string_comparison(temp_string[2], 'Active'):
                        if handled_string.is_valid_ip_address(ips, 'Subnet') and ips not in subnets.keys():
                            if mykey in long_mem.keys():
                                IXP_cc[ips] = IXP_region[mykey]
                                [long_name, short_name] = handled_string.clean_long_short(
                                    long_mem[mykey], temp_string[1])
                                if len(long_name) > len(short_name):
                                    subnets[ips] = [[long_name, short_name]]
                                else:
                                    subnets[ips] = [[short_name, long_name]]

                            elif temp_string[1] != '':
                                [long_name, short_name] = handled_string.clean_long_short("", temp_string[
                                                                                          1])
                                if len(short_name) < len(long_name):
                                    subnets[ips] = [['', short_name]]
                                else:
                                    subnets[ips] = [['', long_name]]
                            else:
                                continue
                        elif ips in subnets.keys():
                            IXP_cc[ips] = IXP_region[mykey]
                            [long_name, short_name] = handled_string.clean_long_short(
                                long_mem[mykey], temp_string[1])
                            if short_name > long_name:
                                tmp_name_string = long_name
                                long_name = short_name
                                short_name = tmp_name_string
                            assigned_tuple = []
                            for IXP in subnets[ips]:
                                assigned_tuple = assigned_tuple + \
                                    handled_string.assign_names(
                                        IXP[0], short_name, IXP[1], long_name)
                            subnets[ips] = assigned_tuple

                        if ips in subnets:
                            Subnet_names[ips] = subnets[ips]

        return (subnets, IXP_cc, Subnet_names)

    def pch_handle_long(self, country2cc):
        '''
        Returns a dictionary with the IXP long names.
        Input: 
            a) filename: The ixp_exchange.csv file.
            b) self.homepath: The directory path of the database.
            c) country2cc: Dictionary that contains country names to country codes.
        Output:
            a) ixpip2long: A dictionary with {keyid}=[IXP long name].
            b) IXP_region: A dictionary with {keyid}=[IXP country, IXP city].
        '''

        doc = self.file_opener(self.filename_excha, 2)
        ixpip2long = {}
        IXP_region = {}
        flag = True
        handled_string = string_handler.string_handler()
        for line in doc:
            if flag:
                flag = False
                continue
            temp_string = line.split(',')
            if len(temp_string) > 6:
                if handled_string.string_comparison(temp_string[5], 'Active'):
                    ixpip2long[temp_string[0]] = temp_string[4]
                    country = re.sub('([^\s\w]|_)+', ' ',
                                     temp_string[2].strip())
                    country = ' '.join(self.unique_list(country.split(' ')))
                    country = re.sub(' +', ' ', country)

                    city = re.sub('([^\s\w]|_)+', ' ', temp_string[3].strip())
                    city = ' '.join(self.unique_list(city.split(' ')))
                    city = re.sub(' +', ' ', city)
                    try:
                        IXP_region[temp_string[0]] = country2cc[country], city
                    except KeyError:
                        IXP_region[temp_string[0]] = country, city

        return (ixpip2long, IXP_region)

    def file_opener(self, filename, option):
        '''
        Opens the .csv files. If they are missing, it downloads the missing file.
        Input:
            a) filename: The file name to open.
            b) self.homepath: The directory path of the database.
            c) option: Flag to select file to download.
        Output:
            a) doc: The file object.
        '''

        try:
            doc = open(self.homepath + '/database' + filename + '.csv')
        except:
            print(filename + ' was not found.')
            if not self.downloader.download_pch(option):
                print("Could not download " + filename +
                      ". Copying from the default database.")
                try:
                    copyfile(self.libpath + '/database/Default' + filename +
                             '.csv', self.homepath + '/database' + filename + '.csv')
                except:
                    print('Could not copy ' + filename +
                          'from the default database.')
            try:
                doc = open(self.homepath + '/database' + filename + '.csv')
            except:
                print('Could not open ' + filename + '. Exiting.')
                sys.exit(0)

        return doc

    def unique_list(self, l):
        return list(set(l))
