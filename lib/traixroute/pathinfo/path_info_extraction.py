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

import SubnetTree
import socket
import os


class path_info_extraction():
    '''
    This module provides the analysis of the path based on the extracted datasets.
    '''

    def __init__(self):
        # self.asn_list: A list with the AS numbers encountered in the IP path.
        self.asn_list = []
        # self.type_vector: A list with the detected types (IXP IP, Prefix,
        # Normal IP) in the IP path.
        self.type_vector = []
        # self.ixp_long_names: A list with the IXP long names in the IP path.
        self.ixp_long_names = []
        # self.ixp_short_names: A list with the IXP short names in the IP path.
        self.ixp_short_names = []
        # self.unsure: A list with flags to specify in which hop an IXP IP is
        # considered as "dirty".
        self.unsure = []

    def path_info_extraction(self, db_extract, ip_path):
        '''
        Analyses the IP path to apply the IXP detection rules.
        Input:
            a) db_extract: The database_handle class.
            b) ip_path: The IP path.
        '''

        ip2asn = db_extract.final_ixp2asn
        Subnet_tree = db_extract.subTree
        Route_tree = db_extract.asn_routeviews

        self.asn_list = ['*' for x in range(0, len(ip_path))]
        self.ixp_long_names = [['No Long Name']
                               for x in range(0, len(ip_path))]
        self.ixp_short_names = [['No Short Name']
                                for x in range(0, len(ip_path))]
        self.type_vector = ['Unresolved' for x in range(0, len(ip_path))]
        self.unsure = ['' for x in range(0, len(ip_path))]

        for i in range(0, len(ip_path)):
            path_cur = ip_path[i]

            # If there is an IXP hit.
            if path_cur in ip2asn and path_cur in Subnet_tree:
                if len(Subnet_tree[path_cur]) > 1:
                    self.unsure[i] = '? '
                # It searches the ASN of the detected IXP IP.
                self.asn_list[i] = ip2asn[path_cur][0]

                # It also searches for the IXP long/short name in the database.
                self.type_vector[i] = 'IXP IP'
                temp = Subnet_tree[path_cur]
                self.ixp_long_names[i] = []
                self.ixp_short_names[i] = []
                for IXP in temp:
                    self.ixp_long_names[i].append(IXP[0])
                    self.ixp_short_names[i].append(IXP[1])

            # Else if there is an IXP Subnet hit it finds only the IXP
            # short/long name.
            elif path_cur in Subnet_tree:
                temp = Subnet_tree[path_cur]
                self.ixp_long_names[i] = []
                self.ixp_short_names[i] = []
                for IXP in temp:
                    self.ixp_long_names[i].append(IXP[0])
                    self.ixp_short_names[i].append(IXP[1])
                self.type_vector[i] = 'IXP prefix'

            # Else for the normal IPs, it finds the ASN using the routeviews
            # dataset.
            elif path_cur in Route_tree:
                self.asn_list[i] = Route_tree[path_cur]
                self.type_vector[i] = 'Normal IP'
