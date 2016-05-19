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

import SubnetTree,socket,os

'''
   This module provides the analysis of the path based on the extracted datasets.
'''

class path_info_extraction():

    '''
    Analyses the IP path to apply the IXP detection rules.
    Input:
        a) ip2asn: A dictionary with {IXP IP}=[ASN].
        b) Subnet_tree: The Subnet Tree with the IXP Subnets.
        c) ip_path: The IP path.
        d) Route_tree: A Subnet Tree with Subnet-to-ASN entries from routeviews.
        e) subnet2name: A dictionary with {IXP Subnet}=[IXP long name, IXP short name].
        f) ip2name: A dictionary with {IXP IP}=[IXP long name,IXP short name]. It is about "dirty" IXP IP addresses.
        g) dirty_ixp2asn: A dictionary with {IXP IP}=[ASN]. It is about "dirty" IXP IP addresses.
        h) additional_info_tree: The Subnet Tree with the IXP related data provided by the user.
    Ouput:
        a) asn_list: A list with the AS numbers encountered in the IP path.
        b) type_vector: A list with the detected types (IXP IP, Prefix, Normal IP) in the IP path. 
        c) ixp_long_names: A list with the IXP long names in the IP path.
        d) ixp_short_names: A list with the IXP short names in the IP path.
        e) unsure: A list with flags to specify in which hop an IXP IP is considered as "dirty".
    '''
    def path_info_extraction(self,ip2asn,Subnet_tree,ip_path,Route_tree,subnet2name,ip2name,dirty_ixp2asn,additional_info_tree):
       
        asn_list = ['*' for x in range(0,len(ip_path))]
        ixp_long_names = ['Not IXP' for x in range(0,len(ip_path))]
        ixp_short_names = ['Not IXP' for x in range(0,len(ip_path))]
        type_vector = ['Unresolved' for x in range(0,len(ip_path))]
        unsure = ['' for x in range(0,len(ip_path))]

        for i in range(0,len(ip_path)):
            path_cur=ip_path[i]

            # If there is an IXP hit.
            if path_cur in ip2asn.keys():

                # It searches the ASN of the detected IXP IP.
                if len(ip2asn[path_cur])>0:
                    asn_list[i]=ip2asn[path_cur][0]
                
                # It also searches for the IXP long/short name in the database.
                type_vector[i]='IXP IP'
                if path_cur in additional_info_tree:
                    temp=additional_info_tree[path_cur]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]                    
                elif path_cur in ip2name.keys():
                    temp=ip2name[path_cur]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]
                elif path_cur in Subnet_tree:
                    subnet=Subnet_tree[path_cur]
                    temp=subnet2name[subnet]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]
            #else if it is a dirty IXP IP.
            elif path_cur in dirty_ixp2asn.keys():

                # It searches the ASN of the detected IXP IP in the database.
                asn_list[i]=dirty_ixp2asn[path_cur][0]
                unsure[i]='? '

                # It also searches for the IXP long/short name in the database.
                type_vector[i]='IXP IP'
                if path_cur in additional_info_tree:
                    temp=additional_info_tree[path_cur]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]   
                elif path_cur in ip2name.keys():
                    temp=ip2name[path_cur]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]
                elif path_cur in subnet2name.keys():
                    temp=subnet2name[path_cur]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]

            # Else if there is an IXP Subnet hit it finds only the IXP short/long name.         
            elif path_cur in Subnet_tree:
                path_cur=Subnet_tree[path_cur]
                if path_cur in subnet2name.keys():
                    temp=subnet2name[path_cur]
                    ixp_long_names[i]=temp[0]
                    ixp_short_names[i]=temp[1]
                type_vector[i]='IXP prefix'

            # Else for the normal IPs, it finds the ASN using the routeviews dataset.
            elif path_cur in Route_tree:
                asn_list[i]=Route_tree[path_cur].split(',')[1]
                type_vector[i]='Normal IP'

        return (asn_list,type_vector,ixp_long_names,ixp_short_names,unsure)