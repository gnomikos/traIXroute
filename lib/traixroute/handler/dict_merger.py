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

from traixroute.controller import string_handler
from collections import defaultdict
import re
import itertools


class dict_merger():
    '''
    Handles the merging of dictionaries from pch, pdb and the additional info (i.e., IXP Prefixes-to-IXP Names and IXP IPs-to-IXP Names.).
    '''

    def merge_keys2names(self, d1, d2):
        '''
        Returns a dictionary C containing the union of the dictionaries A and B. 
        The input dictionaries contain key-to-IXP long, short name entries. The key values can be either IXP Prefix or IP.
        E.g.: if A[id1]=[a,b], B[id1]=[c,d] then C[id1]=[a,b], if a is similar to c and b is similar to d. [a,b] are the valid IXP long and short names for the IXP subnet.
        Input:
            a) d1,d2: The two dictionaries to be merged.
        Output:
            a) d1 or d2: The output dictionary after merging. 
        '''

        handle = string_handler.string_handler()
        
        for k in d1:
            if k in d2:
                assign_tuple = []
                for IXP1 in d1[k]:
                    for IXP2 in d2[k]:
                        assign_tuple = assign_tuple + \
                            handle.assign_names(
                                IXP1[1], IXP2[1], IXP1[0], IXP2[0])
                deleted = []
                for i in range(0, len(assign_tuple) - 1):
                    for j in range(i + 1, len(assign_tuple)):
                        if len(handle.assign_names(assign_tuple[i][0], assign_tuple[j][0], assign_tuple[i][1], assign_tuple[j][1])) == 1:
                            if j not in deleted:
                                deleted = [j] + deleted
                                
                for node in deleted:
                    del assign_tuple[node]

                d2[k] = assign_tuple
            else:
                d2[k] = d1[k]
        return d2

    def include_additional_prefixes(self, final_sub2name, subTree, additional_subnet2name, final_subnet2country, additional_pfx2cc, help_tree, additional_ixp_ip2asn):
        '''
        Includes the additional info subnet2names to the final dictionaries.
        Input:
            a) final_sub2name: The final {IXP Subnet}=[[IXP name long, IXP name short]] dictionary.
            b) subTree: The final [IXP Subnet]=[IXP name long, IXP name short].
            c) additional_subnet2name: The user imported {IXP Subnet}=[[IXP name long, IXP name short]].
            d) help_tree: SubneTree containing the IXP Subnets.
            e) final_subnet2country: subTree: The final [IXP Subnet]=[[IXP name long, IXP name short]].
            f) additional_ixp_ip2asn: {IXP IP} = ASN, all the IXP IPs from additional file.
        Output:
            a) subTree: The final [IXP Subnet]=[[IXP name long, IXP name short]].
            b) final_sub2name: The final dictionary with {IXP Subnet} = [[IXP long name, IXP short name]].
            c) final_subnet2country: A dictioanry containing {IXP Subnet} = [ IXP country, IXP city].
        '''

        handle = string_handler.string_handler()

        for pfx in additional_subnet2name:
            # Include and/or overwrite existing PDB & PCH prefixes based on additional prefixes.
            if handle.sub_prefix_check(pfx, help_tree) and pfx.split('/')[0] not in additional_ixp_ip2asn:
                
                subTree.remove(help_tree[pfx])
                final_sub2name.pop(help_tree[pfx])
                final_subnet2country.pop(help_tree[pfx])
                help_tree.remove(help_tree[pfx])
                
            final_sub2name[pfx]       = [additional_subnet2name[pfx]]
            subTree[pfx]              = [additional_subnet2name[pfx]]
            final_subnet2country[pfx] = additional_pfx2cc[pfx]

        return (subTree, final_sub2name, final_subnet2country)

    def merge_ixp2asns(self, d1, d2, flag, Subnet_tree, replace=False):
        '''
        This function merges two {IP}=[ASN] dictionaries and returns a merged dictionary.
        Input:
            a) d1,d2: The two dictionaries to be merged.
            b) Subnet_tree: The Subnet tree that contains the IXP subnets.
            c) flag: A flag that specifies the need to search for dirty IXPs or not.
            d) replace: A Flag that specifies if dictionary d1 has higher priority than d2.
        Output: 
            a) d3: The output dictionary after merging.
        '''
        
        if replace:
            for key in d1:
                d2[key] = d1[key]
            return d2 
            
        if len(d2) > len(d1):
            big     = d2
            small   = d1
        else:
            big     = d1
            small   = d2            
        
        dirty_count = 0

        for k in small:
            if k in big:
                if big[k][0] == '' and small[k][0] != '':
                    big[k][0] = small[k][0]
                # Exlude an IXP IP when it maps to different ASNs.
                elif big[k][0] and small[k][0] and big[k][0] != small[k][0]:
                    big.pop(k)
            else:
                big[k] = small[k]
        if flag:
            keys = list(big.keys())
            for key in keys:
                # Exclude an IXP - IP when it does not map to an IXP - Prefix. This means that for this IXP IP is not possible to have a mapping to an IXP Name. Because, all the IXP names come from the IXP Prefixes.
                if key not in Subnet_tree:
                    big.pop(key)
                elif len(Subnet_tree[key]) > 1:
                    dirty_count += 1
            return big, dirty_count
        else:
            return big

    def merge_cc(self, d1, d2):
        '''
        Returns a dictionary C containing the union of the dictionaries A and B. 
        The input dictionaries contain key-to-IXP long, short name entries. The key values can be either IXP Prefix or IP.
        E.g.: if A[id1]=[a,b], B[id1]=[c,d] then C[id1]=[a,b], if and only if a is similar to c and b is similar to d. [a,b] are the valid IXP long and short names for the IXP subnet.
        Input:
            a) d1,d2: The two dictionaries to be merged.
        Output:
            a) d1 or d2: The output dictionary after merging.
        '''
        
        handle = string_handler.string_handler()
        
        if len(d2) > len(d1):
            big     = d2
            small   = d1
        else:
            big     = d1
            small   = d2
        
        for k in small:
            if k in big:
                # Compare countries and cities between the two dictionaries
                # example entries of dicts {'198.32.118.0/24': ['US', 'New York']}
                mytuple = self.assign_countries(
                    small[k][0], big[k][0], small[k][1], big[k][1])
                if mytuple != []:
                    big[k] = mytuple
                else:
                    big.pop(k)
            else:
                big[k] = small[k]
        return big

    def assign_countries(self, country1, country2, city1, city2):
        '''
        Takes as inputs countries and cities retrieved by PCH and PeeringDB assigned to a certain prefix and selects the countries and the cities to keep.
        Input:
            a) country1,country2: The country names assigned to an IXP Prefix (from pch and peeringDB).
            b) city1,city2: The city names assigned to an IXP Prefix (from pch and peeringDB).
        Output:
            a) The [country,city] list after merging.
        '''

        string_handle = string_handler.string_handler()
        country = ''
        city = ''
        
        # Comparing IXP countries.
        if string_handle.string_comparison(country1, country2):
            country = country1
        elif country1 == '' and country2 != '':
            country = country2
        elif country1 != '' and country2 == '':
            country = country1
        # Both countries are different
        if country == '':
            country = country1 + '//' + country2

        # Comparing IXP cities.
        if string_handle.string_comparison(city1, city2):
            city = city2
        elif city1 == '' and city2 != '':
            city = city2
        elif city1 != '' and city2 == '':
            city = city1
        # Both cities are different 
        if city == '':
            if string_handle.shortinlong(city1, city2):
                city = city2
            elif string_handle.shortinlong(city2, city1):
                city = city1
            else:
                city = city1 + '//' + city2
                
        return [country, city] if country != '' and city != '' else []
        
