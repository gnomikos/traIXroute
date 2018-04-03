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

import re
import socket
import difflib
import ipaddress
import netaddr
from fuzzywuzzy import fuzz

class string_handler():
    '''
    This modules handles the strings.
    '''

    # TODO: Change this function for IPv6
    def is_valid_ip_address(self, address, kind, dataset):
        '''
        Determines if the given string is in valid IP/Subnet form.
        Input: 
            a) address: The IP address.
            b) kind: "IP" for ip address or "Subnet" for prefix.
        Output:
            a) True if the form is valid, False otherwise.
        '''
    
        if(kind != 'IP' and kind != 'Subnet'):
            print("Wrong argument kind. Give \"IP\" or \"Subnet\".")
            return False

        if not address or address == '\n':
            return False
        else:
            # For IP handling.
            if kind == 'IP':
                try:
                    if address.endswith('.0') or address.endswith('.255'):
                        return False
                    socket.inet_aton(address)
                    return True
                except socket.error as e:
                    print('From',dataset,'error with IP:', address, '-', e)
                    return False
                
            # For Subnet Handling.
            elif kind == 'Subnet':
                try:
                    if ipaddress.IPv4Network(address):
                        return True
                except ValueError as e:
                    print('From',dataset,'error with prefix:', address, '-', e)
                except ipaddress.AddressValueError as e:
                    print('From',dataset,'error with prefix:', address, '-', e)
                except ipaddress.NetmaskValueError as e:
                    print('From',dataset,'error with prefix:', address, '-', e)

                return False

    # TODO: Change this function for IPv6
    def extract_ip(self, string, kind):
        '''
        Extracts an IP or a Subnet from a string using regular expressions.
        Input: 
            a) string: A string containing IP address or Subnet.
            b) kind: "IP" for ip address or "Subnet" for prefix.
        Output: 
            a) ip: A list of IPs or Subnets extracted from the databases.
        '''

        string = string.replace(' ', '')

        if kind == 'Subnet':
            temp_string = string.split('/')
            if len(temp_string) > 1:
                temp_string[0] = temp_string[0].strip('.')
                temp_string[1] = temp_string[1].strip('.')
                ip = re.findall(
                    r'[0-9]+(?:\.[0-9]+){3}/[0-9]+', temp_string[0] + '/' + temp_string[1])
                return ip
            else:
                return []
        elif kind == 'IP':
            return re.findall(r'[0-9]+(?:\.[0-9]+){3}', string)
        else:
            print('Wrong argument type when extracting IP or Subnet.')

    def string_removal(self, string):
        '''
        Removes unwanted characters from a string.
        Input: 
            a) string: The string to be cleaned.
        Output:
            a) string: The "cleaned" string.
        '''

        if string is None:
            string = 'None'
        elif 'NULL' in string:
            string = 'None'
        else:
            whitelist = set('abcdefghijklmnopqrstuvwxyz1234567890')
            string = string.lower()

            string = ''.join(filter(whitelist.__contains__, string))

        return (string)

    def string_comparison(self, string1, string2, prob_difflib = 0.80, prob_leven = 74):
        '''
        A function which compares the similarity of two strings.
        This function has been configured with a similarity factors (true_ratio) after manual tuning.
        Input: 
            a) string1, string2: The two strings to be compared.
            b) prob: The similarity threshold.
        Ouput:
            a) True if the strings are similar, False otherwise.
        '''

        string1 = self.string_removal(string1)
        string2 = self.string_removal(string2)
        ratio_diff = difflib.SequenceMatcher(None, string1, string2).ratio()
        ratio_leven = fuzz.WRatio(string1, string2)
        
        if string1 == '' or string2 == '':
            return False
        
        if ratio_diff > prob_difflib or ratio_leven > prob_leven:
            return True
        else:
            return False
        

    # TODO: Change this function for IPv6
    def clean_ip(self, IP, kind):
        '''
        This function cleans an IP or a Prefix, e.g., from an IP address 192.08.010.1 we get 192.8.10.1.
        Input:
            a) IP: The IP or subnet to be cleaned.
            b) kind: "IP" for IP or "Subnet" for prefix.
        Output:
            a) final: The "cleaned" IP address.
        '''

        if kind == 'Subnet':
            return str(netaddr.IPNetwork(IP).cidr)
        else:
            return str(netaddr.IPNetwork(IP).cidr).split('/')[0]

    def sub_prefix_check(self, prefix, tree):
        '''
        Checks if a given prefix/subprefix is in the SubnetTree.
        Input:
            a) prefix: The candidate prefix.
            b) tree: A SubnetTree containing prefixes.
        Output:
            a) True if the prefix is in the Subnet Tree, False otherwise.
        '''

        if prefix in tree:
            # Due to bug in SubnetTree. Returns True for a lookup of 1.1.1.0/24 when having only 1.1.1.0/25
            if int(prefix.split('/')[1]) >= int(tree[prefix].split('/')[1]):
                return True
        return False

    def assign_names(self, sname1, sname2, lname1, lname2):
        '''
        Takes as inputs the short and long IXP names of a prefix retrieved by PCH and PeeringDB and
        selects the two short and long IXP names to keep.
        Input:
            a) sname1,sname2: The short names assigned to an IXP Prefix (from pch and peeringDB).
            b) lname1,lname2: The long names assigned to an IXP Prefix (from pch and peeringDB).
        Output:
            a) d3: The output list after merging.
        '''

        d3 = ['', '']
        flag = False

        tmp_sname1 = self.concat_nums(sname1)
        tmp_sname2 = self.concat_nums(sname2)
        tmp_lname1 = self.concat_nums(lname1)
        tmp_lname2 = self.concat_nums(lname2)

        # Check if IXP names are substrings of each other.        
        sname1_lname2 = self.shortinlong(tmp_sname1, tmp_lname2)
        sname2_lname1 = self.shortinlong(tmp_sname2, tmp_lname1)
        sname1_sname2 = self.shortinlong(tmp_sname1, tmp_sname2)
        sname2_sname1 = self.shortinlong(tmp_sname2, tmp_sname1)
        lname1_lname2 = self.shortinlong(tmp_lname1, tmp_lname2)
        lname2_lname1 = self.shortinlong(tmp_lname2, tmp_lname1)

        if self.string_comparison(tmp_lname1, tmp_lname2):
            d3[0] = lname1 if len(lname1) > len(lname2) else lname2
        elif tmp_lname1 == '' and tmp_lname2 != '':
            d3[0] = lname2
        elif tmp_lname1 != '' and tmp_lname2 == '':
            d3[0] = lname1

        if self.string_comparison(tmp_sname1, tmp_sname2):
            d3[1] = sname1 if len(sname1) > len(sname2) else sname2
        elif tmp_sname1 == '' and tmp_sname2 != '':
            d3[1] = sname2
        elif tmp_sname1 != '' and tmp_sname2 == '':
            d3[1] = sname1
            
        # Comparing IXP names checking if the first IXP name is substring of the second IXP name and vice versa.
        if d3[1] == '' and d3[0] == '':
            if (sname1_lname2):
                d3 = [lname2, sname1]
            elif (sname2_lname1):
                d3 = [lname1, sname2]
            else:
                if (sname1_sname2):
                    d3 = ['', sname1]
                elif (sname2_sname1):
                    d3 = ['', sname2]
                if (lname1_lname2):
                    d3 = [lname1, '']
                elif lname2_lname1:
                    d3 = [lname2, '']
                elif d3[0] == '' and d3[1] == '':
                    d3 = [[lname1, sname1], [lname2, sname2]]
                    flag = True
        elif d3[1] == '' and d3[0] != '':
            if (sname1_lname2):
                d3 = [d3[0], sname1]
            elif (sname2_lname1):
                d3 = [d3[0], sname2]
            else:
                if (sname1_sname2):
                    d3 = [d3[0], sname1]
                elif (sname2_sname1):
                    d3 = [d3[0], sname2]
        elif d3[1] != '' and d3[0] == '':
            if (sname1_lname2):
                d3 = [lname2, d3[1]]
            elif (sname2_lname1):
                d3 = [lname1, d3[1]]
                if lname1_lname2:
                    d3 = [lname1, d3[1]]
                elif lname2_lname1:
                    d3 = [lname2, d3[1]]

        if flag:
            for i in range(len(d3)):
                if d3[i][0] == '':
                    d3[i][0] = d3[i][1]
                elif d3[i][1] == '':
                    d3[i][1] = d3[i][0]
            return d3
        else:
            if d3[0] == '':
                d3[0] = d3[1]
            elif d3[1] == '':
                d3[1] = d3[0]
            return [d3]

    def shortinlong(self, sname, lname):
        '''
        Checks if the short IXP name is in the long IXP name.
        Input:
            a) sname: The IXP short name.
            b) lname: The IXP long name.
        Output:
            a) True if the short name exists in the long name, False otherwise.
        '''

        if sname == '' or lname == '':
            return False
        whitelist = set('abcdefghijklmnopqrstuvwxyz1234567890 ')
        sname = sname.lower()
        sname = re.sub('([^\s\w]|_)+', ' ', sname.strip())
        sname = re.sub(' +', ' ', sname)
        lname = lname.lower()
        lname = re.sub('([^\s\w]|_)+', ' ', lname.strip())
        lname = re.sub(' +', ' ', lname)
        shorter = sname.split(' ')
        larger = lname.split(' ')

        for word in shorter:
            if word not in larger:
                return False
        return True

    def concat_nums(self, string):
        '''
        Concatenates numbers with strings in the IXP names, e.g.: IXP Lon 1 becomes IXP Lon1.
        Input:
            a) string: The candidate IXP name.
        Output:
            a) new_String: The IXP name with the concatenated numbers.
        '''

        new_string = ''

        for word in string.split():
            if self.is_int(word):
                new_string = new_string + word
            else:
                new_string = new_string + ' ' + word

        return new_string.strip()

    def is_int(self, myint):
        '''
        Checks if the given string can be converted to an integer.
        Input:
            a) myint: The candidate string.
        Output:
            a) True if a string number can be converted to an integer, False otherwise.
        '''

        try:
            int(myint)
            return True
        except ValueError:
            return False

    def clean_ixp_name(self, ixp_name):
    
        ixp_name = re.sub('\(.*?\)', '', ixp_name)
        ixp_name = ixp_name.replace(',', ' ')
        ixp_name = ixp_name.strip()
        ixp_name = re.sub(' +', ' ', ixp_name)
        
        return ixp_name
    
    def clean_long_short(self, long_name, short_name):
        '''
        Cleans the given long and short IXP names from unnecessary characters.
        Input:
            a) long_name, short_name: The IXP long and short names respectively.
        Output:
            a) long_name, short_name: The cleaned long and short names respectively.
        '''

        return self.clean_ixp_name(long_name), self.clean_ixp_name(short_name)
        
    def format_country_city(self, entry):
        entry = re.split('/|,|&', entry.strip())
        
        return '|'.join([item.strip() for item in entry])
        
