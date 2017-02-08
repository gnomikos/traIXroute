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


class string_handler():
    '''
    This modules handles the strings.
    '''

    # TODO: Change this function for IPv6
    def is_valid_ip_address(self, address, kind):
        '''
        Determines if the given string is in valid IP/Subnet form.
        Input: 
            a) address: The IP address.
            b) kind: "IP" for ip address or "Subnet" for prefix.
        Output:
            a) True if the form is valid, False otherwise.
        '''

        if(kind != 'IP' and kind != 'Subnet'):
            print("Error in argument kind. Give \"IP\" or \"Subnet\".")
            return False

        if address is None or address == '' or address == '\n':
            return False

        splitted = address.split('.')
        network = address.split('/')

        # For IP handling.
        if kind == 'IP' and len(splitted) > 3:
            try:
                for node in splitted:
                    if int(node) > 255 or int(node) < 0:
                        return False

                if splitted[-1] != '0' and splitted[-1] != '255':
                    return True
            except:
                return False

        # For Subnet Handling.
        elif kind == 'Subnet' and len(splitted) > 3 and len(network) > 1:
            try:
                for node in network[0].split('.'):
                    if int(node) > 255 or int(node) < 0:
                        print("Error in subnet format.")
                        return False
            except:
                return False

            try:
                mask = int(network[1])
                if (mask < 32) or (mask == 32 and network[0].split('.')[-1] != '0'):
                    return True
            except:
                print("Error in subnet mask:", address)
                return False

        return False

    def subnetcheck(self, string, mask):
        '''
        Converts wrong formatted subnets to valid prefixes:
            A.B.C/24 -> A.B.C.0/24
            A.B/16 -> A.B.0.0/16
            A/8 -> A.0.0.0/8
        Inputs:
            a) string: The subnet.
            b) mask: The mask of the subnet.
        Output:
            a) The valid subnet.
        '''

        subnet_dict = {'8': '.0.0.0', '16': '.0.0', '24': '.0'}
        try:
            int_mask = int(mask)
        except:
            return []
        if mask not in subnet_dict:
            return []
        else:
            ip = re.findall(
                r'[0-9]+(?:\.[0-9]+){3}/[0-9]+', string + subnet_dict[mask] + '/' + mask)
            return ip

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
                return self.subnetcheck(temp_string[0], temp_string[1]) if not ip else ip
            else:
                return []
        elif kind == 'IP':
            return re.findall(r'[0-9]+(?:\.[0-9]+){3}', string)
        else:
            print('Wrong argument type!')

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

    def string_comparison(self, string1, string2, prob=0.80):
        '''
        A function which compares the similarity of two strings.
        This function has been configured with a similarity factor (true_ratio) equals to 0.8
        Input: 
            a) string1, string2: The two strings to be compared.
            b) prob: The similarity threshold.
        Ouput:
            a) True if the strings are similar, False otherwise.
        '''

        string1 = self.string_removal(string1)
        string2 = self.string_removal(string2)
        true_ratio = difflib.SequenceMatcher(None, string1, string2).ratio()
        if string1 == '' or string2 == '':
            return False
        if true_ratio > prob:
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

        temp = IP
        if kind == 'Subnet':
            splitted = IP.split('/')
            if len(splitted) > 1:
                temp = IP.split('/')[0]
            else:
                return ''

        final = ''
        for node in temp.split('.'):
            part = ''
            i = -1
            for i in range(0, len(node) - 1):
                if node[i] != '0':
                    part = part + node[i]
                    break
            for j in range(i + 1, len(node)):
                part = part + node[j]
            if len(node) == 1:
                part = node[0]
            final = final + part + '.'
        if final[-1] == '.':
            final = final[:-1]
        if kind == 'Subnet':
            final = final + '/' + splitted[1]

        return(final)

    def check_input_ip(self, IP):
        '''
        Checks the format of an IP address.
        Input:
            a) IP: The IP to be checked.
        Ouput: 
            a) True if the IP has a valid form, False otherwise.
        '''

        temp = IP.split('.')
        if len(temp) > 4:
            return False
        for node in temp:
            if len(node) > 1 and node[0] == '0':
                return False
        return True

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
        sname1_lname2 = self.shortinlong(tmp_sname1, tmp_lname2)
        sname2_lname1 = self.shortinlong(tmp_sname2, tmp_lname1)
        sname1_sname2 = self.shortinlong(tmp_sname1, tmp_sname2)
        sname2_sname1 = self.shortinlong(tmp_sname2, tmp_sname1)
        lname1_lname2 = self.shortinlong(tmp_lname1, tmp_lname2)
        lname2_lname1 = self.shortinlong(tmp_lname2, tmp_lname1)

        if self.string_comparison(tmp_lname1, tmp_lname2):
            d3[0] = lname1
        elif tmp_lname1 == '' and tmp_lname2 != '':
            d3[0] = lname2
        elif tmp_lname1 != '' and tmp_lname2 == '':
            d3[0] = lname1

        if self.string_comparison(tmp_sname1, tmp_sname2):
            d3[1] = sname1
        elif tmp_sname1 == '' and tmp_sname2 != '':
            d3[1] = sname2
        elif tmp_sname1 != '' and tmp_sname2 == '':
            d3[1] = sname1

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
            return d3
        else:
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

        temp_string = string.split()
        new_string = ""

        for word in temp_string:
            if self.is_int(word):
                new_string = new_string + word
            else:
                new_string = new_string + " " + word

        return new_string

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

    def clean_long_short(self, long_name, short_name):
        '''
        Cleans the given long and short IXP names from unnecessary characters.
        Input:
            a) long_name, short_name: The IXP long and short names respectively.
        Output:
            a) long_name, short_name: The cleaned long and short names respectively.
        '''

        long_name = re.sub('\(.*?\)', '', long_name)
        long_name = long_name.replace(',', ' ')
        long_name = long_name.strip()
        long_name = re.sub(' +', ' ', long_name)
        short_name = re.sub('\(.*?\)', '', short_name)
        short_name = short_name.replace(',', ' ')
        short_name = short_name.strip()
        short_name = re.sub(' +', ' ', short_name)

        return long_name, short_name
