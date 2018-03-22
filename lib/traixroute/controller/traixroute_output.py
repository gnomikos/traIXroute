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
from time import ctime
import os
import socket
import sys
import ujson
import time
import itertools
import ntpath
import datetime


class traixroute_output():
    '''
    Handles all the outputs.
    '''

    def __init__(self):
        
        self.measurement_json = {
            'ixp_crossings': [],
            'remote_peering': [],
            'possible_ixp_crossings': []
        }

        self.measurement_info   = ''
        self.ixp_hops           = ''
        self.remote_hops        = ''
        self.unknown_hops       = ''
        # A list with all the analyzed paths to export to json file
        self.json_obj = []  
        # A list with all the analyzed paths to export to .txt file
        self.txt_obj  = []   

    def flush(self, traixparser):
        '''
        Prints the data and flushes them to a file.
            a) traixparser: The instance of parser that specifies which of the traIXroute command line arguments have been enabled.
        '''
        
        # Complements content output.
        output = self.measurement_info
        if self.ixp_hops != '':
            output += 'IXP hops:\n'          + self.ixp_hops
        if self.remote_hops != '':
            output += 'Remote Peering:\n'    + self.remote_hops
        if self.unknown_hops != '':
            output += 'Possible IXP hops:\n' + self.unknown_hops
        if len(self.measurement_json['ixp_crossings']) == 0:
            del self.measurement_json['ixp_crossings']
        if len(self.measurement_json['remote_peering']) == 0:
            del self.measurement_json['remote_peering']
        if len(self.measurement_json['possible_ixp_crossings']) == 0:
            del self.measurement_json['possible_ixp_crossings']

        # SupplementS the relative output lists.
        if not traixparser.flags['silent']      : print(output)
        if traixparser.flags['outputfile_txt']  : self.txt_obj.append(output)
        if traixparser.flags['outputfile_json'] : self.json_obj.append(self.measurement_json)

        self.measurement_info   = ''
        self.ixp_hops           = ''
        self.remote_hops        = ''
        self.unknown_hops       = ''
        self.measurement_json = {
            'ixp_crossings': [],
            'remote_peering': [],
            'possible_ixp_crossings': []
        }

    def print_db_stats(self, peering_ixp2asn, peering_sub2name, pch_ixp2asn, pch_sub2name, final_ixp2asn, final_sub2name, dirty_ips, additional_ip2asn, additional_subnet2name, lenreserved, db_print, mypath):
        '''
        Prints the number of the extracted IXP IP addresses and Subnets from each dataset before and after merging.
        Input:
            a) peering_ixp2asn: A dictionary with {IXP IP}=[ASN] extracted from peeringdb.
            b) peering_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] extracted from peeringdb. 
            c) pch_ixp2asn: A dictionary with {IXP IP}=[ASN] extracted from pch.
            d) pch_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] extracted from pch.
            e) final_ixp2asn: A dictionary with {IXP IP}=[ASN] after merging pch, peeringdb and user's data.
            f) final_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] after merging pch, peeringdb and user's data.
            g) dirty_ips: The number of dirty ips. 
            h) additional_ip2asn: A dictionary with {IXP IP}=[ASN] specified by the user.
            i) additional_subnet2name: A dictionary with {IXP Subnet}=[IXP long name, IXP short name] specified by the user.
            j) lenreserved: The number of the imported reserved subnets.
            k) db_print: Flag to output the db stats. 
            l) mypath: The path to the database.
        '''

        tmp = 'Imported ' + str(lenreserved) + ' Reserved Subnets.\n'
        tmp = tmp + 'Extracted ' + \
            str(len(additional_ip2asn)) + \
            ' IXP IPs from additional_info.txt.\n'
        tmp = tmp + 'Extracted ' + str(len(additional_subnet2name) - len(
            additional_ip2asn)) + ' IXP Subnets from additional_info.txt.\n'
        tmp = tmp + 'Extracted ' + \
            str(peering_ixp2asn) + ' IXP IPs from PDB.\n'
        tmp = tmp + 'Extracted ' + str(pch_ixp2asn) + ' IXP IPs from PCH.\n'
        tmp = tmp + 'Extracted ' + \
            str(peering_sub2name) + ' IXP Subnets from PDB.\n'
        tmp = tmp + 'Extracted ' + \
            str(pch_sub2name) + ' IXP Subnets from PCH.\n'
        tmp = tmp + 'Extracted ' + \
            str(len(final_ixp2asn)) + \
            ' (no) dirty IXP IPs after merging PDB, PCH and additional_info.txt.\n'
        tmp = tmp + 'Detected ' + \
            str(dirty_ips) + \
            ' dirty IXP IPs after merging PDB, PCH and additional_info.txt.\n'
        tmp = tmp + 'Extracted ' + \
            str(len(final_sub2name)) + \
            ' IXP Subnets after merging PDB, PCH and additional_info.txt.\n'
        if db_print:
            print(tmp)
        try:
            with open(mypath + 'db.txt', 'w') as f:
                f.write(tmp)
        except:
            print('Could not open db.txt file. Exiting.')
            sys.exit(0)

    def print_path_info(self, ip_path, mytime, path_info_extract, traIXparser):
        '''
        Prints and exports the IP path to a file.
        Input:
            a) ip_path: The IP path.
            b) asn_list: A list with the ASNs in the IP path.
            c) mytime: The hop delays.
            d) mypath: The traIXroute directory path.
            e) path_info_extract: The path_info_extract class.
            f) traIXparser: Dictionary that contains the user input flags.
        '''

        asn_list = path_info_extract.asn_list
        ixp_short_names = path_info_extract.ixp_short_names
        ixp_long_names = path_info_extract.ixp_long_names
        unsure = path_info_extract.unsure
        asn_print = traIXparser.flags['asn']
        dns_print = traIXparser.flags['dns']
        size = len(ip_path)

        # Makes dns queries.
        dns = [''] * size
        if dns_print:
            for i,item in enumerate(ip_path):
                if item != '*':
                    try:
                        dns[i] = socket.gethostbyaddr(item)[0]
                    except:
                        dns[i] = item
        
        # The minimum space between the printed strings.
        defaultstep = 3

        # The numbers to be printed in front of each line.
        numbers = [str(x) + ')' for x in range(1, size + 1)]

        # Fix indents for printing.
        maxlenas = 0
        maxlennum = 0
        gra_path = ['*'] * size
        gra_asn = [''] * size

        for i in range(0, size):
            temp = len('AS' + asn_list[i])
            if temp > maxlenas:
                maxlenas = temp
            temp = len(numbers[i])
            if temp > maxlennum:
                maxlennum = temp

        for i in range(0, size):
            gra_path[i] = self.polish_output(
                numbers[i], maxlennum + defaultstep)
            if asn_print:
                gra_asn[i] = self.polish_output(
                    'AS' + asn_list[i], maxlenas + defaultstep)
            else:
                gra_asn[i] = self.polish_output(
                    'AS' + asn_list[i], len('AS' + asn_list[i]) + defaultstep)

        # Prints the output and saves it to a file.
        print_data = ''
        for i in range(0, size):
            if ixp_short_names[i] == ['No Short Name'] and ixp_long_names[i] == ['No Long Name']:
                if asn_print:
                    temp_print = gra_path[i] + gra_asn[i] + dns[i] + \
                        ' ' + '(' + ip_path[i] + ')' + ' ' + mytime[i]
                else:
                    temp_print = gra_path[i] + dns[i] + ' ' + \
                        '(' + ip_path[i] + ')' + ' ' + mytime[i]
            else:
                base_ixp_print = '('
                for ixp in range(0, len(ixp_short_names[i])):
                    if ixp:
                        base_ixp_print = base_ixp_print + ','
                    if ixp_short_names[i][ixp] != '':
                        base_ixp_print = base_ixp_print + ixp_short_names[i][ixp]
                    else:
                        base_ixp_print = base_ixp_print + ixp_long_names[i][ixp]
                base_ixp_print = base_ixp_print + ')'
                temp_print = gra_path[i] + unsure[i] + base_ixp_print + '->' + gra_asn[
                    i] + dns[i] + ' ' + '(' + ip_path[i] + ')' + ' ' + mytime[i]

            print_data += temp_print + '\n'

        self.measurement_info += print_data

    def print_traIXroute_dest(self, traixparser, db_extract, dns_print, dst_ip, src_ip='', info=''):
        '''
        Prints traIXroute destination.
        Input:
            a) dns_print: Flag to enable resolving IP or FQDN.
            b) dst_ip: The destination IP/FQDN to probe.
            c) src_ip: The IP that issued the probe (optional).
            d) info: Traceroute path description.
        '''
    
        string_handle = string_handler.string_handler()
        print_data = 'traIXroute'
        dns_name = '*'
        output_IP = '*'
        if string_handle.is_valid_ip_address(dst_ip, 'IP', 'CLI'):
            if dns_print:
                try:
                    dns_name = socket.gethostbyaddr(dst_ip)[0]
                except:
                    pass
            output_IP = dst_ip
        else:
            if dns_print:
                try:
                    output_IP = socket.gethostbyname(dst_ip)
                except:
                    pass
            dns_name = dst_ip
        if src_ip != '':
            origin_dns = '*'
            if dns_print:
                try:
                    origin_dns = socket.gethostbyaddr(src_ip)[0]
                except:
                    pass
            print_data += ' from ' + origin_dns + ' (' + src_ip + ')'

        if traixparser.flags['asn']:
            if src_ip in db_extract.asn_routeviews:
                print_data += ' AS'+db_extract.asn_routeviews[src_ip]
            elif src_ip:
                print_data += ' AS*'
        
        print_data += ' to ' +  dns_name + ' (' + output_IP + ')'
        if traixparser.flags['asn']:
            if output_IP in db_extract.asn_routeviews:
                print_data += ' AS'+db_extract.asn_routeviews[output_IP]
            else:
                print_data += ' AS*'
           
        if info != '':
            print_data += ' info: ' + info

        self.measurement_info += print_data + '\n'

    def polish_output(self, string1, number1):
        '''
        Sanitizes traIXroute output.
        Input: 
            a) string1: The string to be modified.
            b) number1: The number of empty spaces between strings.
        Ouput:
            a) string1: The polished output of traIXroute with the columns to be aligned.
        '''

        while len(string1) < number1:
            string1 = string1 + ' '
        return string1

    def print_rules_number(self, final_rules, file):
        '''
        Prints the number of extracted rules.
        Input:
            a) final_rules: The list containing the rules.
            b) file: The file containing the rules.
        '''

        print("Imported", len(final_rules),
              "IXP detection rules from", file + ".")

    def print_result(self, asn_print, print_rule, cur_ixp_long, cur_ixp_short, cur_path_asn, path, i, j, num, ixp_short, cur_asmt, ixp_long, cc_tree, remote_peering=None):
        '''
        Prints IXP Hops if they exist.
        Input: 
            a) asn_print: True if the user wants to print the ASNs, False otherwise.
            b) print_rule: True if the user wants to print the rule that infered the IXP crossing, False otherwise.
            c) cur_ixp_long:  A list that contains the IXP long names for the current window.
            d) cur_ixp_short: A list that contains the IXP short names for the current window.
            e) cur_path_asn: A list that contains the ASNs for the current window.
            f) path: The IP path.
            g) i: The current position in the path.
            h) j: The current rule position in the rules list.
            i) num: The number of detected IXP Hops.
            j) ixp_short: A list that contains short IXP names.
            k) cur_asmt: The current assesment.
            l) ixp_long: A list that contains long IXP names.
            m) cc_tree: SubnetTree that contains Subnets to [country,city].
            n) remote_peering: A flag to indicate a potential IXP crossing link based on remote peering connectivity.
        '''
        
        ixp_crossing = None
        unknown_hop = None
        remote_crossing = None
        rule = ''
        if print_rule:
            rule = 'Rule: ' + str(j + 1) + ' --- '

        gra_asn = [''] * len(cur_path_asn)
        ixp_string = [''] * len(cur_ixp_short)
        ixp_dict = [{}] * len(cur_ixp_short)

        for pointer in range(0, len(ixp_string)):
            if len(ixp_short) > i + pointer - 1:
                if ixp_short[i + pointer - 1] != ['No Short Name']:
                    cc_code = ['', '']
                    if path[i + pointer - 1] in cc_tree:
                        cc_code = cc_tree[path[i + pointer - 1]]
            if cur_ixp_short[pointer] != 'No Short Name':
                if cur_ixp_short[pointer] != '':
                    ixp_string[pointer] = cur_ixp_short[pointer] + \
                        ' (' + cc_code[0] + ',' + cc_code[1] + ')'
                    ixp_dict[pointer] = {
                        'name': cur_ixp_short[pointer],
                        'cc': cc_code[0],
                        'city': cc_code[1],
                    }
                else:
                    ixp_string[pointer] = cur_ixp_long[pointer] + \
                        ' (' + cc_code[0] + ',' + cc_code[1] + ')'
                    ixp_dict[pointer] = {
                        'name': cur_ixp_short[pointer],
                        'cc': cc_code[0],
                        'city': cc_code[1],
                    }
        asm_a = ixp_string[0]
        asm_a_dict = []

        if bool(ixp_dict[0]):
            asm_a_dict.append(ixp_dict[0])

        temp_print = ''
        if ixp_string[0] != '' and ixp_string[1] != '' and ixp_string[0] != ixp_string[1]:
            asm_a += ','
        if ixp_string[1] != '' and ixp_string[0] != ixp_string[1]:
            asm_a += ixp_string[1]
            if bool(ixp_dict[1]):
                asm_a_dict.append(ixp_dict[1])

        if len(ixp_string) > 2:
            asm_b = ixp_string[1]
            asm_b_dict = []
            if bool(ixp_dict[1]):
                asm_b_dict.append(ixp_dict[1])
            if ixp_string[1] != '' and ixp_string[2] != '' and ixp_string[2] != ixp_string[1]:
                asm_b += ','
            if ixp_string[2] != '' and ixp_string[1] != ixp_string[2]:
                asm_b += ixp_string[2]
                if bool(ixp_dict[2]):
                    asm_b_dict.append(ixp_dict[2])

        if asn_print:
            for pointer in range(0, len(gra_asn)):
                gra_asn[pointer] = ' (AS' + cur_path_asn[pointer] + ')'

        if 'a' in cur_asmt:
            temp_print = rule + str(i) + ') ' + path[i - 1] + gra_asn[
                0] + ' <--- ' + asm_a + ' ---> ' + str(i + 1) + ') ' + path[i] + gra_asn[1] + '\n'

            ixp_crossing = {
                'crossing': []
            }

            if print_rule:
                ixp_crossing['assesment'] = cur_asmt
                ixp_crossing['rule'] = str(j + 1)

            crossing = {
                'source': {
                    'hop': str(i),
                    'addr': path[i - 1],
                },
                'dest': {
                    'hop': str(i + 1),
                    'addr': path[i],
                },
                'ixp': asm_a_dict,
            }

            if asn_print:
                crossing['source']['asn'] = cur_path_asn[0]
                crossing['dest']['asn'] = cur_path_asn[1]

            ixp_crossing['crossing'].append(crossing)

            if 'aorb' in cur_asmt:
                temp_print += ' or ' + str(i + 1) + ') ' + path[i] + gra_asn[
                    1] + ' <--- ' + asm_b + ' ---> ' + str(i + 2) + ') ' + path[i + 1] + gra_asn[2] + '\n'
                crossing = {
                    'source': {
                        'hop': str(i + 1),
                        'addr': path[i],
                    },
                    'dest': {
                        'hop': str(i + 2),
                        'addr': path[i + 1],
                    },
                    'ixp': asm_b_dict,
                }

                if asn_print:
                    crossing['source']['asn'] = cur_path_asn[1]
                    crossing['dest']['asn'] = cur_path_asn[2]

                ixp_crossing['crossing'].append(crossing)

            elif 'aandb' in cur_asmt:
                temp_print += ('and (' + str(i + 1) + ') ' + path[i] + gra_asn[
                               1] + ' <--- ' + asm_b + ' ---> ' + str(i + 2) + ') ' + path[i + 1] + gra_asn[2]) + '\n'

                crossing = {
                    'source': {
                        'hop': str(i + 1),
                        'addr': path[i],
                    },
                    'dest': {
                        'hop': str(i + 2),
                        'addr': path[i + 1],
                    },
                    'ixp': asm_b_dict,
                }

                if asn_print:
                    crossing['source']['asn'] = cur_path_asn[1]
                    crossing['dest']['asn'] = cur_path_asn[2]

                ixp_crossing['crossing'].append(crossing)

        elif 'b' in cur_asmt:
            temp_print = rule + str(i + 1) + ') ' + path[i] + gra_asn[
                1] + ' <--- ' + asm_b + ' ---> ' + str(i + 2) + ') ' + path[i + 1] + gra_asn[2] + '\n'

            ixp_crossing = {
                'crossing': []
            }

            if print_rule:
                ixp_crossing['assesment'] = cur_asmt
                ixp_crossing['rule'] = str(j + 1)

            crossing = {
                'source': {
                    'hop': str(i + 1),
                    'addr': path[i],
                },
                'dest': {
                    'hop': str(i + 2),
                    'addr': path[i + 1],
                },
                'ixp': asm_b_dict,
            }

            if asn_print:
                crossing['source']['asn'] = cur_path_asn[1]
                crossing['dest']['asn'] = cur_path_asn[2]

            ixp_crossing['crossing'].append(crossing)

        elif '?' in cur_asmt:
            self.unknown_hops += rule + str(i) + ') ' + path[i - 1] + gra_asn[
                0] + ' <--- ' + asm_a + ' ---> ' + str(i + 1) + ') ' + path[i] + gra_asn[1] + '\n'
            unknown_hop = {
                'crossing': []
            }

            if print_rule:
                unknown_hop['assesment'] = cur_asmt
                unknown_hop['rule'] = str(j + 1)

            crossing = {
                'source': {
                    'hop': str(i),
                    'addr': path[i - 1]
                },
                'dest': {
                    'hop': str(i + 1),
                    'addr': path[i]
                },
                'ixp': asm_a_dict,
            }

            if asn_print:
                crossing['source']['asn'] = cur_path_asn[0]
                crossing['dest']['asn'] = cur_path_asn[1]

            unknown_hop['crossing'].append(crossing)

        if temp_print != '' and temp_print not in self.ixp_hops:
            self.ixp_hops += temp_print
        
        if remote_peering is not None:
            remote_data = remote_peering.find_and_print(
                path[i - 1:i + 2], asm_a)

            if(remote_data is not None):
                if('continent' in remote_data):
                    self.remote_hops += rule + str(i) + ') ' +\
                        path[i - 1:i + 2][remote_peering.indexes[remote_peering.temp_index]] +\
                        ' (AS' + remote_data['asn'] + ',' + remote_data['continent'] + ',' +\
                        remote_data['city'] + ',' + str("{0:.2f}".format(round(float(remote_data['median_rtt']), 2))) +\
                        'ms)' + ' <---> ' + asm_a + '\n'

                    remote_crossing = {
                        'hop': str(i),
                        'ip': path[i - 1:i + 2][remote_peering.indexes[remote_peering.temp_index]],
                        'asn': remote_data['asn'],
                        'continent': remote_data['continent'],
                        'city': remote_data['city'],
                        'rtt': str("{0:.2f}".format(round(float(remote_data['median_rtt']), 2))) + 'ms',
                        'ixp': asm_a_dict,
                    }
                else:
                    self.remote_hops += rule + str(i) + ') ' +\
                        path[i - 1:i + 2][remote_peering.indexes[remote_peering.temp_index]] +\
                        ' (AS' + remote_data['asn'] + ',' +\
                        remote_data['city'] + ',' + str("{0:.2f}".format(round(float(remote_data['median_rtt']), 2))) +\
                        'ms)' + ' <---> ' + asm_a + '\n'
                    remote_crossing = {
                        'hop': str(i),
                        'ip': path[i - 1:i + 2][remote_peering.indexes[remote_peering.temp_index]],
                        'asn': remote_data['asn'],
                        'city': remote_data['city'],
                        'rtt': str("{0:.2f}".format(round(float(remote_data['median_rtt']), 2))) + 'ms',
                        'ixp': asm_a_dict,
                    }

        if ixp_crossing != None:
            self.measurement_json['ixp_crossings'].append(ixp_crossing)
        if remote_crossing != None:
            self.measurement_json['remote_peering'].append(remote_crossing)
        if unknown_hop != None:
            self.measurement_json['possible_ixp_crossings'].append(unknown_hop)
        
    def print_args(self, classic, search, arguments, from_ripe, from_import):
        '''
        Prints the arguments of traceroute
        Input:
            a) classic: Flag to choose between traceroute and scamper.
            b) search: Flag to start a measurement.
            c) arguments: Probing arguments.
            d) from_ripe: Flag when usisn ripe.
            e) from_import: Flag when importing from json file.
        '''

        # Remove the key argument from printing.
        if 'key' in arguments:
            del arguments['key']

        if classic and search:
            if arguments != '':
                print('traIXroute using scamper with "' +
                      arguments + '" options.')
            else:
                print('traIXroute using scamper with default options.')
        elif search and not (from_ripe or from_import):
            if arguments != '':
                print('traIXroute using traceroute with "' +
                      arguments + '" options.')
            else:
                print('traIXroute using traceroute with default options.')
        elif from_ripe == 1:
            print(
                'Run traIXroute fetching results from ripe measurement:', arguments)
        elif from_ripe == 2:
            print('Creating a new measurement at RIPE Atlas:', arguments)
        elif from_import == 1:
            print(
                'Run traIXroute from file with traIXroute json format:', arguments)
        elif from_import == 2:
            print('Run traIXroute from file with ripe json format:', arguments)

    def print_pr_db_stats(self, filepath):
        '''
        Prints the number of the extracted IXP IP addresses and Subnets from each dataset for the last time the datasets were merged. 
        Input:
            a) filepath: The directory path of the file that contains the stats.
        '''

        try:
            with open(filepath, 'r') as f:
                print(f.read())
        except:
            print('Could not open db.txt.')

    def read_lst_mod(self, filename, fname2):
        '''
        Reads the lst_mod.txt file, which contains the last modification of the additional_info.txt and compares it
        with the current modification timestamp of the additional_info.txt.
        Input:
            a) filename: The lst_mod.txt file.
            b) mypath: The path to traIXroute folder.
        Output:
            a) True if the file has not been modified, False otherwise.
        '''

        additional_lst_mod = ctime(os.path.getmtime(fname2))
        if (os.path.isfile(filename)):
            with open(filename, 'r') as f:
                data = f.read()
                if data.split('\n')[0] == additional_lst_mod:
                    return True

        else:
            self.write_lst_mod(filename, additional_lst_mod)
            return False

    def write_lst_mod(self, filename, data):
        '''
        Writes the last modification timestamp of the additional_info.txt to the lst_mode.txt.
        Input:
            a) filename: The lst_mode.txt file.
            b) data: The modification timestamp.
        '''

        try:
            with open(filename, 'w') as f:
                f.write(data)
        except:
            print('Could not write to lst_mod.txt. Exiting')
            sys.exit(0)

    def buildJson(self, ip_path, delays, dst_ip, src_ip, asn_list):
        '''
        Builds the structure of the json file.
        Input:
            a) ip_path: Contains the IPs of all the hops in order.
            b) delays: Contains all the delays of the hops in order.
        '''
        
        self.measurement_json.update({
            'af': 4,
            'dst_addr': dst_ip,
            'src_addr': src_ip,
            'type': 'traceroute',
            'timestamp': time.time()
        })
        
        result = []
        for i,ip in enumerate(ip_path):
            result.append(
                {'hop': i+1, 'result': [{'from': ip, 'asn': asn_list[i], 'rtt': delays[i]}]})
        
        self.measurement_json['result'] = result

    def buildJsonRipe(self, entry, asn_list, db_extract):
        '''
        Builds the structure of the json file when having ripe atlas measurement as input.
        Input:
            a) entry:       The ripe atlas measurement object
            b) asn_list:    The ASNs for each hop.
            c) db_extract:  The database instance containing the total IXP/AS related information.
            d) traixparser: The instance of parser that specifies which of the traIXroute command line arguments have been enabled.
        '''
        
        # Add ASN for the public source/dest IP of the traceroute path.
        if entry['from'] in db_extract.asn_routeviews:
            entry['from_asn'] = db_extract.asn_routeviews[entry['from']]
        if entry['dst_addr'] in db_extract.asn_routeviews:
            entry['dst_addr_asn'] = db_extract.asn_routeviews[entry['dst_addr']] 
        
        for hop in entry['result']:
            if hop['hop'] != 255:
                try:
                    hop['asn'] = asn_list[hop['hop'] - 1]
                except KeyError:
                    pass
            else:
                hop['asn'] = '*'
        self.measurement_json.update(entry)
     
    def get_filename_from_path(self, path):
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)
           
    def export_results_to_files(self, json_data, txt_data, traixparser, homepath, arguments, exact_time):
        '''
        Exports the total results to .txt/.json files.
        Input:
            a) json_data: Contains all the analyzed traceroute paths to be exported in json format.
            b) txt_data: Contains all the analyzed traceroute paths to be exported in raw txt format.
            c) traixparser: The instance of parser to identify if necessary arguments have been enabled.
            d) homepath: The home directory path of traIXroute.
            e) arguments: The absolute path of the traceroute path file.
        '''
    
        # Discriminating the case when we have as input ripe altas measurements directly from RIPE's database or local files.
        file_name = self.get_filename_from_path(arguments) if not traixparser.flags['ripe'] else 'msm_id_' + str(arguments['msm_id'])
        
        if traixparser.flags['outputfile_json']:
            outputfile_json = traixparser.outputfile_json
            filename = outputfile_json + file_name if outputfile_json else homepath + '/output/output_json_' + (file_name if file_name else exact_time)
                
            with open(filename, 'w') as f:
                size_list = len(json_data)
                counter = 1
                f.write('[\n')
                for entry in itertools.chain.from_iterable(json_data):
                    f.write(ujson.dumps(entry))
                    # Checking for the last element.
                    if counter < size_list:
                        f.write('\n,\n')
                    counter+=1    
                f.write('\n]')
                print('Results in json format have been exported:', filename)
            
        if traixparser.flags['outputfile_txt']:
            outputfile_txt  = traixparser.outputfile_txt
            filename = outputfile_txt + file_name if outputfile_txt else homepath + '/output/output_txt_' + (file_name if file_name else exact_time)
            
            with open(filename, 'w') as f:
                for entry in txt_data:
                    for subentry in entry:
                        f.write(subentry+'\n')
                print('Results have been exported:', filename)

    def stats_extract(self, homepath, num_ips, rules, final_rules_hit, exact_time, traixparser, arguments):
            '''
            Writes various statistics to the stats.txt file.
            Input:
                a) homepath: The home directory path of traIXroute.
                b) num_ips: The number of IPs to send probes.
                c) rules: The rules that detected IXP crossing links.
                d) funal_rules_hit: The number of "hits" for each rule.
                e) exact_time: The starting timestamp of traIXroute.
                f) traixparser: The instance of parser to identify if necessary arguments have been enabled.
                g) arguments: The absolute path of the traceroute path file.
            '''

            file_name = self.get_filename_from_path(arguments)
            filename = homepath+'/output/output_stats_' + (file_name if file_name else exact_time)
                        
            num_hits = sum(final_rules_hit)
            with open(filename, 'w') as fp_stats:
                temp = num_hits / num_ips
                data = 'traIXroute stats from ' + exact_time + ' to ' + datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")                                + '\n'  +\
                    'Number of IXP hits: ' + str(num_hits)      + '\n'  +\
                    'Number of traIXroutes: ' + str(num_ips)    + '\n'  +\
                    'IXP hit ratio: ' + str(temp)               + '\n'  +\
                    'Number of hits per rule:\n'
                for myi in range(0, len(rules)):
                    if num_hits > 0:
                        temp = final_rules_hit[myi] / num_hits
                        data += 'Rule ' + str(myi + 1) + ': Times encountered: ' + str(
                            final_rules_hit[myi]) + ' - Encounter Percentage: ' + str(temp) + '\n'
                    else:
                        data += 'Rule ' + str(myi + 1) + ': Times encountered:0 Encounter Percentage:0\n'
                fp_stats.write(data)
            print('Stats have been exported:', filename)
            
