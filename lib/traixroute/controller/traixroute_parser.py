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

import argparse
import sys
import ujson
import os
from collections import defaultdict


class traixroute_parser():

    def __init__(self, ver):
        # self.inputIP: The destination IP or FQDN to send the probe.
        self.inputIP = ''
        
        # self.outputfile_txt: The .txt output file name in which all the results will
        # be redirected to.
        self.outputfile_txt = ''
        
        # self.outputfile_json: The .json output file name in which all the results will
        # be redirected to.
        self.outputfile_json = ''
        
        # self.inputfile: The file name with the list of the destination IP
        # addresses/FQDNs to send the probes.
        self.inputfile = ''
        
        # self.arguments: traIXroute arguments.
        self.arguments = ''
        
        # self.flags: A dictionary containing the user input flags.
        self.flags = defaultdict(bool)
        
        # self.version: The running version of traIXroute.
        self.version = ver

    def __str__(self):
        ss  = 'InputIP: '        + str(self.inputIP)             + '\n'
        ss += 'outputfile_txt: ' + str(self.outputfile_txt)      + '\n'
        ss += 'outputfile_json: '+ str(self.outputfile_json)     + '\n'
        ss += 'inputfile: '      + str(self.inputfile)           + '\n'
        ss += 'arguments: '      + str(self.arguments)           + '\n'
        for v in self.flags:
            ss += str(v) + ': '  + str(self.flags[v])            + '\n'
        return ss

    def parse_input(self):
        '''
        The parser rensponsible for resolving the command line arguments set by the user.
        '''

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest='subparser_name')

        parser_probe = subparsers.add_parser('probe', help='probe --help')
        parser_ripe = subparsers.add_parser('ripe', help='ripe --help')
        parser_import = subparsers.add_parser('import', help='import --help')

        parser.add_argument('-stats', '--enable-stats', action='store_true',
                            help='Enables logging IXP crossing related information.')
        parser.add_argument('-silent', '--silence-path-print', action='store_true',
                            help='Enables printing the analyzed traceroute paths with their IXP crossing links.')
        parser.add_argument('-dns', '--enable-dns-print', action='store_true',
                            help='Enables printing the domain name of each IP hop in the traceroute path.')
        parser.add_argument('-asn', '--enable-asn-print', action='store_true',
                            help='Enables printing the ASN of each IP hop in the traceroute path.')
        parser.add_argument('-db', '--store-database', action='store_true',
                            help='Enables printing the database information.')
        parser.add_argument('-rule', '--enable-rule-print', action='store_true',
                            help='Enables printing the hit IXP detection rule(s) in the traceroute path.')
        parser.add_argument('-u', '--update', action='store_true',
                            help='Updates the database with up-to-date datasets.')
        parser.add_argument('-m', '--merge', action='store_true',
                            help='Exports the database to distinct files, the ixp_prefixes.txt and  ixp_membership.txt.')
        parser.add_argument('-otxt', '--output-txt', default='disabled', nargs='?', type=str,
                            help='Enables to export data in .txt file and (optional) specifies the output file name to redirect the traIXroute results.')
        parser.add_argument('-ojson', '--output-json', default='disabled', nargs='?', type=str,
                            help='Enables to export data in .json file and (optional) specifies the output file name to redirect the traIXroute results.')                    
        parser.add_argument('-v', '--version', action='version', version='current version of traixroute: '+self.version)
        parser_mode = parser.add_mutually_exclusive_group(required=True)
        parser_mode.add_argument('-thread', action='store_true',help='Enables threads for parallel analysis. This mode is more conservative in terms of performance and is recommended in case of memory limitations.')
        parser_mode.add_argument('-process', action='store_true', help='Enables processes for parallel analysis. This mode is quite memory hungry to maximize the analysis performance.')
        

        group_0 = parser_probe.add_mutually_exclusive_group(required=True)
        group_0.add_argument('-dest', '--destination', nargs='+', action='store',
                             type=str, help='The IP/FQDN destination to send the probe.')
        group_0.add_argument('-doc', '--input-file', nargs=1, action='store', type=str,
                             help='The input file with the list of the destination IP addresses or FQDNs to send the probes.')

        group_1 = parser_probe.add_mutually_exclusive_group(required=True)
        group_1.add_argument('-t', '--traceroute', nargs='*', action='store', type=str,
                             help='Calls traIXroute with traceroute and (optional) traceroute arguments.')
        group_1.add_argument('-sc', '--scamper', nargs='*', action='store', type=str,
                             help='Calls traIXroute with scamper and (optional) scamper arguments.')

        group_2 = parser_ripe.add_mutually_exclusive_group(required=True)
        group_2.add_argument('-r', '--request', nargs=1, action='store', type=ujson.loads,
                             help='Fetches the traceroute results of a RIPE Atlas measurement to detect IXP crossing links.')
        group_2.add_argument('-c', '--create', nargs=2, action='store', type=ujson.loads,
                             help='Creates a new measurement in the RIPE Atlas platform with the desired options.')

        group_3 = parser_import.add_mutually_exclusive_group(required=True)
        group_3.add_argument('-json', '--parse-json', nargs=1, action='store', type=str,
                             help='Imports a list of traceroute paths from a traIXroute format (json based) file to detect IXP crossing links. For example see Examples/test.json.')
        group_3.add_argument('-ripejson', '--parse-ripe-json', nargs=1, action='store', type=str,
                             help='Imports a list of traceroute paths from a ripe json format file to detect IXP crossing links.')
        
        options = parser.parse_args()

        # Parameterize arguments from subparser probe
        if (options.subparser_name == 'probe'):
            if options.destination is not None:
                self.inputIP = options.destination[0]
                self.flags['useTraiXroute'] = True
            elif options.input_file is not None:
                self.inputfile = options.input_file[0]
                self.flags['useTraiXroute'] = True
            if (options.traceroute is not None):
                self.flags['tracetool'] = 0
                if len(options.traceroute) > 0:
                    self.arguments = options.traceroute[0]
                if ('-6' in self.arguments):
                    print('IPv6 is not supported yet.')
                    sys.exit(-1)
            elif (options.scamper is not None):
                self.flags['tracetool'] = 1
                if len(options.scamper) > 0:
                    self.arguments = options.scamper[0]

        # Parameterize arguments from subparser ripe
        elif (options.subparser_name == 'ripe'):
            if (options.request is not None):
                self.arguments = options.request[0]
                self.flags['ripe']          = 1
                self.flags['useTraiXroute'] = True
                self.flags['showSourceIP']  = True
            elif (options.create is not None):
                self.arguments = []
                self.arguments.append(options.create[0])
                self.arguments.append(options.create[1])
                self.flags['ripe']          = 2
                self.flags['useTraiXroute'] = True
                self.flags['showSourceIP']  = True

        # Parameterize arguments from subparser import                
        elif (options.subparser_name == 'import'):
            if (options.parse_json is not None):
                self.arguments = str(options.parse_json[0])
                self.flags['import']        = 1
                self.flags['useTraiXroute'] = True
                self.flags['showSourceIP']  = True
                self.flags['import_is_dir'] = True if os.path.isdir(self.arguments) else False
            elif (options.parse_ripe_json is not None):
                self.arguments = str(options.parse_ripe_json[0])
                self.flags['import']        = 2
                self.flags['useTraiXroute'] = True
                self.flags['showSourceIP']  = True
                self.flags['import_is_dir'] = True if os.path.isdir(self.arguments) else False
              
        if not options.output_txt or options.output_txt != 'disabled':
            if options.output_txt: 
                self.outputfile_txt = options.output_txt
            self.flags['outputfile_txt'] = True
        
        if not options.output_json or options.output_json != 'disabled':
            if options.output_json:
                self.outputfile_json = options.output_json 
            self.flags['outputfile_json'] = True
        
        if options.thread:
            self.flags['mode'] = 'thread'
        elif options.process:
            self.flags['mode'] = 'process'
        
        if options.enable_stats:
            self.flags['stats']  = True
        
        if options.silence_path_print:
            self.flags['silent'] = True
        
        if options.update:
            self.flags['update'] = True

        if options.merge:
            self.flags['merge']  = True

        if options.enable_dns_print:
            self.flags['dns']    = True

        if options.enable_asn_print:
            self.flags['asn']    = True

        if options.store_database:
            self.flags['db']     = True

        if options.enable_rule_print:
            self.flags['rule']   = True
