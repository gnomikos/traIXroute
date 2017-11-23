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

from traixroute.tracetools import *
from traixroute.pathinfo import *
from traixroute.downloader import *
from traixroute.detector import *
from traixroute.handler import database_extract, handle_ripe, handle_json
from traixroute.controller import *
from multiprocessing import cpu_count
import concurrent.futures
import sys
import getopt
import os
import datetime
import socket
import SubnetTree
import ujson
import signal
import itertools
import threading
import math
import copy
from distutils.dir_util import copy_tree
from shutil import copyfile
import xmlrpc.client


class traIXroute():

    '''
    This is the core module of the tool.
    It orchestrates all the modules to detect and identify if and between
    which hops in a traceroute path an IXP crossing occurs.
    '''

    def __init__(self):
        self.version = '2.3'

    def check_version(self):
        pypi = xmlrpc.client.ServerProxy('https://pypi.python.org/pypi')
        version = pypi.package_releases('traixroute')
        if version[0] != self.version:
            print('New version is available: %s' % (version[0]))
    
    def main(self):
        '''
        The main function which calls all the other traIXroute modules.
        '''

        if '-v' in sys.argv or '--version' in sys.argv:
            self.check_version()

        def signal_handler(signal, frame):
            print('\nClosing Files')
            if fp_txt is not None:
                fp_txt.close()
            if fp_json is not None:
                fp_json.close()
            if fp_stats is not None:
                fp_stats.close()
            sys.exit(0)

        fp_txt = None
        fp_json = None
        fp_stats = None
        signal.signal(signal.SIGINT, signal_handler)

        # Calls the parser to analyze the command line arguments.
        libpath = os.path.dirname(os.path.realpath(__file__))
        homepath = os.path.expanduser('~') + '/traixroute'

        if not os.path.exists(homepath + '/output'):
            os.makedirs(homepath + '/output')
            
        if not os.path.exists(homepath):
            os.makedirs(homepath)
            copy_tree(libpath + '/configuration', homepath + '/configuration')

        if not os.path.exists(homepath + '/configuration'):
            copy_tree(libpath + '/configuration', homepath + '/configuration')

        for config_file in ['additional_info.txt',
                            'config',
                            'delimeters.txt',
                            'expressions.txt',
                            'rules.txt']:
            if not os.path.exists(homepath + '/configuration/' + config_file):
                copyfile(libpath + '/configuration/' + config_file,
                         homepath + '/configuration/' + config_file,)
        exact_time = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")

        traixparser = traixroute_parser.traixroute_parser(self.version)
        traixparser.parse_input()
        inputIP         = traixparser.inputIP
        outputfile_txt  = traixparser.outputfile_txt
        outputfile_json = traixparser.outputfile_json
        inputfile       = traixparser.inputfile
        arguments       = traixparser.arguments
        useTraIXroute   = traixparser.flags['useTraiXroute']
        merge_flag      = traixparser.flags['merge']
        print_rule      = traixparser.flags['rule']
        db_print        = traixparser.flags['db']
        path_print      = traixparser.flags['silent']
        ripe            = traixparser.flags['ripe']
        selected_tool   = traixparser.flags['tracetool']
        import_flag     = traixparser.flags['import']
        enable_stats    = traixparser.flags['stats']
        dns_print       = traixparser.flags['dns']

        json_handle = handle_json.handle_json()
        [config, config_flag] = json_handle.import_IXP_dict(
            homepath + '/configuration/config')
        if config_flag:
            print("Detected problem in the config file. Exiting.")
            sys.exit(0)
        elif config["num_of_cores"] > cpu_count():
            print("Exceeded maximum core number in the config file. Exiting.")
            sys.exit(0)
        # Assigns all the available cores to traIXroute.
        elif config["num_of_cores"] < 1:
            config["num_of_cores"] = cpu_count()

        downloader = download_files.download_files(config, homepath)
        num_ips = 0

        # Calls the download module if needed.
        check_db = (
            os.path.exists(libpath + '/database')
        )

        check_user_db = (
            os.path.exists(homepath + '/database/') and
            os.path.exists(homepath + '/database/PCH') and
            os.path.exists(homepath + '/database/PDB') and
            os.path.exists(homepath + '/database/RouteViews')
        )

        check_default_db = (
            os.path.exists(libpath + '/database/Default') and
            os.path.exists(libpath + '/database/Default/RouteViews') and
            os.path.exists(libpath + '/database/Default/PDB') and
            os.path.exists(libpath + '/database/Default/PCH')
        )

        outcome = True
        if traixparser.flags['update'] or (
                (not check_db or not check_user_db) and
                (useTraIXroute or merge_flag)):
            if not check_db:
                traixparser.flags['update'] = True
                print('Database not found.\nUpdating the database...')
                os.makedirs(libpath + '/database')
            elif not check_user_db:
                traixparser.flags['update'] = True
                print('Dataset files are missing.\nUpdating the database...')
                if not os.path.exists(homepath + '/database'):
                    os.makedirs(homepath + '/database')
            else:
                print('Updating the database...')

            outcome = downloader.start_download()
            if outcome:
                print('Database has been updated successfully.')
            else:
                outcome = outcome or (check_db and check_default_db)
                print(
                    'Database cannot be updated. Trying to use traIXroute with the default database.')

            if not outcome and (not check_db or not check_default_db):
                print(
                    'One or more files are missing from the default database. Exiting.')
                sys.exit(0)

        # Extract info from the database folder.
        if useTraIXroute or merge_flag:
            db_extract = database_extract.database(
                traixparser, downloader, config, outcome, libpath)
            db_extract.dbextract()
            
        if useTraIXroute:
            if import_flag:
                [input_list, flag] = json_handle.import_IXP_dict(arguments)
                if flag:
                    print(arguments + ' file not found or has invalid json format. Exiting.')
                    sys.exit(0)
            elif ripe == 1:
                ripe_m = handle_ripe.handle_ripe(config)
                input_list = ripe_m.get_measurement(arguments)
            elif ripe == 2:
                ripe_m = handle_ripe.handle_ripe(config)
                input_list = ripe_m.create_measurement(arguments)
            elif inputfile or inputIP:
                if inputfile:
                    with open(inputfile, 'r') as f:
                        input_list = f.read().split('\n')             
                elif inputIP:
                    input_list = inputIP.split(',')
             
                input_list = list(filter(('').__ne__, input_list))
                
                # Check IP or FQDN format consistency for the given destinations.
                string_handle = string_handler.string_handler()
                for inputIP in input_list:
                    if not string_handle.is_valid_ip_address(inputIP, 'IP'):
                        try:
                            IP_name = socket.gethostbyname(inputIP)
                        except:
                            print(
                                'Wrong input IP address format.\nExpected an IPv4 format or a valid url.')
                            sys.exit(0)
                    elif not string_handle.check_input_ip(inputIP):
                        print(
                            'Wrong input IP address format.\nExpected an IPv4 format or a valid url.')
                        sys.exit(0)

        if useTraIXroute:
        
            # Detection rules import.
            detection_rules_node = detection_rules.detection_rules()
            detection_rules_node.rules_extract(homepath)
            
            # Stats structure initialization.
            if enable_stats: final_rules_hit = [0] * len(detection_rules_node.rules)
        
            output = traixroute_output.traixroute_output()
            output.print_args(selected_tool, useTraIXroute,
                              arguments, ripe, import_flag)

            def openfile(filename):
                try:
                     return open(filename, 'w')
                except:
                    print('Could not open', filename, 'Exiting.')
                    sys.exit(0)
            
            # Set output file names.
            if traixparser.flags['outputfile_txt']:
                filename = outputfile_txt + '.txt' if outputfile_txt else homepath + '/output/output_' + exact_time + '.txt'
                fp_txt = openfile(filename)
            if traixparser.flags['outputfile_json']:
                filename = outputfile_json + '.json' if outputfile_json else homepath + '/output/output_' + exact_time + '.json'
                fp_json = openfile(filename)

            def analyze_measurement(entries):
                '''
                Takes over the total path analysis of a path.
                Input:
                    a) entries: A list with traceroute paths.
                Output:
                    a) rule_hits: Stats about which of the rules have been satisfied.
                    b) json_obj: Contains the path result in json format.
                '''
                
                json_obj = []
                db_extract_copy = copy.copy(db_extract)
                for index,entry in enumerate(entries):
                    output = traixroute_output.traixroute_output()
                    if import_flag == 1:
                        [ip_path, delays_path, dst_ip, src_ip,
                            info] = json_handle.export_trace_from_file(entry)
                        if traixparser.flags['outputfile_txt'] or not traixparser.flags['silent']:
                            output.print_traIXroute_dest(dns_print, dst_ip, src_ip, info)
                    elif import_flag == 2:
                        [ip_path, delays_path, dst_ip, src_ip,
                            info] = json_handle.export_trace_from_ripe_file(entry)
                        if traixparser.flags['outputfile_txt'] or not traixparser.flags['silent']:
                            output.print_traIXroute_dest(dns_print, dst_ip, src_ip, info)
                    elif ripe == 1:
                        [src_ip, dst_ip, ip_path,
                            delays_path] = ripe_m.return_path(entry)
                        if traixparser.flags['outputfile_txt'] or not traixparser.flags['silent']:
                            output.print_traIXroute_dest(dns_print, dst_ip, src_ip)
                    else:
                        src_ip = ''
                        dst_ip = entry.replace(' ', '')
                        myinput = trace_tool.trace_tool()
                        
                        if traixparser.flags['outputfile_txt'] or not traixparser.flags['silent']:
                            output.print_traIXroute_dest(dns_print, dst_ip)
                        [ip_path, delays_path] = myinput.trace_call(
                            dst_ip, selected_tool, arguments)
                    
                    if len(ip_path):
                        # IP path info extraction and print.
                        path_info_extract = path_info_extraction.path_info_extraction()
                        path_info_extract.path_info_extraction(db_extract_copy, ip_path)
                        
                        if traixparser.flags['outputfile_txt'] or not traixparser.flags['silent']:
                            output.print_path_info(ip_path, delays_path, path_info_extract, traixparser)
                            
                        rule_hits = detection_rules_node.resolve_path(ip_path, output, path_info_extract, db_extract_copy, traixparser)
                         
                        if import_flag == 2 or ripe == 1:
                            output.buildJsonRipe(entry, path_info_extract.asn_list)
                        else:
                            output.buildJson(
                                ip_path, delays_path, dst_ip, src_ip, path_info_extract.asn_list)
                    else:
                        rule_hits = [0] * len(detection_rules_node.rules)

                    json_obj.append(output.flush(fp_txt, traixparser))

                return rule_hits, json_obj
            
            # Load balancing over threads.
            json_data = []
            size_of_biglist = len(input_list)
            size_of_sublist = math.ceil(max(size_of_biglist,config["num_of_cores"])/min(size_of_biglist, config["num_of_cores"]))
            sublisted_data = (input_list[x:x+size_of_sublist] for x in range(0, size_of_biglist, size_of_sublist))
            with concurrent.futures.ThreadPoolExecutor(max_workers=config["num_of_cores"]) as executor:
                for rule_hits, json_obj in executor.map(analyze_measurement, sublisted_data):
                
                    json_data.append(json_obj)
                    if enable_stats: 
                        final_rules_hit = [x + y for x, y in zip(final_rules_hit, rule_hits)]
                        num_ips += 1
            
            if traixparser.flags['outputfile_json']:
                ujson.dump(itertools.chain.from_iterable(json_data), fp_json, indent=1)
                fp_json.close()
                
            if traixparser.flags['outputfile_txt']:
                fp_txt.close()
                
            #Extracting statistics.
            if enable_stats:
                self.stats_extract(homepath, num_ips, detection_rules_node.rules, final_rules_hit, exact_time)

    def stats_extract(self, homepath, num_ips, rules, final_rules_hit, time):
        '''
        Writes various statistics to the stats.txt file.
        Input:
            a) homepath: The home directory path of traIXroute.
            b) num_ips: The number of IPs to send probes.
            c) rules: The rules that detected IXP crossing links.
            d) funal_rules_hit: The number of "hits" for each rule.
            e) time: The starting timestamp of traIXroute.
        '''

        num_hits = sum(final_rules_hit)
        
        if num_ips:
            with open(homepath+'/output/output_' + time + '.stats', 'w') as fp_stats:
                temp = num_hits / num_ips
                data = 'traIXroute stats from ' + time + ' to ' + datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S") + '\n' +\
                    'Number of IXP hits: ' + str(num_hits) + '\n' +\
                    'Number of traIXroutes: ' + str(num_ips) + '\n' +\
                    'IXP hit ratio: ' + str(temp) + '\n' + \
                    'Number of hits per rule:\n'
                for myi in range(0, len(rules)):
                    if num_hits > 0:
                        temp = final_rules_hit[myi] / num_hits
                        data += 'Rule ' + str(myi + 1) + ': Times encountered: ' + str(
                            final_rules_hit[myi]) + ' - Encounter Percentage: ' + str(temp) + '\n'
                    else:
                        data += 'Rule ' + str(myi + 1) + ': Times encountered:0 Encounter Percentage:0\n'
                fp_stats.write(data)
            
def run_traixroute():
    traIXroute_module = traIXroute()
    traIXroute_module.main()

if __name__ == '__main__':
    run_traixroute()

