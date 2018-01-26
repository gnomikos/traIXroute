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

from traixroute.handler     import database_extract, handle_ripe, handle_json
from distutils.dir_util     import copy_tree
from shutil                 import copyfile
from multiprocessing        import cpu_count
from multiprocessing        import Manager
from traixroute.tracetools  import *
from traixroute.pathinfo    import *
from traixroute.downloader  import *
from traixroute.detector    import *
from traixroute.controller  import *
from stat                   import *
import concurrent.futures
import sys
import getopt
import os
import datetime
import socket
import SubnetTree
import ujson
import threading
import math
import xmlrpc.client
import resource


class traIXroute():

    '''
    This is the core module of the tool.
    It orchestrates all the modules to detect and identify if and between
    which hops in a traceroute path an IXP crossing occurs.
    '''

    def __init__(self):
        self.version        = '2.3'
        self.mode           = None
        self.downloader     = None
        self.config         = None
        self.outcome        = True
        self.libpath        = None
        self.import_flag    = None
        self.dns_print      = None
        self.input_list     = None
        self.db_extract     = None
        self.enable_stats   = None
        self.exact_time     = None
        self.ripe           = None
        self.selected_tool  = None
        self.ripe_handle    = None
        self.traixparser    = traixroute_parser.traixroute_parser(self.version)
        self.detection_rules= detection_rules.detection_rules()
        self.json_handle    = handle_json.handle_json()

    def analyze_measurement(self, indexes):

        json_handle_local = handle_json.handle_json()
        output = traixroute_output.traixroute_output()
        
        if self.mode == 'thread':
            db_extract = self.db_extract
        else:
            print('traIXroute process with id', os.getpid(),'has just started.')
            db_extract = database_extract.database(self.traixparser, self.downloader, self.config, self.outcome, self.libpath)
            db_extract.dbextract()
        
        for index,entry in enumerate(self.input_list[indexes[0]:indexes[1]]):
            
            if self.import_flag == 1:
                [ip_path, delays_path, dst_ip, src_ip,
                    info] = json_handle_local.export_trace_from_file(entry)
                if self.traixparser.flags['outputfile_txt'] or not self.traixparser.flags['silent']:
                    output.print_traIXroute_dest(self.traixparser, db_extract, self.dns_print, dst_ip, src_ip, info)
            elif self.import_flag == 2:
                [ip_path, delays_path, dst_ip, src_ip,
                    info] = json_handle_local.export_trace_from_ripe_file(entry)
                if self.traixparser.flags['outputfile_txt'] or not self.traixparser.flags['silent']:
                    output.print_traIXroute_dest(self.traixparser, db_extract, self.dns_print, dst_ip, src_ip, info)
            elif self.ripe == 1:
                [src_ip, dst_ip, ip_path,
                    delays_path] = self.ripe_handle.return_path(entry)
                if self.traixparser.flags['outputfile_txt'] or not self.traixparser.flags['silent']:
                    output.print_traIXroute_dest(self.traixparser, db_extract, self.dns_print, dst_ip, src_ip)
            else:
                src_ip = ''
                dst_ip = entry.replace(' ', '')
                myinput = trace_tool.trace_tool()
                
                if self.traixparser.flags['outputfile_txt'] or not self.traixparser.flags['silent']:
                    output.print_traIXroute_dest(self.traixparser, db_extract, self.dns_print, dst_ip)
                [ip_path, delays_path] = myinput.trace_call(
                    dst_ip, self.selected_tool, self.arguments)

            if len(ip_path):
                # IP path info extraction and print.
                path_info_extract = path_info_extraction.path_info_extraction()
                path_info_extract.path_info_extraction(db_extract, ip_path)
                
                if self.traixparser.flags['outputfile_txt'] or not self.traixparser.flags['silent']:
                    output.print_path_info(ip_path, delays_path, path_info_extract, self.traixparser)
                    
                rule_hits = self.detection_rules.resolve_path(ip_path, output, path_info_extract, db_extract, self.traixparser)
                 
                if self.import_flag == 2 or self.ripe == 1:
                    output.buildJsonRipe(entry, path_info_extract.asn_list, db_extract)
                else:
                    output.buildJson(
                        ip_path, delays_path, dst_ip, src_ip, path_info_extract.asn_list)
            else:
                rule_hits = [0] * len(self.detection_rules.rules)
            
            output.flush(self.traixparser)
        
        # Empty database instance.
        if self.mode == 'process':
            db_extract.clean()
            del db_extract
        
        return [rule_hits, output.json_obj, output.txt_obj]

    def check_version(self):
        pypi = xmlrpc.client.ServerProxy('https://pypi.python.org/pypi')
        version = pypi.package_releases('traixroute')
        if version[0] != self.version:
            print('New version is available: %s' % (version[0]))
    
    def main(self):
        '''
        The main function which calls all the other traIXroute modules.
        '''
        
        # Calls the parser to analyze the command line arguments.
        self.traixparser.parse_input()
        inputIP             = self.traixparser.inputIP
        inputfile           = self.traixparser.inputfile
        self.arguments      = self.traixparser.arguments
        useTraIXroute       = self.traixparser.flags['useTraiXroute']
        merge_flag          = self.traixparser.flags['merge']
        print_rule          = self.traixparser.flags['rule']
        db_print            = self.traixparser.flags['db']
        path_print          = self.traixparser.flags['silent']
        self.ripe           = self.traixparser.flags['ripe']
        self.selected_tool  = self.traixparser.flags['tracetool']
        import_is_dir       = self.traixparser.flags['import_is_dir']
        self.import_flag    = self.traixparser.flags['import']
        self.enable_stats   = self.traixparser.flags['stats']
        self.dns_print      = self.traixparser.flags['dns']
        self.mode           = self.traixparser.flags['mode']
        self.libpath        = os.path.dirname(os.path.realpath(__file__))
        
        if '-v' in sys.argv or '--version' in sys.argv:
            self.check_version()

        # Initiates the tool with the output directories and all the proper configurations.
        homepath = os.path.expanduser('~') + '/traixroute'
        if not os.path.exists(homepath + '/output'):
            os.makedirs(homepath + '/output')
            
        if not os.path.exists(homepath):
            os.makedirs(homepath)
            copy_tree(self.libpath + '/configuration', homepath + '/configuration')

        if not os.path.exists(homepath + '/configuration'):
            copy_tree(self.libpath + '/configuration', homepath + '/configuration')

        for config_file in ['additional_info.txt',
                            'config',
                            'delimeters.txt',
                            'expressions.txt',
                            'rules.txt']:
            if not os.path.exists(homepath + '/configuration/' + config_file):
                copyfile(self.libpath + '/configuration/' + config_file,
                         homepath + '/configuration/' + config_file,)
        
        [self.config, config_flag] = self.json_handle.import_IXP_dict(homepath + '/configuration/config')
        if config_flag:
            print("Detected problem in the config file. Exiting.")
            sys.exit(0)
        elif self.config["num_of_cores"] > cpu_count():
            print("Exceeded maximum core number in the config file. Exiting.")
            sys.exit(0)
        # Assigns all the available cores to traIXroute.
        elif self.config["num_of_cores"] < 1:
            self.config["num_of_cores"] = cpu_count()

        self.downloader = download_files.download_files(self.config, homepath)

        # Calls the download module if needed.
        check_db = (
            os.path.exists(self.libpath + '/database')
        )

        check_user_db = (
            os.path.exists(homepath + '/database/')     and
            os.path.exists(homepath + '/database/PCH')  and
            os.path.exists(homepath + '/database/PDB')  and
            os.path.exists(homepath + '/database/RouteViews')
        )

        check_default_db = (
            os.path.exists(self.libpath + '/database/Default')            and
            os.path.exists(self.libpath + '/database/Default/RouteViews') and
            os.path.exists(self.libpath + '/database/Default/PDB')        and
            os.path.exists(self.libpath + '/database/Default/PCH')
        )

        if self.traixparser.flags['update'] or (
                (not check_db or not check_user_db) and
                (useTraIXroute or merge_flag)):
            if not check_db:
                self.traixparser.flags['update'] = True
                print('Database not found.\nUpdating the database...')
                os.makedirs(self.libpath + '/database')
            elif not check_user_db:
                self.traixparser.flags['update'] = True
                print('Dataset files are missing.\nUpdating the database...')
                if not os.path.exists(homepath + '/database'):
                    os.makedirs(homepath + '/database')
            else:
                print('Updating the database...')

            self.outcome = self.downloader.start_download()
            if self.outcome:
                print('Database has been updated successfully.')
            else:
                self.outcome = self.outcome or (check_db and check_default_db)
                print(
                    'Database cannot be updated. Trying to load the default local database.')
            if not self.outcome and (not check_db or not check_default_db):
                print(
                    'One or more files are missing from the default database. Exiting.')
                sys.exit(0)

        # Extract info from the database folder.
        if useTraIXroute or merge_flag:
            db_extract = database_extract.database(
                    self.traixparser, self.downloader, self.config, self.outcome, self.libpath)
            
            if self.mode == 'thread':
                self.db_extract = db_extract
                self.db_extract.dbextract()
            else:
                if merge_flag:
                    db_extract.dbextract()
                    db_extract.clean()
                    # To avoid merging again when processes are used.
                    self.traixparser.flags['merge'] = False
            
        if useTraIXroute:
            # Detection rules import.
            self.detection_rules.rules_extract(homepath)
            manager = Manager()
            
            if self.import_flag:
                # Find all the files in the given directory
                if import_is_dir:
                    self.dir_walk(homepath, useTraIXroute, self.arguments, manager, self.traixroute_core)
                # Analyze the given file.
                else:
                    [input_list, flag] = self.json_handle.import_IXP_dict(self.arguments)
                    if flag:
                        print('WARNING:', self.arguments + ' file not found or has invalid json format. Exiting.')
                        sys.exit(0)
                    self.traixroute_core(homepath, input_list, useTraIXroute, self.arguments, manager)    
            
            # Case: when a ripe atlas measurement is fetched to be analyzed.
            elif self.ripe == 1:
                self.ripe_handle = handle_ripe.handle_ripe(self.config)
                input_list = self.ripe_handle.get_measurement(self.arguments)
                self.traixroute_core(homepath, input_list, useTraIXroute, self.arguments, manager)
            # Case: when a ripe atlas measurement is created and then it is fetched to be analyzed.
            elif self.ripe == 2:
                self.ripe_handle = handle_ripe.handle_ripe(self.config)
                input_list = self.ripe_handle.create_measurement(self.arguments)
                self.traixroute_core(homepath, input_list, useTraIXroute, self.arguments, manager)
            
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
                self.traixroute_core(homepath, input_list, useTraIXroute, self.arguments, manager)
        
        # Empty database. In case of using threads only one database instance is used.       
        if self.mode == 'thread':
            self.db_extract.clean()
    
    # Finds all the files in directories and subdirectories when a directory has been given as input.
    def dir_walk(self, homepath, useTraIXroute, root_path, manager, callback):
        for filename in sorted(os.listdir(root_path)):
            pathname = os.path.join(root_path, filename)
            mode = os.stat(pathname)[ST_MODE]
            if S_ISDIR(mode):
                # It's a directory
                self.dir_walk(homepath, useTraIXroute, pathname, callback)
            elif S_ISREG(mode):
                # It's a file
                [input_list, flag] = self.json_handle.import_IXP_dict(pathname)
                if flag:
                    print('WARNING:', pathname + ' file not found or has invalid json format. Exiting.')
                else:
                    callback(homepath, input_list, useTraIXroute, pathname, manager)
            else:
                # Unknown file type
                print ('WARNING:', 'skipping', pathname)
    
    def traixroute_core(self, homepath, input_list, useTraIXroute, arguments, manager):
    
        json_data = []
        txt_data  = []
        num_ips = 0
        if self.mode == 'process':
            self.input_list = manager.list(input_list)
            del input_list[:], input_list
        else:
            self.input_list = input_list
        
        # Set the starting time
        self.exact_time = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
    
        # Stats structure initialization.
        if self.enable_stats: final_rules_hit = [0] * len(self.detection_rules.rules)
    
        output = traixroute_output.traixroute_output()
        output.print_args(self.selected_tool, useTraIXroute, arguments, self.ripe, self.import_flag)

        # Load balancing over Threads or Processes based on the selected mode.
        size_of_biglist = len(self.input_list)
        size_of_sublist = math.ceil(max(size_of_biglist,self.config["num_of_cores"])/min(size_of_biglist, self.config["num_of_cores"]))
        sublisted_data = [[x,x+size_of_sublist] for x in range(0, size_of_biglist, size_of_sublist)]
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.config["num_of_cores"]) \
        if self.mode == 'process' else \
        concurrent.futures.ThreadPoolExecutor(max_workers=self.config["num_of_cores"]) \
        as executor:
            for [rule_hits, json_obj, txt_obj] in executor.map(self.analyze_measurement, sublisted_data):
                if self.traixparser.flags['outputfile_json']: json_data.append(json_obj)
                if self.traixparser.flags['outputfile_txt']: txt_data.append(txt_obj)
                
                if self.enable_stats: 
                    final_rules_hit = [x + y for x , y in zip(final_rules_hit, rule_hits)]
                    num_ips += 1
        
        output.export_results_to_files(json_data, txt_data, self.traixparser, homepath, arguments, self.exact_time)
        
        # Extracting statistics.
        if self.enable_stats and num_ips>0:
            output.stats_extract(homepath, num_ips, self.detection_rules.rules, final_rules_hit, self.exact_time, self.traixparser, arguments)
        
        del self.input_list[:], json_data[:], txt_data[:]
        
def run_traixroute():
    traIXroute_module = traIXroute()
    traIXroute_module.main()

if __name__ == '__main__':
    run_traixroute()
