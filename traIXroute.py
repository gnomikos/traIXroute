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

from Trace_Tools import *
from Path_Info_Handler import *
from Download_Handler import *
from Detection_Handler import *
from Database_Handler import database_extract,handle_ripe,handle_json
from Controller import *
from multiprocessing import cpu_count
import concurrent.futures, sys, getopt, os, datetime, socket, SubnetTree, ujson,signal,time

class traIXroute():
    '''
    This is the core module of the tool. It orchestrates all the modules to detect and identify if and between which hops in a traceroute path an IXP crossing occurs.
    '''

    def main(self):
        '''
        The main function which calls all the other traIXroute modules.
        '''

        def signal_handler(signal, frame):
            print('\nClearing Memory')
            if fp is not None:
                fp.close()
            sys.exit(0)
            
        fp=None
        signal.signal(signal.SIGINT, signal_handler)
        
        # Calls the parser to analyze the command line arguments.
        mypath = sys.path[0]
        exact_time = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")

        traIXparser = traIXroute_parser.traIXroute_parser(exact_time)
        traIXparser.parse_input()

        inputIP         = traIXparser.inputIP
        outputfile      = traIXparser.outputfile
        inputfile       = traIXparser.inputfile
        arguments       = traIXparser.arguments
        useTraIXroute   = traIXparser.flags['useTraiXroute']
        merge_flag      = traIXparser.flags['merge']
        asn_print       = traIXparser.flags['asn']
        print_rule      = traIXparser.flags['rule']
        dns_print       = traIXparser.flags['dns']
        db_print        = traIXparser.flags['db']
        ripe            = traIXparser.flags['ripe']
        selected_tool   = traIXparser.flags['tracetool']
        import_flag     = traIXparser.flags['import']
        
        json_handle = handle_json.handle_json()
        [config,config_flag]=json_handle.import_IXP_dict(mypath+'/config')
        if config_flag:
            print("Detected problem in the config file. Exiting.") 
            sys.exit(0)
        elif config["num_of_cores"]>cpu_count():
            print("Exceeded maximum core number in the config file. Exiting.")
            sys.exit(0)
        #Assigns all the available cores to traIXroute.
        elif config["num_of_cores"]<1:
            config["num_of_cores"]=cpu_count()

        num_ips = 0
       
        # Calls the download module if needed.
        check_db = os.path.exists(mypath+'/Database')
        check_user_db = os.path.exists(mypath+'/Database/User') and os.path.exists(mypath+'/Database/User/PCH') and os.path.exists(mypath+'/Database/User/PDB') and os.path.exists(mypath+'/Database/User/RouteViews')
        check_default_db = os.path.exists(mypath+'/Database/Default') and os.path.exists(mypath+'/Database/Default/RouteViews') and os.path.exists(mypath+'/Database/Default/PDB') and os.path.exists(mypath+'/Database/Default/PCH')
        outcome = True
        if traIXparser.flags['update'] or ((not check_db or not check_user_db) and (useTraIXroute or merge_flag)):
            if not check_db:
                traIXparser.flags['update']=True
                print('Database not found.\nUpdating the database...')
                os.makedirs(mypath+'/Database')
            elif not check_user_db:
                traIXparser.flags['update']=True
                print('Dataset files are missing.\nUpdating the database...')
            else:
                print ('Updating the database...')

            mydownload = download_files.download_files(config)
            outcome = mydownload.download_files(mypath)
            if outcome:
                print ('Database has been updated successfully.')
            else:
                outcome = outcome or (check_db and check_default_db)
                print ('Database cannot be updated. Trying to use traIXroute with the default database.')
            
            if not outcome and ( not check_db or not check_default_db):
                print('One or more files are missing from the default database. Exiting.')
                sys.exit(0)

        if useTraIXroute:
            if import_flag:
                [input_list,flag] = json_handle.import_IXP_dict(arguments)
                if flag:
                    print(arguments+' file not found or has invalid json format. Exiting.')
                    sys.exit(0)
            elif ripe == 1:
                ripe_m = handle_ripe.handle_ripe(config)
                input_list = ripe_m.get_measurement(arguments)
            elif ripe == 2:
                ripe_m = handle_ripe.handle_ripe(config)
                input_list = ripe_m.create_measurement(arguments)
            elif inputfile!='':
                try:
                    f = open(inputfile,'r')
                except:
                    print(inputfile+' was not found. Exiting.')
                    sys.exit(0)
                input_list = f.read()
                f.close()
                input_list = input_list.split('\n')
            else:
                input_list = inputIP.split(',')
            input_list=list(filter(('').__ne__, input_list))
            temp_point=0
            if not ripe and not import_flag:
                inputIP=input_list[temp_point].replace(' ','')        
            # Instead of an IP address, a domain name has been given as destination to send the probe, the domain name is reversed.
            string_handle=string_handler.string_handler()
            if not string_handle.is_valid_ip_address(inputIP,'IP'):
                try:
                    IP_name=socket.gethostbyname(inputIP)
                except:
                    print('Wrong input IP address format.\nExpected an IPv4 format or a valid url.')
                    sys.exit(0)    
            elif not string_handle.check_input_ip(inputIP):
                print('Wrong input IP address format.\nExpected an IPv4 format or a valid url.')
                sys.exit(0)

            detection_rules_node = detection_rules.detection_rules()
            detection_rules_node.rules_extract('Rules.txt')

            final_rules_hit = [0 for x in range(0,len(detection_rules_node.rules))]

            myinput = trace_tool.trace_tool()
        
        # Step 1: Construct the database.
        # Step 2: Send probe.
        # Step 3: Analyse traceroute path to apply detection rules and infer IXP crossing links.
        
        # Extract info from the database folder.
        if useTraIXroute or merge_flag:
            db_extract = database_extract.database(traIXparser,mypath,config,outcome)
            db_extract.dbextract() 

        if useTraIXroute:
            output=traIXroute_output.traIXroute_output()
            output.print_args(selected_tool,useTraIXroute,arguments,ripe,import_flag)
            outputfile='Output/'+outputfile
            write_path=mypath+'/Output'
            if not os.path.exists(write_path):
                os.makedirs(write_path)  
            try:
                fp=open(mypath+'/'+outputfile,'w')
            except:
                print('Could not open outputfile. Exiting.')
                sys.exit(0) 
            
            def analyze_measurement(entry):
                output = traIXroute_output.traIXroute_output()
                if import_flag == 1:
                    [IP_route,path_delay,json_dst,json_src,info]=json_handle.export_trace_from_file(entry)
                    output.print_traIXroute_dest(json_dst,json_src,info)
                elif import_flag == 2:
                    [IP_route,path_delay,json_dst,json_src,info]=json_handle.export_trace_from_ripe_file(entry)
                    output.print_traIXroute_dest(json_dst,json_src,info)
                elif ripe==1:
                    [src_ip,dst_ip,IP_route,path_delay]=ripe_m.return_path(entry)
                    output.print_traIXroute_dest(dst_ip,src_ip)
                else:
                    dst_ip=entry.replace(' ','')
                    output.print_traIXroute_dest(dst_ip)                   
                    [IP_route,path_delay]=myinput.trace_call(dst_ip,selected_tool,arguments)
                rule_hits=[0 for x in detection_rules_node.rules]

                if len(IP_route):
                    # IP path info extraction and print.
                    path_info_extract=path_info_extraction.path_info_extraction()
                    path_info_extract.path_info_extraction(db_extract,IP_route)
                    output.print_path_info( IP_route, path_delay, mypath, path_info_extract, traIXparser )
                    detection_rules_node.resolve_path(IP_route, mypath, output, path_info_extract, db_extract, traIXparser)
                    rule_hits = detection_rules_node.rule_hits

                output.flush(fp)
                return rule_hits
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=config["num_of_cores"]) as executor:
                for rule_hits in executor.map(analyze_measurement,input_list):
                    final_rules_hit=[x + y for x, y in zip(final_rules_hit, rule_hits)]
                    num_ips+=1
                    
            # Extracting statistics.
            self.stats_extract(mypath,'stats_'+exact_time+'.txt',num_ips,detection_rules_node.rules,final_rules_hit,exact_time)            


    def stats_extract(self,mypath,filename,num_ips,rules,final_rules_hit,time):
        '''
        Writes various statistics to the stats.txt file.
        Input: 
            a) mypath: The current directory path.
            b) filename: The file name to write.
            c) num_ips: The number of IPs to send probes.
            d) rules: The rules that detected IXP crossing links.
            e) funal_rules_hit: The number of "hits" for each rule.
            f) time: The starting timestamp of traIXroute.
        '''

        try:
            f = open(mypath+'/Output/'+filename, 'a')
        except:
            print('Output file not found. Exiting')
            sys.exit(0)

        num_hits=sum(final_rules_hit)
        if num_ips>0:
            temp=num_hits/num_ips
            data='traIXroute stats from '+time+' to '+ datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")+' \nNumber of IXP hits:'+str(num_hits)+' Number of traIXroutes:'+str(num_ips)+' IXP hit ratio:'+str(temp)+'\n'
            data=data+'Number of hits per rule:\n'
            for myi in range(0,len(rules)):
                if num_hits>0:
                    temp=final_rules_hit[myi]/num_hits
                    data=data+'Rule '+str(myi+1)+': Times encountered:'+str(final_rules_hit[myi])+' Encounter Percentage:'+str(temp)+'\n'
                else:
                    data=data+'Rule '+str(myi+1)+': Times encountered:0 Encounter Percentage:0\n'
            f.write(data)
            f.close()


    def check_db(self,path):
        '''
        Checks if the json files that form the database are included in the directory path.
        Input:
            a) path: The directory path to check.
        Output:
            a) True if all the files exist, False otherwise. 
        '''
        
        if os.path.isfile(path + '/IXPIP2ASN.json') and os.path.isfile(path + '/trIX_subnet2name.json') and os.path.isfile(path + '/asn_memb.json') and os.path.isfile(path + '/sub2country.json') and os.path.isfile(path + '/routeviews.json') and os.path.isfile(path + '/ix.json') and os.path.isfile(path + '/ixlan.json') and os.path.isfile(path + '/ixp_exchange.csv') and os.path.isfile(path + '/ixpfx.json') and os.path.isfile(path + '/ixp_membership.csv') and os.path.isfile(path + '/ixp_subnets.csv') and os.path.isfile(path + '/netixlan.json') and os.path.isfile(path + '/netixlan.json'):
            return True
        else: 
            return False


if __name__ == "__main__":
    traIXroute_module=traIXroute()
    traIXroute_module.main()
    
