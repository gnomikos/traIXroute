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

import sys, getopt,os,trace_tool,path_info_extraction,download_files,detection_rules,database_extract,datetime,string_handler,socket,traIXroute_output

'''
This is the core module of the tool.
It orchestrates all the modules to detect and identify if and at which hops in a traceroute path an IXP crossing happens.
'''

class traIXroute():

    '''
    This function extracts the parameters of the twofold arguments (e.g in a -i <IP> argument, it would extract the second parameter <IP>).
    Input:
        a) argv: The command line arguments.
        b) element: The first element of a twofold argument.
        c) flag: TRUE, to check arguments in brackets in the command line, FALSE otherwise.
        d) check_argv: A temporary string containing the command line arguments.
    Ouput: 
        a) argument: The second element of a twofold argument, otherwise it returns "".
        b) check_argv: A temporary string containing the rest command line arguments.
    '''
    def extract_element(self,argv,element,flag,check_argv):
            position=argv.index(element)
            temp_argv=''.join(argv)
            if not flag:
                if len(argv)>position+1:
                   argument=argv[position+1]
                   try:
                       check_argv.remove(argument)
                   except:
                       pass
                   return argument,check_argv
            else:
                if len(argv)>position+1:
                    if '[' in argv[position+1]:
                        argument=argv[position+1]
                        try:
                            check_argv.remove(argv[position+1])
                        except:
                            pass
                        if '[' in argument and ']' not in argument:
                            for i in range(position+2,len(argv)):            
                                argument=argument+' '+argv[i]
                                check_argv.remove(argv[i])
                                if ']' in argv[i]:
                                    break
                        argument=argument.replace('[','')  
                        argument=argument.replace(']','')  
                        return argument,check_argv
                    elif '[' in temp_argv:
                        print ('Expected traceroute/scamper arguments after the corresponding option. Exiting.')
                        exit(0)

            return '',check_argv


    '''
     The parser rensponsible for resolving the command line arguments set by the user.
     Input:
        a) argv: Τhe command line arguments.
     Output:
        a) inputIP: The IP or url to probe.
        b) outputfile: The output file name in case the other_output_flag is set to 1.
        c) download: Flag to download the datasets.
        d) search: Flag to send probe.
        e) classic: Flag to choose between traceroute and scamper.
        f) source: Flag to set the source of the IP address to probe.
        g) input_file: The file name with the list of the IP addresses to probe.
        h) arguments: Probing arguments.
        i) other_output_flag: Flag to change the default output file name.
        j) merged_flag: Flag to print the merged PCH and Peering IXP IP addresses and Prefixes.
    '''
    def parser(self,argv):
        inputIP=''
        outputfile='output'
        download=0
        valid1=0
        valid2=0
        other_output_flag=0
        search=0
        source=0
        help=0
        merge_flag=0
        classic=-1
        asn_print=False
        arguments=''
        print_rule=False
        stringh=string_handler.string_handler()
        check_argv=[x for x in argv]
        input_file='input.txt'
        temp_argv=' '.join(argv)
        if temp_argv.count('[')>1 or temp_argv.count(']')>1:
            print ('Expected only one [ and only one ]. Exiting.')
            exit(0)
        elif '[' in temp_argv and ']' not in temp_argv:
            print ('Expected one ]. Exiting.') 
            exit(0)
        elif ']' in temp_argv and '[' not in temp_argv:
            print ('Expected one [. Exiting.') 
            exit(0) 
        elif '[' in temp_argv and ']' in temp_argv:
            try:
                if len(temp_argv.split(']'))>1:
                    temp_argv=temp_argv.split('[')[0]+temp_argv.split(']')[1]
                else:
                    temp_argv=temp_argv.split('[')[0]
            except:
                print(' Wrong syntax. Exiting.')
                exit(0)

        # Sanity checks for arguments as well as defining if the destination IP will be extracted from the cmd or input file.
        if temp_argv.count("-i")>1 or temp_argv.count("-d")>1 or temp_argv.count("-t")>1 or argv.count('')>1 or temp_argv.count("-h")>1 or temp_argv.count("-u")>1 or argv.count("-m")>1 or temp_argv.count("-o")>1 or temp_argv.count("-s")>1:
            print('Each traIXroute option must be used only once.')
            exit(0)
        elif ('-i' in temp_argv or '-d' in temp_argv) and ('-t' not in temp_argv and '-s' not in temp_argv):
            print('Please, choose one probing tool. Exiting.')
            exit(0)           
        elif ('-t' in temp_argv or '-s' in temp_argv) and ('-i' not in temp_argv and '-d' not in temp_argv):
            print('Please, choose one destination IP. Exiting.')
            exit(0)           
        elif '-i' in temp_argv and '-d' in temp_argv:
            print ('Please, choose only one method to set the destination IP to probe. Exiting.')
            exit(0)
        elif '-i' in temp_argv and ( '-t' in temp_argv or '-s' in temp_argv):
            [inputIP,check_argv]=self.extract_element(argv,'-i',False,check_argv)
            try:
                check_argv.remove('-i')
            except:
                pass
            valid1=1
        elif '-d' in temp_argv and ( '-t' in temp_argv or '-s' in temp_argv):
            [input_file,check_argv]=self.extract_element(argv,'-d',False,check_argv)
            try:
                check_argv.remove('-d')
            except:
                pass
            source=1
            valid1=1
            inputIP=input_file

        # -s for scamper, -t for traceroute (mandatory options).
        if '-s' in temp_argv and '-t' in temp_argv:
            print('Please, choose only one probing tool. Exiting.')
            exit(0)
        elif '-s' not in temp_argv and '-t' not in temp_argv and '-u' not in temp_argv and '-m' not in temp_argv and '-h' not in temp_argv:
            print('Please, choose one probing tool. Exiting.')
            exit(0)

        if '-s' in temp_argv and ('-i' in temp_argv or '-d' in temp_argv):
            [arguments,check_argv]=self.extract_element(argv,'-s',True,check_argv)
            if stringh.extract_ip(arguments, 'IP')!=[]:
                print('Wrong input, please give an IPv4 address or a url using the -i option.')
                exit(0)
            valid2=1
            classic=1
            try:
                check_argv.remove('-s')
            except:
                pass
        elif '-t' in temp_argv and ('-i' in temp_argv or '-d' in temp_argv):
            classic=0
            [arguments,check_argv]=self.extract_element(argv,'-t',True,check_argv)
            temp=stringh.extract_ip(arguments,'IP')
            try:
                check_argv.remove('-t')
            except:
                pass
            if len(temp)>0:
                inputIP=temp[0]
                arguments=arguments.replace(inputIP,'')
            if '-6' in arguments:
                print('IPv6 is not supported yet.')
                exit(0)
            valid2=1
        if '-asn' in temp_argv:
            asn_print=True
            try:
                check_argv.remove('-asn')
            except:
                pass
        if '-rule' in temp_argv:
            print_rule=True
            try:
                check_argv.remove('-rule')
            except:
                pass
        # The name of the output file, output.txt is the default name.
        if '-o' in temp_argv:
            [outputfile,check_argv]=self.extract_element(argv,'-o',False,check_argv)
            if outputfile=='':
                print('Expected a file name. Exiting.')
                exit(0)
            try:
                check_argv.remove('-o')
            except:
                pass
            other_output_flag=1

        if '-u' in temp_argv:
            download=1
            try:
                check_argv.remove('-u')
            except:
                pass
        if '-m' in temp_argv:
            merge_flag=1
            try:
                check_argv.remove('-m')
            except:
                pass
        # A valid traIXroute command stands when a destination IP address and a probing tool have been properly set.
        if valid1 and valid2:
            search=1
        elif not download and not merge_flag:
            help=1
        if '-h' in temp_argv:
            help=1
            try:
                check_argv.remove('-h')
            except:
                pass
        check_input=''.join(check_argv)
        if len(check_input):
            print('Wrong set of arguments for traIXroute. Exiting.')
            exit(0)
        if (not search and not download and not merge_flag) or help:
            print('usage: sudo python3 traIXroute.py -i <IP> -s <arguments>\nAlternative arguments:\n-h: Prints a list of the available command line options.\n-i <IP/URL>: The IP/URL destination to send the probe.\n-d <filename>: The file with the list of IP addresses.\n-u: Updates the databases.\n-o: Specifies the output file name.\n-m: Exports the database to two distinct files the ixp_prefixes.txt and ixp_membership.txt.\n-asn: Enables printing the ASN for each IP hop.\n-rule: Enables printing the IXP detection rule in the IXP Hops.\n-s "options": Calls traIXroute with scamper and (optional) scamper arguments.\n-t "options": Calls traIXroute with traceroute and (optional) traceroute arguments.')

        return inputIP,outputfile,download,search,classic,source,input_file,arguments,other_output_flag,merge_flag,asn_print,print_rule


    '''
    The main function which calls all the other modules.
    Inputs:
        a) argv: Τhe command line arguments.
    '''
    def main(self,argv):

        # Calls the parser for the arguments.
        (inputIP, outputfile,download,search,classic,source,input_file,arguments,other_output_flag,merge_flag,asn_print,print_rule)=self.parser(argv)
        mypath=sys.path[0]
        exact_time=datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
        if not other_output_flag:
            outputfile=outputfile+'_'+exact_time+'.txt'
        num_ips=0
        
        # Calls the download module if needed.
        if download or (not os.path.exists(mypath+'/database') and (search or merge_flag)):
            print ('Updating the database...')
            mydownload=download_files.download_files()
            outcome=mydownload.download_files(mypath)
            if mydownload:
                print ('Database was downloaded successfully.')
            else:
                print ('Database was not downloaded. Exiting...')
                exit(0)
        if search:
            if source:
                try:
                    f=open(input_file,'r')
                except:
                    print('Input file was not found. Exiting.')
                    exit(0)
                input_list=f.read()
                f.close
                input_list=input_list.split('\n')
                temp_point=0
                inputIP=input_list[temp_point]
            # Instead of an IP address, a domain name has been given as destination to send the probe, the domain name is reversed.
            string_handle=string_handler.string_handler()
            if not string_handle.is_valid_ip_address(inputIP,'IP'):
                try:
                    IP_name=socket.gethostbyname(inputIP)
                except:
                    print('Wrong input IP address format.\nExpected an IPv4 format or a valid url.')
                    exit(0)    
            elif not string_handle.check_input_ip(inputIP):
                print('Wrong input IP address format.\nExpected an IPv4 format or a valid url.')
                exit(0)

            detection_rules_node=detection_rules.detection_rules()
            [rules,assmt]=detection_rules_node.rules_extract('rules.txt')
            final_rules_hit=[0 for x in range(0,len(rules))]
            myinput=trace_tool.trace_tool()

        # Extract info from the database folder.
        if search or merge_flag:
            mydb=database_extract.database()
            [final_ixp2asn,final_sub2names,reserved_sub_tree,final_asn2ip,final_ixp2name,asn_routeviews,Sub_tree,dirty_ixp2asn,additional_info_tree]=mydb.dbextract('ixp_subnets','ixp_exchange','ixp_membership','ix.json','netixlan.json','ixpfx.json','ixlan.json','routeviews','additional_info.txt',merge_flag,mypath) 

        if search:
            output=traIXroute_output.traIXroute_output()
            output.print_args(classic, search,arguments)
            while(1):
                
                # Loads the IP list after parsing the input file.
                if source:
                    inputIP=input_list[temp_point]

                # Calls the module responsible for probing.
                output.print_traIXroute_dest(inputIP,outputfile,mypath)
                [IP_route,path_delay]=myinput.trace_call(inputIP,classic,arguments)
                num_ips=num_ips+1

                if IP_route!=0 and len(IP_route)>1:
                    
                    # IP path info extraction and print.
                    path_info_extract=path_info_extraction.path_info_extraction()
                    [asn_vector,encounter_type,ixp_long,ixp_short,unsure]=path_info_extract.path_info_extraction(final_ixp2asn,Sub_tree,IP_route,asn_routeviews,final_sub2names,final_ixp2name,dirty_ixp2asn,additional_info_tree)
                    
                    output.print_path_info(IP_route,asn_vector,path_delay,mypath,outputfile,ixp_short,ixp_long,unsure,asn_print)

                    # Applying rules.
                    rule_hits=detection_rules_node.resolve_path(IP_route,rules,assmt,asn_vector,encounter_type,ixp_long,ixp_short,final_asn2ip,mypath,outputfile,asn_print,print_rule)
                    final_rules_hit=[x + y for x, y in zip(final_rules_hit, rule_hits)]

                if source:
                    temp_point=temp_point+1
                else:
                    inputIP= input('Enter next target to probe or type exit for terminating:')

                # Extracting statistics.
                if (inputIP=='exit' or (source and temp_point>=len(input_list))):
                    self.stats_extract(mypath,'stats_'+exact_time+'.txt',num_ips,rules,final_rules_hit,exact_time)
                    break


    '''
    This function writes various statistics to the stats.txt file.
    Input: 
        a) mypath: The current directory path.
        b) filename: The file name to write.
        c) num_ips: The number of IPs to probe.
        d) funal_rules_hit: The number of "hits" for each rule.
        e) time: The starting timestamp of traIXroute.
    '''
    def stats_extract(self,mypath,filename,num_ips,rules,final_rules_hit,time):
        try:
            os.chdir(mypath+'/Output')
            f = open(filename, 'a')
        except:
            print('Output file not found. Exiting')
            exit(0)

        num_hits=sum(final_rules_hit)
        if num_ips>0:
            temp=num_hits/num_ips
            data='\ntraIXroute stats from '+time+' to '+ datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")+' \nNumber of IXP hits:'+str(num_hits)+' Number of traIXroutes:'+str(num_ips)+' IXP hit ratio:'+str(temp)+'\n'
            data=data+'Number of hits per rule:\n'
            for myi in range(0,len(rules)):
                if num_hits>0:
                    temp=final_rules_hit[myi]/num_hits
                    data=data+'Rule '+str(myi+1)+': Times encountered:'+str(final_rules_hit[myi])+' Encounter Percentage:'+str(temp)+'\n'
            f.write(data)
            f.close()
        os.chdir(mypath)

if __name__ == "__main__":
    traIXroute_module=traIXroute()
    traIXroute_module.main(sys.argv[1:])
