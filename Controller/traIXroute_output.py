#!/usr/bin/env python3

# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis, Dimitris Mavrommatis and George Nomikos
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

import os, socket, sys
from Controller import string_handler
from threading import Lock
from time import ctime

class traIXroute_output():
    '''
    Handles all the outputs.
    '''

    def __init__(self):
        # self.print_data: The data to print.
        self.print_data = ''


    def flush(self,fp):
        '''
         Prints the data and flushes them to a file.
         Input:
            a) fp: The pointer to the file to write the data.
        '''
        
        print(self.print_data)
        fp.write(self.print_data+'\n')
        self.print_data = ''


    def print_db_stats(self,peering_ixp2asn,peering_sub2name,pch_ixp2asn,pch_sub2name,final_ixp2asn,final_sub2name,dirty_ips,additional_ip2asn,additional_subnet2name,lenreserved,db_print,mypath):
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

        tmp='Imported '+ str(lenreserved)+' Reserved Subnets.\n'  
        tmp=tmp+'Extracted '+ str(len(additional_ip2asn))+' IXP IPs from additional_info.txt.\n'
        tmp=tmp+'Extracted '+ str(len(additional_subnet2name)-len(additional_ip2asn))+' IXP Subnets from additional_info.txt.\n'     
        tmp=tmp+'Extracted '+ str(peering_ixp2asn)+' IXP IPs from PDB.\n'
        tmp=tmp+'Extracted '+ str(pch_ixp2asn)+' IXP IPs from PCH.\n'
        tmp=tmp+'Extracted '+ str(peering_sub2name)+' IXP Subnets from PDB.\n'
        tmp=tmp+'Extracted '+ str(pch_sub2name)+' IXP Subnets from PCH.\n'
        tmp=tmp+'Extracted '+ str(len(final_ixp2asn))+' no dirty IXP IPs after merging PDB, PCH and additional_info.txt.\n'
        tmp=tmp+'Extracted '+ str(dirty_ips)+' dirty IXP IPs after merging PDB, PCH and additional_info.txt.\n'
        tmp=tmp+'Extracted '+ str(len(final_sub2name))+' IXP Subnets after merging PDB, PCH and additional_info.txt.\n'
        if db_print:
            print(tmp)        
        try:
            f=open(mypath+'db.txt','w')
            f.write(tmp)
            f.close()
        except:
            print('Could not open db.txt file. Exiting.')
            sys.exit(0)


    def print_path_info(self,ip_path,mytime,mypath,path_info_extract,traIXparser):
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
        
        # Makes dns queries.
        if dns_print:
            dns=[ip_path[i] for i in range(0,len(ip_path))]
            for i in range(0,len(ip_path)):
                if ip_path[i]!='*':
                    try:
                        dns[i]=socket.gethostbyaddr(ip_path[i])[0]
                    except:
                        pass
        else:
            dns=['' for i in range(0,len(ip_path))]

        # The minimum space between the printed strings.
        defaultstep = 3

        # The numbers to be printed in front of each line.
        numbers = [str(x)+')' for x in range(1,len(ip_path)+1)]

        # Fix indents for printing.
        maxlenas = 0
        maxlennum = 0
        gra_path = ['*' for x in range(0,len(ip_path))]
        gra_asn = ['' for x in range(0,len(ip_path))]

        for i in range(0,len(ip_path)):
            temp=len('AS'+asn_list[i])
            if temp>maxlenas:
                maxlenas=temp
            temp=len(numbers[i])
            if temp>maxlennum:
                maxlennum=temp
                
        for i in range(0,len(ip_path)):
            gra_path[i]=self.polish_output(numbers[i],maxlennum+defaultstep)
            if asn_print:
                gra_asn[i]=self.polish_output('AS'+asn_list[i],maxlenas+defaultstep)
            else:
                gra_asn[i]=self.polish_output('AS'+asn_list[i],len('AS'+asn_list[i])+defaultstep)
                
        # Prints the output and saves it to a file.
        print_data=''
        for i in range(0,len(ip_path)):
            if ixp_short_names[i]==['No Short Name'] and ixp_long_names[i]==['No Long Name']:
                if asn_print:
                    temp_print=gra_path[i]+gra_asn[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]
                else:
                    temp_print=gra_path[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]
            else:
                base_ixp_print='('
                for ixp in range(0,len(ixp_short_names[i])):
                    if ixp>0:
                        base_ixp_print=base_ixp_print+','
                    if ixp_short_names[i][ixp]!='':
                        base_ixp_print=base_ixp_print+ixp_short_names[i][ixp]
                    else:
                        base_ixp_print=base_ixp_print+ixp_long_names[i][ixp]
                base_ixp_print=base_ixp_print+')'
                temp_print=gra_path[i]+unsure[i]+base_ixp_print+'->'+gra_asn[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]

            print_data+=temp_print+'\n'
            
        print_data=print_data+'IXP Hops:\n'
        self.print_data += print_data

    
    def print_traIXroute_dest(self,input_IP,origin='',info=''):
        '''
        Prints traIXroute destination.
        Input:
            a) input_IP: The destination IP/FQDN to probe.
            b) origin: The IP that issued the probe (optional).
            c) info: Traceroute path description.
        '''

        string_handle=string_handler.string_handler()
        dns_name='*'
        output_IP='*'
        if string_handle.is_valid_ip_address(input_IP,'IP'):
            try:
                dns_name=socket.gethostbyaddr(input_IP)[0]
            except:
                pass
            output_IP=input_IP
        else:
            try:
                output_IP=socket.gethostbyname(input_IP)
            except:
                pass
            dns_name=input_IP
        if origin!='':
            origin_dns=''
            try:
                origin_dns=socket.gethostbyaddr(origin)[0]
            except:
                pass
            origin=' from '+origin_dns+'('+origin+')'

        print_data='traIXroute'+origin+' to '+dns_name+' ('+output_IP+').'
        if info!='':
            print_data=print_data+' info: '+info
    
        self.print_data += print_data+'\n'


    def polish_output(self,string1,number1):
        '''
        Sanitizes traIXroute output.
        Input: 
            a) string1: The string to be modified.
            b) number1: The number of empty spaces between strings.
        Ouput:
            a) string1: The polished output of traIXroute with the columns to be aligned.
        '''

        while len(string1)<number1:
            string1=string1+' '
        return string1


    def print_rules_number(self,final_rules,file):
        '''
        Prints the number of extracted rules.
        Input:
            a) final_rules: The list containing the rules.
            b) file: The file containing the rules.
        '''

        print("Imported "+str(len(final_rules))+" IXP Detection Rules from "+file+".")       
    
    
    def print_result(self,asn_print,print_rule,cur_ixp_long,cur_ixp_short,cur_path_asn,path,i,j,num,ixp_short,cur_asmt,ixp_long,cc_tree):
        '''
        Prints IXP Hops if they exist.
        Input: 
            a) asn_print: TRUE if the user wants to print the ASNs, FALSE otherwise.
            b) print_rule: TRUE if the user wants to print the rule that infered the IXP crossing, FALSE otherwise.
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
            m) cc_tree: SubnetTree that contains Subnets to [country,city]
        '''
     
        rule=''
        if print_rule:
            rule= 'Rule: '+str(j+1)+' --- '
        
        gra_asn=['' for x in cur_path_asn]
        ixp_string=['' for x in cur_ixp_short]

        for pointer in range(0,len(ixp_string)):
            if len(ixp_short)>i+pointer-1:
                if ixp_short[i+pointer-1]!=['No Short Name']:
                    cc_code=['','']
                    if path[i+pointer-1] in cc_tree:
                        cc_code=cc_tree[path[i+pointer-1]]
            if cur_ixp_short[pointer]!='No Short Name':
                if cur_ixp_short[pointer]!='':
                    ixp_string[pointer]=cur_ixp_short[pointer]+' ('+cc_code[0]+','+cc_code[1]+')'
                else:
                    ixp_string[pointer]=cur_ixp_long[pointer]+' ('+cc_code[0]+','+cc_code[1]+')'
        asm_a=ixp_string[0]
        if ixp_string[0]!='' and ixp_string[1]!='' and  ixp_string[0]!=ixp_string[1]:
            asm_a=asm_a+','
        if ixp_string[1]!='' and ixp_string[0]!=ixp_string[1]:
            asm_a=asm_a+ixp_string[1]
        if len(ixp_string)>2:
            asm_b=ixp_string[1]
            if ixp_string[1]!='' and ixp_string[2]!='' and ixp_string[2]!=ixp_string[1]:
                asm_b=asm_b+','
            if ixp_string[2]!=''  and ixp_string[1]!=ixp_string[2]:
                asm_b=asm_b+ixp_string[2]
        if asn_print:
            for pointer in range(0,len(gra_asn)):
                gra_asn[pointer]=' (AS'+cur_path_asn[pointer]+')'    
        if 'a' in cur_asmt:
            temp_print=rule+str(i)+') ' +path[i-1]+gra_asn[0]+' <--- '+asm_a+' ---> '+str(i+1)+') '+path[i]+gra_asn[1]
            
            if 'aorb' in cur_asmt:
                temp_print+=' or '+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
            elif 'aandb' in cur_asmt:
                temp_print+=('and ('+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2])
        elif 'b' in cur_asmt:
            temp_print=rule+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
    
        if temp_print not in self.print_data:
            self.print_data += temp_print+'\n'


    def print_no_IXPs(self):
        '''
        Prints a message in case no IXP Hops have been found.
        '''    

        self.print_data += 'No IXP Hops have been found.\n'


    def print_args(self, classic, search,arguments,from_ripe,from_import):
        '''
        Prints the arguments of traceroute
        Input:
            a) classic: Flag to choose between traceroute and scamper.
            b) search: Flag to start a measurement.
            c) arguments: Probing arguments.
            d) from_ripe: Flag when usisn ripe.
            e) from_import: Flag when importing from json file.
        '''
        try:
            if classic and search:
                if arguments!='':
                    print('traIXroute using scamper with "'+arguments+'" options.')
                else:
                    print('traIXroute using scamper with default options.')
            elif search and not (from_ripe or from_import):
                if arguments!='':
                    print('traIXroute using traceroute with "'+arguments+'" options.')
                else:
                    print('traIXroute using traceroute with default options.')
            elif from_ripe==1:
                print('Run traIXroute on an online ripe measurement: '+str(arguments))
            elif from_ripe==2:
                print('Creating a new measurement at RIPE Atlas: '+str(arguments))
            elif from_import==1:
                print('Run traIXroute from a file with traIXroute json format: '+str(arguments))
            elif from_import==2:
                print('Run traIXroute from a file with ripe json format: '+str(arguments))
        except:
            pass
    

    def print_pr_db_stats(self,filepath):
        '''
        Prints the number of the extracted IXP IP addresses and Subnets from each dataset for the last time the datasets were merged. 
        Input:
            a) filepath: The directory path of the file that contains the stats.
        '''

        try:
            f=open(filepath,'r')
            data=f.read()
            print(data)
            f.close
        except:
            print('Could not open db.txt.')
            pass


    def read_lst_mod(self,filename,mypath):
        '''
        Reads the lst_mod.txt file, which contains the last modification of the additional_info.txt and compares it
        with the current modification timestamp of the additional_info.txt.
        Input:
            a) filename: The lst_mod.txt file.
            b) mypath: The path to traIXroute folder.
        Output:
            b) True if the file has not been modified, False otherwise.
        '''

        try:
            additional_lst_mod=ctime(os.path.getmtime(sys.path[0]+'/additional_info.txt'))
            f=open(filename,'r')
            data=f.read()
            data=data.split('\n')
            data=data[0]
            if data==additional_lst_mod:
                return True
        except:
            pass

        self.write_lst_mod(filename,additional_lst_mod)
        return False
    

    def write_lst_mod(self,filename,data):
        '''
        Writes the last modification timestamp of the additional_info.txt to the lst_mode.txt.
        Input:
            a) filename: The lst_mode.txt file.
            b) data: The modification timestamp.
        '''

        try:
            f=open(filename,'w')
            f.write(data)
        except:
            print('Could not write to lst_mod.txt. Exiting')
            sys.exit(0)

