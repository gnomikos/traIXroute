# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis and George Nomikos
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

import os,socket

'''
Handles all the prints.
'''

class traIXroute_output():


    '''
    Prints the number of the extracted IXP IP addresses and Subnets from each dataset before and after merging.
    Input:
        a) peering_ixp2asn: A dictionary with {IXP IP}=[ASN] extracted from peeringdb.
        b) peering_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] extracted from peeringdb. 
        c) pch_ixp2asn: A dictionary with {IXP IP}=[ASN] extracted from pch.
        d) pch_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] extracted from pch.
        e) final_ixp2asn: A dictionary with {IXP IP}=[ASN] after merging pch, peeringdb and user's data.
        f) final_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] after merging pch, peeringdb and user's data.
        g) dirty_ips: A dictionary with {IXP IP}=[ASN]. It is about dirty IXP IPs-to-ASNs. 
        h) additional_ip2asn: A dictionary with {IXP IP}=[ASN], imported from the user.
        i) additional_subnet2name: A dictionary with {IXP Subnet}=[IXP long name, IXP short name], imported from the user.
        j) lenreserved: The number of the imported reserved subnets.
    '''
    def print_db_stats(self,peering_ixp2asn,peering_sub2name,pch_ixp2asn,pch_sub2name,final_ixp2asn,final_sub2name,dirty_ips,additional_ip2asn,additional_subnet2name,lenreserved):
        
        print('Imported '+ str(lenreserved)+' Reserved Subnets.')  
        print('Extracted '+ str(len(additional_ip2asn.keys()))+' IXP IPs from additional_info.txt.')
        print('Extracted '+ str(len(additional_subnet2name.keys()))+' IXP Subnets from additional_info.txt.')        
        print('Extracted '+ str(len(peering_ixp2asn.keys()))+' IXP IPs from PDB.')
        print('Extracted '+ str(len(pch_ixp2asn.keys()))+' IXP IPs from PCH.')
        print('Extracted '+ str(len(peering_sub2name.keys()))+' IXP Subnets from PDB.')
        print('Extracted '+ str(len(pch_sub2name.keys()))+' IXP Subnets from PCH.')
        print('Extracted '+ str(len(final_ixp2asn.keys()))+' not dirty IXP IPs after merging PDB, PCH and additional_info.txt.')
        print('Extracted '+ str(len(dirty_ips.keys()))+' dirty IXP IPs after merging PDB, PCH and additional_info.txt.')
        print('Extracted '+ str(len(final_sub2name.keys()))+' IXP Subnets after merging PDB, PCH and additional_info.txt.')


    '''
    Prints and exports the IP path to a file.
    Input:
        a) ip_path: The IP path.
        b) asn_list: A list with the ASNs in the IP path.
        c) mytime: The hop delays.
        d) mypath: The traIXroute directory path.
        e) outputfile: The output file name.
        f) ixp_short_names: A list with The IXP short names.
        g) unsure: A list with flags to specify in which hop an IXP IP is considered as "dirty".
        h) ixp_long_names: A list with the IXP long names.
        i) asn_print: TRUE if the user wants to print the ASNs, FALSE otherwise.
    '''
    def print_path_info(self,ip_path,asn_list,mytime,mypath,outputfile,ixp_short_names,ixp_long_names,unsure,asn_print):

        # Makes dns queries.
        dns=[ip_path[i] for i in range(0,len(ip_path))]
        for i in range(0,len(ip_path)):
            if ip_path[i]!='*':
                try:
                    dns[i]=socket.gethostbyaddr(ip_path[i])[0]
                except:
                    pass

        write_path=mypath+'/Output'
        if os.path.exists(write_path)==False:
            os.makedirs(write_path)

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
            gra_path[i]=self.gra_in(numbers[i],maxlennum+defaultstep)
            if asn_print:
                gra_asn[i]=self.gra_in('AS'+asn_list[i],maxlenas+defaultstep)
            else:
                gra_asn[i]=self.gra_in('AS'+asn_list[i],len('AS'+asn_list[i])+defaultstep)
                
        # Prints the output and saves it to a file.
        os.chdir(mypath+'/Output')
        try:
            f = open(outputfile, 'a')
            data='traIXroute to '+dns[-1]+'('+ip_path[-1]+')'
            print (data)
            f.write(data+'\n')
            for i in range(0,len(ip_path)):
                if ixp_short_names[i]=='Not IXP' and ixp_long_names[i]=='Not IXP':
                    if asn_print:
                        temp_print=gra_path[i]+gra_asn[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]
                        print(temp_print)
                        f.write(temp_print+'\n')
                    else:
                        temp_print=gra_path[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]
                        print(temp_print)
                        f.write(temp_print+'\n')
                else:
                    if ixp_short_names[i]!='':
                        temp_print=gra_path[i]+unsure[i]+ixp_short_names[i]+'->'+gra_asn[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]
                        print(temp_print)
                        f.write(temp_print+'\n')
                    else:
                        temp_print=gra_path[i]+unsure[i]+ixp_long_names[i]+'->'+gra_asn[i]+dns[i]+' '+'('+ip_path[i]+')'+' '+mytime[i]
                        print(temp_print)
                        f.write(temp_print+'\n')                    
            print('IXP Hops:')
            f.write('IXP Hops:\n')
            f.close()
            os.chdir(mypath)
        except:
            print('---> Could not open output file, try to execute traIXroute with administrator rights. Exiting.')
            exit(0)
    
    
    '''
    Sanitizes traIXroute output.
    Input: 
        a) string1: The string to be modified.
        b) number1: The number of empty spaces between strings.
    Ouput:
        a) string1: The polished output of traIXroute with the columns to be aligned.
    '''
    def gra_in(self,string1,number1):
        while len(string1)<number1:
            string1=string1+' '

        return string1


    '''
    Prints the number of extracted rules.
    Input:
        a) final_rules: The list containing the rules.
        b) file: The file containing the rules.
    '''
    def print_rules_number(self,final_rules,file):
        print("Imported "+str(len(final_rules))+" IXP Detection Rules from "+file+".")       
    
    
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
        i) f: An ouput file object.
        j) num: The number of detected IXP Hops.
        k) ixp_short: A list that contains short IXP names.
        l) cur_asmt: The current assesment.
    '''
    def print_result(self,asn_print,print_rule,cur_ixp_long,cur_ixp_short,cur_path_asn,path,i,j,f,num,ixp_short,cur_asmt):
     
        rule=''
        if print_rule:
            rule= 'Rule: '+str(j+1)+' --- '
        
        gra_asn=['' for x in cur_path_asn]
        ixp_string=['' for x in cur_ixp_short]
        for pointer in range(0,len(ixp_string)):
            if len(ixp_short)>i+pointer-1:
                if ixp_short[i+pointer-1]!='Not IXP':
                    if ixp_short[i+pointer-1]!='':
                        ixp_string[pointer]=ixp_short[i+pointer-1]  
                    else:
                        ixp_string[pointer]=ixp_long[i+pointer-1]
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
            print(temp_print)
            f.write(temp_print+'\n')

            if 'aorb' in cur_asmt:
                temp_print=' or '+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
                print(temp_print)
                f.write(temp_print+'\n')
            if 'aandb' in cur_asmt:
                temp_print=('and ('+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2])
                print(temp_print)
                f.write(temp_print+'\n')
        elif 'b' in cur_asmt:
            temp_print=rule+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
            print(temp_print)
            f.write(temp_print+'\n')


    '''
    Prints a message in case no IXP Hops were found.
    Input:
        a) f: An ouput file object. 
    '''    
    def print_no_IXPs(self,f):

           print ('No IXP Hops found.')
           f.write('No IXP Hops found.\n')


    '''
    Prints the arguments of traceroute
    Input:
        a) classic: Flag to choose between traceroute and scamper.
        b) search: Flag to send probe.
        c) arguments: Probing arguments.
    '''
    def print_args(self, classic, search,arguments):

        if classic and search:
            if arguments!='':
                print('TraIXrouting using scamper with "'+arguments+'" options.')
            else:
                print('TraIXrouting using scamper with default options.')
        elif search:
            if arguments!='':
                print('TraIXrouting using traceroute with "'+arguments+'" options.')
            else:
                print('TraIXrouting using traceroute with default options.')