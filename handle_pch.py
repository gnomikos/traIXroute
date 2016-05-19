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

import dict_merger,string_handler,SubnetTree,download_files

'''
This class imports the PCH dataset.
'''
class pch_handle():

    '''
    Handles all the methods to import IXP related information from PCH files.
    Input:
        a) ixp_membership: The ixp_membership.csv file.
        b) ixp_subnet: The ixp_subnets.csv file.
        c) ixp_excha: The ixp_exchange.csv file.
        d) mypath: The directory path of the database.
        e) reserved_tree: The SubnetTree containing the reserved Subnets.
    Output:
        a) pch_final: A dictionary with {IXP Subnet}=[IXP long name,IXP short name].
        b) ixp_mem: A dictionary with {IXP IP}=[ASN].
        c) dirty: A dictionary with {IXP IP}=[IXP long name,IXP short name]. It is about "dirty" IXP IP addresses.
    '''
    def pch_handle_main(self,ixp_membership,ixp_subnet,ixp_excha,mypath,reserved_tree):

        sub_mem=self.pch_handle_sub(ixp_subnet,mypath,reserved_tree)
        long_mem=self.pch_handle_long(ixp_excha,mypath)
        pch_final=self.unite_long_short(long_mem,sub_mem)

        [ixp_mem,dirty]=self.pch_handle_ixpm(ixp_membership,mypath,reserved_tree)

        return pch_final,ixp_mem,dirty


    '''
    Extracts the IXP IPs from PCH.
    Input: 
        a) filename: The ixp_membership.csv file.
        b) mypath: The directory path of the database.
        c) reserved_tree: The SubnetTree containing the reserved Subnets.
    Output:
        a) IXP_IP: A dictionary with {IXP IP}=[ASN].
        b) dirty: A dictionary with {IXP IP}=[ASN]. It is about "dirty" IXP IP addresses.
    '''
    def pch_handle_ixpm(self,filename,mypath,reserved_tree):

        doc=self.file_opener(filename,mypath,3)
        table = doc.read()
        doc.close()
        table=table.split('\n')
        tree=SubnetTree.SubnetTree()
        IXP_IP= {}
        sub_to_ixp={}
        dirty={}

        hstring=string_handler.string_handler()
        count=0
        dumped_ixps=[]
        for i in range(0,len(table)-1):
            temp_string=table[i+1].split(',')
            if len(temp_string)>1:
                ip=hstring.extract_ip(temp_string[1],'IP')
                for inode in ip:
                    inode=hstring.clean_ip(inode,'IP')
                    if hstring.is_valid_ip_address(inode,'IP'):
                        subnet=hstring.extract_ip(temp_string[0],'Subnet')
                        for snode in subnet:
                            snode=hstring.clean_ip(snode,'Subnet')
                            if hstring.is_valid_ip_address(snode,'Subnet'):
                                tree[snode]=snode
                            if inode in tree and inode not in IXP_IP.keys() and inode not in dumped_ixps and inode not in reserved_tree:
                                IXP_IP[inode]=[temp_string[3].replace(' ','')]
                            elif inode in IXP_IP.keys():
                                if IXP_IP[inode]!=[temp_string[3].replace(' ','')]:
                                    IXP_IP.pop(inode,None)
                                    dumped_ixps.append(inode)
                            elif inode not in dumped_ixps:
                                dirty[inode]=[temp_string[3].replace(' ','')]
        return IXP_IP,dirty
    

    '''
    Extracts the IXP keys-to-Subnets from the ixp_subnets.csv file.
    Input:
        a) filename: The ixp_subnets.csv file.
        b) mypath: The directory path of the database.
        c) reserved_tree: The SubnetTree containing the reserved Subnets.
    Output: 
        a) IXP: A dictionary with {keyid}=[IXP short name, IXP Subnet].
    '''
    def pch_handle_sub(self,filename,mypath,reserved_tree):
        handled_string=string_handler.string_handler()
        doc=self.file_opener(filename,mypath,1)
        table = doc.read()
        doc.close()
        table=table.split('\n')
        IXP={}
        subnets={}
        denied_subs=[]

        for i in range(0,len(table)-1):
            temp_string=table[i+1].split(',')
            if len(temp_string)>5:
                mykey=temp_string[0]
                myip=temp_string[6]
                myip=handled_string.extract_ip(myip,'Subnet')
                for ips in myip:
                    ips=handled_string.clean_ip(ips,'Subnet')
                    if ips!='':
                        if handled_string.is_valid_ip_address(ips,'Subnet') and ips not in subnets.keys() and ips not in denied_subs and ips not in reserved_tree:
                            subnets[ips]=mykey
                            IXP[mykey]=[temp_string[1],ips]
                        elif ips in subnets.keys():
                            if subnets[ips]!=mykey:
                                IXP.pop(subnets[ips],None)
                                subnets.pop(ips,None)
                                denied_subs.append(ips)
        return (IXP)

    
    '''
    Returns a dictionary with the IXP long names.
    Input: 
        a) filename: The ixp_exchange.csv file.
        b) mypath: The directory path of the database.
    Output:
        a) IXP_IP: A dictionary with {keyid}=[IXP long name].
    '''
    def pch_handle_long(self,filename,mypath):
        doc=self.file_opener(filename,mypath,2)
        table = doc.read()
        doc.close()
        table=table.split('\n')
        IXP_IP={}
        for i in range(0,len(table)-1):
            temp_string=table[i+1].split(',')
            if len(temp_string)>5:
                IXP_IP[temp_string[0]]=[temp_string[4]]

        return (IXP_IP)


    '''
    Merges two dictionaries.
    Input
        a) table_long: A dictionary with {keyid}=[IXP long name].
        b) table_short: A dictionary with {keyid}=[IXP short name, IXP Subnet].
    Output
        a) final_table: A dictionary with {IXP Subnet}=[IXP long name, IXP short name].
    '''
    def unite_long_short(self,table_long,table_short):
        final_table={}
        dict_m=dict_merger.dict_merger()
        temp_table=dict_m.inner_join(table_long,table_short)
        str_handle=string_handler.string_handler()

        for node in temp_table:
            myvalues=temp_table[node]
            if len(myvalues)>2:
                new_item=[myvalues[0],myvalues[1]]
            elif len(myvalues)>1:
                new_item=[myvalues[0],myvalues[0]]
            else:
                new_item=['','']
            Subnet=str_handle.extract_ip(myvalues[2],'Subnet')[0]
            if Subnet!='' and Subnet not in final_table.keys():
                final_table[Subnet]=new_item
            elif Subnet in final_table.keys():
                del_flag=True
                if str_handle.string_comparison(final_table[Subnet][0],new_item[0]):
                    del_flag=False
                    new_item=[final_table[Subnet][0],'']
                if str_handle.string_comparison(final_table[Subnet][0],new_item[1]):
                    del_flag=False
                    new_item=[new_key[0],final_table[Subnet][1]] 
                if del_flag:
                    final_table.pop(Subnet, None)
                else:
                    final_table[Subnet]=new_item
        
        return final_table


    '''
    Opens the .csv files. If they are missing, it downloads the missing file.
    Input:
        a) filename: The file name to open.
        b) mypath: The directory path of the database.
        c) option: Flag to select file to download.
    Output:
        a) doc: The file object.
    '''
    def file_opener(self,filename,mypath,option):
        try:
            doc=open('database/'+filename+'.csv')
        except:
            download=download_files.download_files()
            print (filename+' was not found. Downloading...')
            if not download.download_pch(mypath,option):
                exit(0)
            else:
                try:
                    doc=open('database/'+filename+'.csv')
                except:
                    print ('Could not open '+filename+'. Exiting')
                    exit(0)
                    
        return doc