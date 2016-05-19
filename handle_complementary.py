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

import sys,string_handler,os,SubnetTree,download_files

'''
Handles the AS prefixes from Routeviews.
'''
class asn_handle():

    '''
    Imports the file from routeviews to a Subnet Tree.
    Input:
        a) filename: The file name from routeviews to parse.
        b) mypath: The directory path of the database folder.
    Output: 
        b) Stree: A SubnetTree containing Subnet-to-ASNs.
    '''
    def routeviews_extract(self,filename,mypath):
        handler=string_handler.string_handler()
        try:
            f=open('database/'+filename)
        except:
            download=download_files.download_files()
            print(filename+'.txt was not found. Downloading...')
            if not download.download_routeviews(mypath):
                exit(0)
            else:
                try:
                    f=open('database/'+filename)
                except:
                    print('Could not open '+filename+'. Exiting.')
                    exit(0)
        f2=f.read()
        f.close()
        f2=f2.split('\n')
        Stree=SubnetTree.SubnetTree()
        for i in range(0,len(f2)):
            f2[i]=f2[i].replace('\t',' ')
            temp=f2[i].split(' ')
            myip=handler.extract_ip(temp[0],'IP')
            if len(myip)>0:
                if handler.is_valid_ip_address(myip[0]+'/'+str(temp[1]),'Subnet'):
                    Stree[myip[0]+'/'+temp[1]]=myip[0]+'/'+temp[1]+','+temp[2]
        
        return Stree


'''
Handles the AS Membership information.
'''
class asn_memb_info():
    
    '''
    Constructs a new dictionary with {ASN}={IXP long name, IXP short name} based on IXP_final and dirty_ixp2asn dictionaries.
    Input:
        a) IXP_final: A dictionary with {IXP}=[ASN] after merging peeringdb and pch datasets.
        b) dirty_ixp2name: A dictionary with {IXP IP}=[IXP long name, IXP short name]. It is about dirty IXP IPs that do not belong to a known IXP Subnet.
        c) tree: The SubnetTree with the IXP prefixes.
        d) sub2names: A dictionary with {Subnet}=[IXP long name, IXP short name].
        e) dirty_ixp2asn: A dictionary with {IXP IP}=[ASN]. It is about dirty IXP IPs that do not belong to a known IXP Subnet.
    Output:
        a) ASn_memb: A dictionary with {ASN}=[IXP long name, IXP short name].
    '''
    def asn_memb(self,IXP_final,dirty_ixp2name,tree,sub2names,dirty_ixp2asn):
        stringh=string_handler.string_handler()
        ASn_memb={}
        for node in IXP_final.keys():
            temp_string_node=['','']
            new_key=IXP_final[node][0]
            if node in tree:
                subnet=tree[node]
                if subnet in sub2names:
                    temp_string_node=sub2names[subnet]
            elif node in dirty_ixp2name:
                temp_string_node=dirty_ixp2name[node]

            if new_key not in ASn_memb.keys():
                ASn_memb[new_key]=[temp_string_node]
            else:
                ASn_memb[new_key].append(temp_string_node)

        for node in dirty_ixp2asn.keys():
            temp_string_node=['','']
            new_key=dirty_ixp2asn[node][0]
            if node in dirty_ixp2name:
                temp_string_node=dirty_ixp2name[node]
            if new_key not in ASn_memb.keys():
                ASn_memb[new_key]=[temp_string_node]
            else:
                ASn_memb[new_key].append(temp_string_node)

        return ASn_memb


'''
Handles the reserved IPs.
'''
class reserved_handle():

    '''
    Loads the reserved subnets and returns a SubnetTree.
    Output:
        a) Stree: A Subnet Tree with the reserved subnets.
        b) lenreserved: The number of the reserved subnets.
    '''
    def reserved_extract(self):
        Stree=SubnetTree.SubnetTree()
        reserved_list=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4','255.255.255.255/32']
        for node in reserved_list:
            Stree[node]=node
        lenreserved=len(reserved_list)
        
        return Stree,lenreserved


'''
Imports the extracted IXP Subnets to a Subnet Tree.
'''
class Subnet_handle():

  '''
    Returns a Subnet Tree containing all the IXP subnets.
    Input:
        a) Sub: A dictionary with {Subnet}=[IXP long name,IXP short name].
    Output:
        a) Stree: A Subnet Tree with the IXP Subnets.
  '''
  def Subnet_tree(self,Sub):
    string_handle=string_handler.string_handler()
    Stree=SubnetTree.SubnetTree()
    for node in Sub:
        if string_handle.is_valid_ip_address(node,'Subnet'):
             Stree[node]=node
    return Stree


'''
This class extracts additional IXP related information provided by the user.
'''
class extract_additional_info():

    '''
    Input: 
        a) filename: the additional_info.txt file.
    Output: 
        a) IXP_dict: A dictionary with {IXP IP}=[ASN].
        b) IXP_to_names: A dictionary with {IXP IP}=[IXP long name,IXP short name].
        c) Subnet: A dictionary with {Subnet}=[IXP long name,IXP short name].
        d) additional_info_tree: A Subnet Tree containing all the IXP subnets provided by the user.
    '''
    def extract_additional_info(self,filename):
        mypath=sys.path[0]+'/'+filename
        handles=string_handler.string_handler()
        IXP_dict={}
        Subnet={}
        IXP_to_names={}
        additional_info_tree=SubnetTree.SubnetTree()

        # Creates the user IXP file if it does not exist.
        if not os.path.exists(mypath):
            try:
                f=open(mypath,'a')
                f.close()
            except:
                print('Could not create '+mypath+'.Exiting.')
                exit(0)
        else:
            try:
                f=open(mypath,'r')
            except:
                print('Could not open '+mypath+'. Exiting.')
                exit(0)
            data=f.read()
            f.close()
            data_lines=data.split('\n')
            
            # Parses the additional_info.txt file. 
            for i in range(0,len(data_lines)):

                # Clears the comments.
                data_lines[i]=data_lines[i].split('#')[0]
                data_lines[i]=data_lines[i].replace(' ','')
                if data_lines[i]=='':
                    continue
                line_split=data_lines[i].split(',')
                
                IXP=handles.extract_ip(data_lines[i],'Subnet')
                if len(IXP)>0:
                  IXP=IXP[0]
                else:
                  IXP=''
                # Imports only IXP Subnets with valid format.
                if handles.is_valid_ip_address(IXP,'Subnet') and IXP == line_split[0]:
                    if len(line_split)==3:

                        ixp_full_name=line_split[1]     
                        ixp_short_name=line_split[2]
                        if IXP not in Subnet.keys():
                            additional_info_tree[IXP]=[ixp_full_name,ixp_short_name]
                            Subnet[IXP]=[ixp_full_name,ixp_short_name]
                        else:
                            print('additional_info.txt: Multiple similar IXP Prefixes detected. Exiting.')
                            exit(0)         
                # # Imports only IXP IPs with valid format.
                    else:
                        print('Invalid syntax in line '+str(i+1)+'. Exiting.')
                        exit(0)

                else: 
                    IXP=handles.extract_ip(data_lines[i],'IP')
                    if len(IXP)>0:
                      IXP=IXP[0]
                    else:
                      IXP=''
                    if len(line_split)==4:
                        try:
                            int(line_split[1])
                        except:
                            print('additional_info.txt: Invalid syntax in line '+str(i+1)+'. Exiting.')
                            exit(0)
                        ASn=line_split[1]
                        ixp_full_name=line_split[2]
                        ixp_short_name=line_split[3]
                        if handles.is_valid_ip_address(IXP,'IP') and IXP==line_split[0]:
                            if IXP not in IXP_dict.keys():
                                IXP_dict[IXP]=[ASn]
                                IXP_to_names[IXP]=[ixp_short_name,ixp_full_name]
                            else:
                                print('additional_info.txt: Multiple similar IXP IPs detected. Exiting.')
                                exit(0)                                 
                        else:
                            print('additional_info.txt: Invalid syntax in line '+str(i+1)+'. Exiting.')
                            exit(0)                            
                    else:
                        print('additional_info.txt: Invalid syntax in line '+str(i+1)+'. Exiting.')
                        exit(0)
        return [IXP_dict,IXP_to_names,Subnet,additional_info_tree]