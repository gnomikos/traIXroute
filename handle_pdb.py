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

import dict_merger,json, string_handler, SubnetTree, download_files

'''
This class imports the peerindb dataset.
'''
class peering_handle():
    
    '''
    Handles all the methods to import IXP related information from peeringdb .json files.
    Input:
        a) filename_peer_name: The ix.json file.
        b) filename_peer_ip: The netixlan.json file.
        c) filaname_peer_pfx: The ixpfx.json file.
        d) filename_peer_ixlan: The ixlan.json file.
        e) reserved_tree: The SubnetTree containing the reserved Subnets.
    Output: 
        a) sub2names: A dictionary with {Subnet}=[IXP long name, IXP short name].
        b) ip2asn: A dictionary with {IXP IP}=[ASN].
        c) dirty_IXP_to_name: A dictionary with {IXP IP}=[IXP long name, IXP short name]. It is about "dirty" IXP IP addresses.
        d) dirty_ixp2asn: A dictionary with {IXP IP}=[ASN]. It is about "dirty" IXP IP addresses.
    '''
    def peering_handle(self,filename_peer_name,filename_peer_ix,filename_peer_pfx,filename_peer_ixlan,add_subnet_tree,mypath,reserved_tree):

        json_names=self.extract_json_data(filename_peer_name,mypath,2)
        id_to_names=self.extract_names(json_names)

        json_ixlan=self.extract_json_data(filename_peer_ixlan,mypath,4)
        ixlan_dict=self.extract_ixlan(json_ixlan)

        json_pfx=self.extract_json_data(filename_peer_pfx,mypath,1)
        (sub2names,temp_subnet_tree)=self.extract_pfx(json_pfx,ixlan_dict,id_to_names,reserved_tree)

        json_ip=self.extract_json_data(filename_peer_ix,mypath,3)
        (ip2asn,dirty_ixp_to_name,dirty_ixp2asn)=self.extract_ip(json_ip,temp_subnet_tree,add_subnet_tree,reserved_tree)

        return(sub2names,ip2asn,dirty_ixp_to_name,dirty_ixp2asn)

    
    '''
    Imports .json files from peeringdb and returns a list of dictionaries with all the retrieved IXP information.
    Input: 
        a) filename_peer_name: A .json file name.
        b) mypath: The directory path of the database.
        c) option: Flag to download the file.
    Ouput: 
        a) A list of dictionaries.
    '''
    def extract_json_data(self,filename_peer_name,mypath,option):
        try:
            with open ('database/'+filename_peer_name) as data_file:
                obj = json.load(data_file)
        except:
            download=download_files.download_files()
            print(filename_peer_name+' was not found. Downloading...')
            if not download.download_peering(mypath,option):
                exit(0)
            else:
                try:
                    with open ('database/'+filename_peer_name) as data_file:
                        obj = json.load(data_file)
                except:
                    print('Could not open '+filename+' Exiting.')
                    exit(0)
        return (obj['data'])


    '''
    Extracts a json table and returns a key-to-key dictionary to bind the ix.json with the ixpfx.json via the ixlan.csv file.
    Input:
        a) json_ixlan: A json table with ixlan and ix ids. 
    Ouput: 
        a) ixlan_dict: A dictionary with {ixlan key}=ix key.
    '''
    def extract_ixlan(self,json_ixlan):
        ixlan_dict={}
        for node in json_ixlan:
            ixlan_id=node['id']
            ixlan_ixid=node['ix_id']
            ixlan_dict[ixlan_id]=ixlan_ixid

        return (ixlan_dict)


    '''
    Extracts the IXP ID-to-IXP names from the ix.json file.
    Input:
        a) json_names: A json table with ix ids and the IXP long and short names.
    Output:
        a) names_dict: A dictionary with {ix id}=[IXP long name, IXP short name].
    '''
    def extract_names(self,json_names):
        names_dict={}
        for node in json_names:
            ixid=node['id']
            ixname=node['name']
            ixlong=node['name_long']
            names_dict[ixid]=[ixlong,ixname]
        
        return (names_dict)


    '''
    Extracts the prefixes from ixpfxs:
    Input:
        a) json_pfx: A json table containing the IXP prefixes and ids to ixlan.
        b) ixlan_dict: A dictionary with {ixlan id} = [ix id] to bind IXP prefixes and IXP names.
        c) id_to_names: A dictionary with {ix id}= [IXP long name, IXP short name]
        d) reserved_tree: The SubnetTree containing the reserved Subnets.
    Output:
        a) pfxs_dict: A dictionary with {IXP Subnet}=[IXP long name, IXP short name].
        b) temp_subnet_tree: A Subnet Tree with IXP Subnet-to-ix id.
    '''
    def extract_pfx(self,json_pfx,ixlan_dict,id_to_names,reserved_tree):
        handler=string_handler.string_handler()
        pfxs_dict={}
        i=0
        temp_subnet_tree=SubnetTree.SubnetTree()
        denied_subs=[]
        for node in json_pfx:
            subnet=handler.extract_ip(node['prefix'],'Subnet')
            for s in subnet:
                if handler.is_valid_ip_address(s,'Subnet') and s not in reserved_tree:
                    ixpfx=s
                    ixlan_id=node['ixlan_id']
                    if ixlan_id in ixlan_dict.keys():
                        ix_id=ixlan_dict[ixlan_id]
                        if ix_id in id_to_names.keys() and s not in pfxs_dict and s not in denied_subs:
                            pfxs_dict[s]=id_to_names[ix_id]
                            temp_subnet_tree[s]=ix_id
                        elif s in pfx_dict:
                            del_flag=True
                            new_item=['','']
                            if handler.string_comparison(pfxs_dict[s][0],id_to_names[ix_id][0]):
                                del_flag=False
                                new_item=[pfxs_dict[s][0],'']
                            if handler.string_comparison(pfxs_dict[s][1],id_to_names[ix_id][1]):
                                del_flag=False
                                new_item=[new_item[0],pfxs_dict[s][1]]
                            if del_flag:
                                pfxs_dict.pop(s,None)
                                temp_subnet_tree.remove(s)
                                denied_subs.append(s)
                            else:
                                pfxs_dict[s]=new_item

        return (pfxs_dict,temp_subnet_tree)


    '''
    Extracts the IXP IPs from peeringdb.
    Input: 
        a) json_IP: A json table containing IXP IPs, IXP short names and IXP IDs.
        b) temp_subnet_Tree: The Subnet Tree containing the IXP subnets from peeringdb.
        c) add_subnet_Tree: The Subnet Tree containing IXP Subnets provided by the user.
        d) reserved_tree: The SubnetTree containing the reserved Subnets.
    Output:
        a) ixp_to_asn: A dictionary with {IXP IP}=[ASN].
        b) dirty_ixp_to_names: A dictionary with {IXP IPs}=['',short names]. It is about "dirty" IXP IP addresses.
        c) dirty_ixp2asn: A dictionary with {IXP IP}=[ASN]. It is about "dirty" IXP IP addresses.
    '''
    def extract_ip(self,json_ip,temp_subnet_tree,add_subnet_tree,reserved_tree):
        handler=string_handler.string_handler()
        ixp_to_asn={}
        dirty_ixp_to_names={}
        dirty_ixp2asn={}
        dumped_ixps=[]
        for node in json_ip:
            if node['ipaddr4'] is None:
                temp=''
            else:
                temp=node['ipaddr4']
            ips=handler.extract_ip(temp,'IP')

            for ixpip in ips:
                if handler.is_valid_ip_address(ixpip,'IP'):
                    ixid='no_id'

                    # the ix id for the ip must be the same with the prefix's one
                    # in which the ip belongs.
                    if ixpip in temp_subnet_tree:
                        ixid=temp_subnet_tree[ixpip]

                    # if the prefix ix id is the same with the ip ix id or the ip is given by the user,
                    # add the ip.
                    if ((ixid != 'no_id' and ixid == node['ix_id'])  and ixpip not in ixp_to_asn.keys() and ixpip not in dumped_ixps and ixpip not in reserved_tree)or ixpip in add_subnet_tree:
                        ixp_to_asn[ixpip]=[str(node['asn'])]
                    elif ixpip in ixp_to_asn.keys():
                        if ixp_to_asn[ixpip]!= [str(node['asn'])]:
                            dumped_ixps.append(ixpip)
                            ixp_to_asn.pop(ixpip,None)
                    # else consider the IP as dirty.
                    elif ixpip not in dumped_ixps:
                        dirty_ixp2asn[ixpip]=[str(node['asn'])]
                        dirty_ixp_to_names[ixpip]=['',node['name']]

        return (ixp_to_asn,dirty_ixp_to_names,dirty_ixp2asn)