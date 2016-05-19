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

import handle_pdb,handle_pch,handle_complementary,dict_merger,traIXroute_output

'''
Handles all the methods responsible for extracting info from the databases.
Returns the total information needed for resolving the path.
'''

class database():

    ''' 
    Handles all the methods to extract information from the databases.
    Input:
        a) filename_subset: The ixp_subnets.csv file from pch.
        b) filename_excha: The ixp_exchange.csv file from pch
        c) filename_ixp_membership: The ixp_membership.csv file from pch. 
        d) filename_peer_name: The ix.json file from peeringdb.
        e) filename_peer_ip: The netixlan.json file from peeringdb.
        f) filaname_peer_pfx: The ixpfx.json file from peeringdb.
        g) filename_peer_ixlan: The ixlan.json file from peeringdb.
        h) route_filename: The routeviews Subnet-to-ASN file.
        i) reserved_names: The reservedIPs.txt file.
        j) usr_ixps: The additional_info.txt file.
        k) merge_flag: Flag to export the merged IXP IPs and IXP subnets to files.
        l) mypath: The directory path of the traIXroute folder.
    Output:
        a) final_ixp2asn: A dictionary with {IXP IP}=[ASN].
        b) final_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name].
        c) reserved_sub_tree: A Subnet Tree with the reserved Subnets.
        d) ASn_memb: A dictionary with {ASN}=[list of IXP names].
        e) final_ip2name: A dictionary with {IXP IP}=[Name]. It is about dirty and user IXP IP addresses.
        f) asn_routeviews: A Subnet Tree with Subnet-to-AS from routeviews.
        g) Subnet_tree: A Subnet Tree containing the IXP Subnets.
        h) dirty_ixp2asn: A dictionary with {IXP IP}=[ASN]. It is about dirty IXP IPs that do not belong to a known IXP Subnet.
        i) additional_info_tree: A Subnet Tree containing all the IXP subnets provided by the user.
    '''
    def dbextract(self,filename_subset,filename_excha,filename_ixp_membership,filename_peer_name,filename_peer_ip,filename_peer_pfx,filename_peer_ixlan,route_filename,user_ixps,merge_flag,mypath):
        
        # Calls the function responsible for importing additional information provided by the user.
        mypath=mypath+'/database/'
        user_imports=handle_complementary.extract_additional_info()
        [additional_ip2asn,additional_ip2name,additional_subnet2name,additional_info_tree]=user_imports.extract_additional_info(user_ixps)

        # Imports the reserved IPs.
        reserved=handle_complementary.reserved_handle()
        [reserved_sub_tree,lenreserved]=reserved.reserved_extract()

        # Calls the class responsible for handling the dataset from peeringdb. 
        peeringdb=handle_pdb.peering_handle()
        [peering_subnet2name,peering_ip2asn,peering_ixp2name,dirty_ixp2asn]=peeringdb.peering_handle(filename_peer_name,filename_peer_ip,filename_peer_pfx,filename_peer_ixlan,additional_info_tree,mypath,reserved_sub_tree)

        # Calls the class responsible for handling the dataset from pch.
        pch=handle_pch.pch_handle()
        [pch_subnet2names,pch_ixp2asn,dirty_pch]=pch.pch_handle_main(filename_ixp_membership,filename_subset,filename_excha,mypath,reserved_sub_tree)
            
        # Merges the dictionaries from pch, peeringdb and the additional_info file.
        dict_merge=dict_merger.dict_merger()
        merged_sub2name=dict_merge.merge_keys2names(pch_subnet2names,peering_subnet2name)
        final_sub2name=dict_merge.merge_keys2names(additional_subnet2name,merged_sub2name)

        # Creates final datasets after merging PeeringDB, Packet Clearing House and 
        # additional information provided by the user.
        Sub_hand=handle_complementary.Subnet_handle() 
        Subnet_tree=Sub_hand.Subnet_tree(final_sub2name)
        merged_subtree=Sub_hand.Subnet_tree(merged_sub2name)
        
        [merged_ixp2asn,dirty_merged]=dict_merge.merge_ixp2asns(pch_ixp2asn,peering_ip2asn,True,Subnet_tree)
        final_ixp2asn=dict_merge.merge_ixp2asns(additional_ip2asn,merged_ixp2asn,False,Subnet_tree)
        dirty_ixp2asn=dict_merge.merge_ixp2asns(dirty_ixp2asn,dirty_merged,False,Subnet_tree)
        dirty_ixp2asn=dict_merge.merge_ixp2asns(dirty_ixp2asn,dirty_pch,False,Subnet_tree)
         
        final_ip2name=dict_merge.merge_keys2names(additional_ip2name,peering_ixp2name)
        
        # Creates an ASN-to-IXP names dictionary.
        asn_hand_info=handle_complementary.asn_memb_info()
        ASn_memb=asn_hand_info.asn_memb(final_ixp2asn,final_ip2name,Subnet_tree,final_sub2name,dirty_ixp2asn)

        # Extracts the ASNs from routeviews file
        asn_hand=handle_complementary.asn_handle()
        asn_routeviews=asn_hand.routeviews_extract(route_filename,mypath)
        

        output=traIXroute_output.traIXroute_output()
        output.print_db_stats(peering_ip2asn,peering_subnet2name,pch_ixp2asn,pch_subnet2names,final_ixp2asn,final_sub2name,dirty_ixp2asn,additional_ip2asn,additional_subnet2name,lenreserved)  
        if merge_flag:
            self.subs_to_file(additional_subnet2name,merged_sub2name,'ixp_prefixes.txt')
            self.ips_to_file(additional_ip2asn,final_ip2name,dirty_ixp2asn,merged_subtree,merged_ixp2asn, merged_sub2name ,'ixp_membership.txt')
        
        return [final_ixp2asn,final_sub2name,reserved_sub_tree,ASn_memb,final_ip2name,asn_routeviews,Subnet_tree,dirty_ixp2asn,additional_info_tree]
 

    '''
    Prints the IXP subnets with their corresponding IXP names to the ixp_prefixes.txt file.
    Input:
        a) d1: The dictionary with the IXP subnets-to-IXP names from the additional_info.txt file.
        b) d2: The dictionary with the IXP subnets-to-IXP names from the database (after merging pch and peeringdb).
        c) filename: The ixp_prefixes.txt file name.
    '''
    def subs_to_file (self,d1,d2,filename):
        filename=open('database/'+filename,'w')
        output=''
        number=0
        for key in d1.keys():
            output=output+str(number)+'\t'+'+'+'\t'+key
            for node in d1[key]:
                output=output+'\t'+node
            output=output+'\n'
            number=number+1
        for key in d2.keys():
            output=output+str(number)+'\t'+key
            for node in d2[key]:
                output=output+'\t'+node
            output=output+'\n'
            number=number+1
        filename.write(output)
        filename.close()
 

    '''
    Prints all the IXP IP-ASN-IXP long name-IXP short name entries to the ixp_membership.txt file.
    Input:
        additional_ip2name: The dictionary with IXP IP-to-IXP long, short names from the user.
        dirty_ixp2asn: The dictionary with IXP IP-to-ASN from pch and peeringdb. It is about dirty IXP IP addresses.
        Subnet_tree: A subnet tree containing IXP prefixes.
        merged_ixp2asn: The merged dictionary with IXP IP-to-ASN from peeringdb and pch.
        sub2names: The dictionary with {Subnet}=[IXP long name, IXP short name].
        filename: The output file name.
    '''
    def ips_to_file(self,additional_ip2asn,additional_ip2name,dirty_ixp2asn,Subnet_tree,merged_ixp2asn,sub2names, filename):
        filename=open('database/'+filename,'w')
        output=''
        number=0
        for key in additional_ip2asn.keys():
            output=output+str(number)+'\t'+'+'+'\t'+key
            for node in additional_ip2asn[key]:
                output=output+'\t'+node
            for node in additional_ip2name[key]:
                output=output+'\t'+node
            output=output+'\n'
            number=number+1

        for key in dirty_ixp2asn.keys():
            output=output+str(number)+'\t'+'?'+'\t'+key
            for node in dirty_ixp2asn[key]:
                output=output+'\t'+node
            if key in additional_ip2name:
                for node in additional_ip2name[key]:
                    output=output+'\t'+node
            output=output+'\n'
            number=number+1

        for key in merged_ixp2asn.keys():
            if key in Subnet_tree:
                output=output+str(number)+'\t'+key
            else:
                output=output+str(number)+'\t'+'?'+'\t'+key
            for node in merged_ixp2asn[key]:
                output=output+'\t'+node
            if key in Subnet_tree:
                subnet=Subnet_tree[key]
                for node in sub2names[subnet]:
                    output=output+'\t'+node
            output=output+'\n'
            number=number+1

        filename.write(output)
        filename.close()