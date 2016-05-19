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

import string_handler

'''
This class is responsible for handling dictionaries like IXP Prefixes-to-IXP Names and IXP IPs-to-IXP Names.
'''
class dict_merger(): 
    
    '''
    Returns a dictionary C containing the union of the dictionaries A and B. 
    The input dictionaries contain key-to-IXP long, short name entries. The key values can be either IXP Prefix or IP.
    E.g.: if A[id1]=[a,b], B[id1]=[c,d] then C[id1]=[a,b], if a is similar to c and b is similar to d. [a,b] are the valid IXP long and short names for the IXP subnet.
    Input:
        a) d1,d2: The two dictionaries to be merged.
    Output:
        a) d3: The output dictionary after merging. 
    '''
    def merge_keys2names(self,d1,d2):
        d3={}
        for k in d1.keys():
            if k in d2.keys():
                mytuple=self.assign_names(d1[k][1],d2[k][1],d1[k][0],d2[k][0])
                if mytuple!=[]:
                    d3[k]=mytuple
            elif k not in d3.keys():
                d3[k]=d1[k]
            elif d3[k]==['',''] or d3==['']:
                d3=d1[k]
        for k in d2.keys():
            if k not in d1.keys():
                d3[k]=d2[k]

        return (d3)


    '''
    Takes as inputs the short and long IXP names retrieved by PCH and PeeringDB assigned to a certain prefix and
    decides which of the two short and long IXP names to keep.
    Input:
        a) sname1,sname2: The short names assigned to an IXP Prefix (from pch and peeringDB).
        b) lname1,lname2: The long names assigned to an IXP Prefix (from pch and peeringDB).
    Output:
        a) d3: The output list after merging.
    '''
    def assign_names(self,sname1,sname2,lname1,lname2):
        string_handle=string_handler.string_handler()
        d3=[]
        if string_handle.string_comparison(lname1,lname2):
            d3.append(lname1)
        elif lname1=='' and lname2!='' :
            d3.append(lname2)

        elif lname1!='' and lname2=='':
            d3.append(lname1)
        else:
            d3.append('')

        if string_handle.string_comparison(sname1,sname2):
            d3.append(sname1)
        elif sname1=='' and sname2!='':
            d3.append(sname2)
        elif sname1!='' and sname2=='':
            d3.append(sname1)
        else:
            d3.append('')

        return d3


    '''
    This function merges two {IP}=[ASN] dictionaries and returns a merged dictionary.
    Input:
        a) d1,d2: The two dictionaries to be merged.
        b) Subnet_tree: The Subnet tree that contains the IXP subnets.
        c) flag: A flag that specifies the need to search for dirty IXPs or not.
    Output: 
        a) d3: The output dictionary after merging.
        b) dirty: The dictionary {IP}=[ASN] containing the IXP IPs that no longer correspond to an IXP prefix in the Subnet_tree.
    '''
    def merge_ixp2asns(self,d1,d2,flag,Subnet_tree):        
        d3={}
        dirty={}
        for k in d1.keys():
            if k not in Subnet_tree and flag:
                dirty[k]=d1[k]
            elif k in d2.keys() and (k not in d3.keys()):

                if d1[k][0]==d2[k][0]:
                    d3[k]=[]
                    d3[k].append(d1[k][0])
                elif d1[k][0]=='' and d2[k][0]!='':
                    d3[k]=[]
                    d3[k].append(d2[k][0])
                elif d1[k][0]!='' and d2[k][0]=='':
                    d3[k]=[]
                    d3[k].append(d1[k][0])
            elif k not in d3.keys():
                if d1[k][0]!='':
                    d3[k]=d1[k]
        for k in d2.keys():
            if k not in Subnet_tree and flag:
                dirty[k]=d1[k]
            elif k not in d3.keys():
                if d2[k][0]!='':
                    d3[k]=d2[k] 
        if flag:
            return d3,dirty
        else:
            return d3 


    '''
    Returns a dictionary C containing the intersection of A and B.
    E.g.: if A[id1]=[a], B[id1]=[b] then C[id1]=[a,b].
    If an id is not a key in both A and B then it will not be a key in C too.
    Input:
        a) d1,d2: The two dictionaries from which the inner join is selected.
    Output:
        a) d3: The Intersection of the two dictionaries.
    '''
    def inner_join(self,d1,d2):
        d3 = { k : d1[k] + d2[k] for k in d1.keys() if k in d2.keys() }
        return d3