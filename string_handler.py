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

import re,socket,difflib

'''
This modules handles the strings.
'''

class string_handler():

    '''
    Determines if the given string is in valid IP/Subnet form.
    Input: 
        a) address: The IP address
        b) kind: IP for ip address or Subnet for prefix.
    Output:
        TRUE if the form is valid, FALSE otherwise.
    '''
    def is_valid_ip_address(self,address,kind):
        if address is None:
            return False
        if address=='':
            return False

        # For IP handling.
        splitted=address.split('.')
        if len(splitted)>3 and kind=='IP':
            for node in splitted:
                try:
                    if int(node)>255 or int(node)<0:
                        return False
                except:
                    return False
            if splitted[-1]!='0' and splitted[-1]!='255':
                return True 

        # For Subnet Handling.
        elif len(splitted)>3 and kind=='Subnet' and len(address.split('/'))>1:
            splitted2=address.split('/')
            splitted=splitted2[0].split('.')
            for node in splitted:
                try:
                    if int(node)>255 or int(node)<0:
                        return False
                except:
                    return False            
            try:
                if int(address.split('/')[1])<33:
                    return True
            except:
                pass
        return False


    '''
    Extracts an IP or a Subnet from a string using regular expressions.
    Input: 
        a) string: a string with an IP address or Subnets.
        b) kind: IP for ip address or Subnet for prefix.
    Output: 
        a) a list of IPs, or Subnets extracted from the struct.
    '''
    def extract_ip(self,string,kind):

        if kind=='Subnet':
            ip=re.findall( r'[0-9]+(?:\.[0-9]+){3}/[0-9]+', string )
        elif kind=='IP':
            ip=re.findall( r'[0-9]+(?:\.[0-9]+){3}', string )
        else:
            print('Wrong argument type!')
        return ip


    '''
    Removes unwanted characters from a string.
    Input: 
        a) string: the string to clean.
    Output:
        a) string: the "clean" string.
    '''
    def string_removal(self,string):
        if string is None:
            string='None'
        elif 'NULL' in string:
            string='None'
        else:
            string=string.replace(' ','')
            string=string.replace('\t','')
            string=string.lower()
            string=string.replace('-','')
            string=string.replace('/','')
            string=string.replace(';','')
            string=string.replace('\\','')
            string=string.replace('\'','')
            string=string.replace('\"','')
            string=string.replace(',','')
        return (string)


    '''
    A function which compares the similarity of two strings.
    This function has been configured with a similarity factor (true_ratio) equals to 0.9
    Input: 
        a) string1, string2: The two strings to be compared.
    Ouput:
        TRUE if the strings are similar, FALSE otherwise.
    '''
    def string_comparison(self,string1,string2):
        string1=self.string_removal(string1)
        string2=self.string_removal(string2)
        true_ratio= difflib.SequenceMatcher(None,string1,string2).ratio()
        if string1=='' or string2=='':
            return False
        if true_ratio>0.9:
            return True
        else:
            return False
    

    '''
    This function cleans an IP or a Prefix. 
    E.g. from an IP address 192.08.010.1 we get 192.8.10.1
    Input:
        a) IP: The IP or subnet to be cleaned.
        b) kind: IP or Subnet for prefix.
    Output:
        a) final: The "clean" IP address.
    '''
    def clean_ip(self,IP,kind):
        temp=IP
        if kind=='Subnet':
            splitted=IP.split('/')
            if len(splitted)>1:
                temp=IP.split('/')[0]
            else:
                return ''
        temp=temp.split('.')
        final=''
        for node in temp:
            part=''
            i=-1
            for i in range(0,len(node)-1):
                if node[i]!='0':
                    part=part+node[i]
                    break
            for j in range(i+1,len(node)):
                part=part+node[j]
            if len(node)==1:
                part=node[0]
            final=final+part+'.'
        if final[-1]=='.':
            final=final[:-1]
        if kind=='Subnet':
            final=final+'/'+splitted[1]
        return(final)


    '''
    Check the format of an IP address.
    Input:
        a) IP: The IP to check.
    Ouput: 
    TRUE if the IP has a valid form, FALSE otherwise.
    '''
    def check_input_ip(self,IP):
        temp=IP.split('.')
        if len(temp)>4:
            return False
        for node in temp:
            if len(node)>1 and node[0]=='0':
                return False
        return True
