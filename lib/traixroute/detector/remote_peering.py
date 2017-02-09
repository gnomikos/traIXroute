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


class remote_peering():
    '''
    This class is responsible for detecting Remote IXP crossing links in IP paths.
    '''

    def __init__(self):
        # Maps remote peering rules to remote peer position in the hop window.
        self.rules = {}
        # Maps IXP detection rule indexes from rules.txt to number of hop in
        # the hop window.
        self.indexes = {}
        # Initializes the remote peering detection rules.
        self.set_rules()
        # The database containing all the remote peering information.
        self.rp_database = None
        # A temporary index used for remote peering detection for each hop
        # window in a candidate IP path.
        self.temp_index = None

    def set_rules(self):
        '''
        Specifies the remote peering detection rules and which hops have to be checked in a hop window to infer
        the IXP crossing link.
        '''

        self.rules['AS_M0-(IXP_IPandAS_M1)-AS_M1'] = 0

    def check_rule(self, rule, index):
        '''
        Checks if a remote peering detection rule also exists in the IXP detection rule list and then asocciates 
        which hop of the hop window has to be checked for IXP crossing based on the remote peering link.
        Input:
            a) rule: Candidate rule.
            b) index: Index of IXP detection rule in the total list of IXP detection rules.
        '''

        rule = '-'.join(rule)
        if rule in self.rules:
            self.indexes[index] = self.rules[rule]

    def rule_hit(self, index):
        '''
        Checks if the satisfied IXP detection rule also exists in the remote peering detection rules.
        Input:
            a) index: The index of the satisfied IXP detection rule in the total list with the IXP detection rules.
        Output:
            a) True in case of a remote peering detection rule is satisfied, otherwise False.
        '''

        return True if index in self.indexes else False

    def find_and_print(self, ips, asm_a):
        '''
        Checks if all the requirements are satisfied to infer the IXP crossing link based on remote peering connectivity
        and returns all the remote peering related information.
        Input:
            a) ips: The candidate hop window in the IP path.
            b) asm_a: The detected IXP crossing link.
        Output:
            a) entries[entry]: Information about the remote peering IXP crossing link, otherwise, it returns None.
        '''

        if ips[self.indexes[self.temp_index]] in self.rp_database:

            asm_a = asm_a.split('(')
            ixp = asm_a[0].rstrip().lower()
            country = asm_a[1].split(',')[0].lower()
            city = asm_a[1].split(',')[1].rstrip(')').lower()

            entries = self.rp_database[ips[self.indexes[self.temp_index]]]
            for entry in entries:
                tuple_entry = eval(entry)

                if((tuple_entry[0].lower() in ixp or ixp in tuple_entry[0].lower()) and tuple_entry[1].lower() in country and tuple_entry[2].lower() in city):
                    return entries[entry]

        return None
