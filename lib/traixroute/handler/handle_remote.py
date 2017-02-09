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

import os


class handle_remote():
    '''
    This class imports the remote peering dataset.
    '''

    def __init__(self, homepath, libpath):
        # <absolute path>/traixroute/
        self.directory = libpath + '/database/RemotePeering'
        self.homedir = homepath + '/database/RemotePeering'
        # The filename containing the total infomation concerning the remote
        # peering interfaces.
        self.rp_dataset_json = 'remote_peering.json'

    def extract_rp_per_ixp(self, files, json_handle):
        '''
        Organises the available remote peering information in a dictionary data structure.
        Input:
            a) files: A list of .json files containing remote peering information for the available IXPs.
            b) json_handle: Instance of the handle_json class to manipulate .json files.
        Output:
            a) rp_dataset: A dictionary {IP}={IXP short name: {IXP Country, IXP City}} containing remote peering related information.
        '''

        rp_dataset = {}

        for json_file in files:
            data = json_handle.import_IXP_dict(
                self.directory + '/' + json_file)[0]
            for entry in data[3]:
                rp_dataset.setdefault(entry["ip"], {}).update(
                    {str((data[0], data[1], data[2])): entry})

        return rp_dataset

    def handle_import(self, json_handle):
        '''
        Imports the remote peeing .json dabaset to the database. Otherwise, it lists the available remote peering datasets for each IXP to finally construct an aggregated dataset.
        Input:
            a) json_handle: Instance of the handle_json class to manipulate .json files.
        Output:
            a) rp_database: A dictionary {IP}={IXP short name: {IXP Country, IXP City}} containing remote peering related information.
        '''

        if os.path.exists(self.homedir + '/' + self.rp_dataset_json):
            return json_handle.import_IXP_dict(self.homedir + '/' + self.rp_dataset_json)[0]
        else:
            libfiles = [file for file in os.listdir(
                self.directory) if file.endswith(".json")]

            rp_database = self.extract_rp_per_ixp(libfiles, json_handle)

            if not os.path.exists(self.homedir):
                os.makedirs(self.homedir)

            json_handle.export_IXP_dict(
                rp_database, self.homedir + '/' + self.rp_dataset_json)
            return rp_database
