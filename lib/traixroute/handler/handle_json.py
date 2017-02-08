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

import ujson
import os
import SubnetTree
import sys


class handle_json():
    '''
    Handles the json files and all the actions related with the json files.
    '''

    def export_IXP_dict(self, IXP_dict, filename):
        '''
        Exports a dict in a file in json format.
        Input:
            a) IXP_dict: A candidate dictionary to be exported in a .json file.
            b) filename: The output file name to dump the dictionary.
        '''

        with open(filename, 'w') as fp:
            ujson.dump(IXP_dict, fp)

    def import_IXP_dict(self, filename):
        '''
        Imports a .json file.
        Input:
            a) filename: The .json file to read.
        Output:
            a) data: The data imported from the json file.
            b) flag: True if the data have not been exported, False otherwise.
        '''

        flag = False
        data = {}
        try:
            with open(filename, 'r') as fp:
                data = ujson.load(fp)
        except:
            print(filename, 'not found.')
            flag = True
        return data, flag

    def export_trace_from_file(self, trace):
        '''
        Exports the traces from an input json-based file to a new file, in json format too. As input example, see Examples/test_traceroute_paths.json
        Input:
            a) trace: The input traceroute paths.
        Output:
            a) current_trace: A list [IP1,IP2,...IPN].
            b) current_info: A list [string1, string2,...stringN] with info for each IP respectively.
            c) trace_dst: A string with the traceroute's destination. The destination might be either IP or url.
            d) trace_src: A string with the traceroute's source. The source might be either IP or url.
            e) trace_info: A string with information related to the current traceroute path.
        '''

        flag = False
        current_trace = []
        current_info = []
        trace_src = '-'
        trace_dst = '-'
        info = ''
        trace_info = ''
        try:
            trace_id = trace['id']
            trace_dst = trace['dst']
            trace_src = trace['src']
            if('info' in trace.keys()):
                trace_info = trace['info']
            path_to_parse = trace['result']
            len_path = len(path_to_parse)
        except:
            print('Wrong json format. Exiting.')
            print(trace)
            os._exit(0)

        tmp_list = []
        for hop_to_parse in path_to_parse:
            hop = int(hop_to_parse.replace('hop', ''))
            tmp_list.append((hop, path_to_parse[hop_to_parse]))

        tmp_list.sort(key=lambda tup: tup[0])

        if not tmp_list:
            return current_trace, current_info, trace_dst, trace_src, trace_info

        for i in range(0, tmp_list[-1][0] + 1):
            hop = [item[1] for item in tmp_list if i == item[0]]
            try:
                flag = False
                if len(hop) > 0:
                    try:
                        hop_to_parse = hop[0]
                        flag = True
                    except:
                        print('Wrong format, hop: ' +
                              str(i + 1) + '. Exiting.')
                        print(trace)
                        os._exit(0)
                else:
                    print('Expected at least one hop in ' +
                          str(i + 1) + ' in ' + trace + '. Hop is ignored.')
                    IP = '*'
                    info = ' '
            except:
                IP = '*'
                info = ''

            if flag:
                try:
                    IP = hop_to_parse['from']
                    if('info' in hop_to_parse.keys()):
                        info = str(hop_to_parse['info'])
                except:
                    print('Wrong format, hop: ' + str(i + 1) + '. Exiting.')
                    print(trace)
                    os._exit(0)
            current_trace.append(IP)
            current_info.append(info)

        return current_trace, current_info, trace_dst, trace_src, trace_info

    def export_trace_from_ripe_file(self, trace):
        '''
        Exports the traces from an input ripe-json-based file to a new file, in json format too. As input example, see Examples/test_traceroute_paths_from_ripe.json
        Input:
            a) trace: The input traceroute paths.
        Output:
            a) current_trace: A list [IP1,IP2,...IPN].
            b) current_info: A list [string1, string2,...stringN] with info for each IP respectively.
            c) trace_dst: A string with the traceroute's destination. The destination might be either IP or url.
            d) trace_src: A string with the traceroute's source. The source might be either IP or url.
            e) trace_info: A string with information related to the current traceroute path.
        '''

        if(trace['af'] != 4 or trace['type'] != 'traceroute'):
            print('TraIXroute only supports Traceroute and IPv4 measurements. Exiting.')
            os._exit(0)

        current_trace = []
        current_info = []
        trace_src = '-'
        trace_dst = '-'
        info = ''
        trace_info = ''
        try:
            trace_id = trace['msm_id']
            trace_dst = trace['dst_addr']
            trace_src = trace['from']
            if('msm_name' in trace.keys()):
                trace_info = trace['msm_name']
            path_to_parse = trace['result']
            len_path = len(path_to_parse)
        except:
            print('Wrong json format. Exiting.')
            print(trace)
            os._exit(0)

        # Select the first IP from the list and set as info the rtt.
        for hop in trace['result']:
            if hop['hop'] != 255:
                if 'from' in hop['result'][0]:
                    current_trace.append(hop['result'][0]['from'])
                    current_info.append(str(hop['result'][0]['rtt']) + ' ms')
                else:
                    current_trace.append('*')
                    current_info.append('')

        return current_trace, current_info, trace_dst, trace_src, trace_info
