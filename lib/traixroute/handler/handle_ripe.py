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

from ripe.atlas.cousteau import AtlasResultsRequest, Traceroute, AtlasSource, AtlasCreateRequest
from ripe.atlas.sagan import Result, TracerouteResult
from datetime import datetime
import sys


class handle_ripe():
    '''
    Handles the RIPE Atlas measurements. Fetches and creates measurements requested by the user to detect IXP crossing links.
    '''

    def __init__(self, config):

        # The ripe authentication key.
        self.ripe_key = config['ripe_auth_key']

    def get_measurement(self, kwargs):
        '''
        Downloads the requested ripe measurement and returns the results.
        Input:
            a) kwargs: A dict containing the keys required as defined by ripe.cousteau. Supported keys are "mesm_id","start","stop" and "probe_ids".
        Output:
            a) results: A list containing the traceroutes as returned by ripe.atlas.cousteau.
        '''

        kwargs['key'] = self.ripe_key
        is_success, results = AtlasResultsRequest(**kwargs).create()

        if(is_success):
            if (len(results)):
                if(results[0]['type'] == 'traceroute' and results[0]['af'] == 4):
                    return results
                else:
                    print(
                        'TraIXroute only supports Traceroute and IPv4 measurements. Exiting.')
            else:
                print('Empty measurement returned. Exiting.')
        else:
            print('Ripe measurement not found. Exiting.')
            print(
                'Check also your RIPE Atlas authentication key in \'config\' file in \"ripe_auth_key\".')
        sys.exit(0)

    def create_measurement(self, kwargs):
        '''
        Creates the request for a measurement to ripe.
        Input:
            a) kwargs: The user input arguments in a dictionary.
        Output:
            a) response: The response from ripe. 
        '''

        default_defs = {
            'target': 'www.inspire.edu.gr',
            'type': 'traceroute',
            'protocol': 'ICMP',
            'resolve_on_probe': True,
            'af': 4,
            'description': 'traIXroute (IPv4)'
        }

        default_probes = {
            'type': 'probes',
            'value': '23385',
            'requested': 1
        }

        default_defs.update(kwargs[0].items())
        default_probes.update(kwargs[1].items())

        if(default_defs['type'] != 'traceroute' or default_defs['af'] != 4):
            print('TraIXroute only supports Traceroute and IPv4 measurements. Exiting.')

        traceroute = Traceroute(** default_defs)
        source = AtlasSource(** default_probes)

        atlas_request = AtlasCreateRequest(
            start_time=datetime.utcnow(),
            key=self.ripe_key,
            measurements=[traceroute],
            sources=[source],
            is_oneoff=True
        )

        (is_success, response) = atlas_request.create()

        if(is_success):
            print('Please wait for ripe to complete the measurements and run traIXroute again with: ripe -r \'{\"msm_id\":' + str(
                response['measurements'][0]) + '}\'')
        else:
            print('Please revise the arguments you have given. Ripe does not accept these arguments or it may be unavailable at this time.')
        sys.exit(0)

    def return_path(self, result):
        '''
        Returns the ith ip path from a ripe measurement.
        Input:
            a) result: Dictionary containing the ith traceroute.
        Output:
            a) src_ip: A string with the source IP address.
            b) dst_ip: A string with the destination IP address.
            c) ip_path: A list containing the IPs of the traceroute path.
            d) delays: A list containing the delays of the traceroute path.
        '''

        trace_res = TracerouteResult(result)
        all_replies = trace_res.hops
        src_ip = result['from']
        ip_path = []
        delays = []
        dst_ip = '*'

        if 'error' not in result['result'][0]:
            dst_ip = trace_res.destination_address
            for node in all_replies:
                packet = node.packets
                if node.index != 255:
                    [ip, delay] = self.choose_ip(packet)
                    ip_path.append(ip)
                    delays.append(delay)

        return (src_ip, dst_ip, ip_path, delays)

    def choose_ip(self, packet):
        '''
        Returns the first valid IP reply for a given traceroute hop.
        Input: 
            a) packet: A Hop class containing the packets for the certain hop.
        Output:
            a) ip: The first valid ip from the list of IPs for a certain hop.
            b) delay: The relative rtt value of the selected IP.
        '''

        for pkt in packet:
            ip = pkt.origin
            delay = str(pkt.rtt)

            if ip is not None:
                return ip, delay + ' ms'
        return '*', ''
