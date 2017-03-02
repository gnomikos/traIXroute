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

from traixroute.handler import handle_json, handle_pch, handle_pdb, handle_ripe, dict_merger, handle_complementary, handle_remote
from traixroute.controller import traixroute_output, traixroute_parser
from os import remove, makedirs
from os.path import exists
import SubnetTree
import concurrent.futures
import sys


class database():
    '''
    Handles all the methods responsible for building the database.
    Returns the total information needed for resolving a traceroute path.
    '''

    def __init__(self, traixroute_parser, downloader, config, outcome, libpath):
        '''
        The initialization of the tool.
        Inputs: 
            a) traixroute_parser: A dictionary that contains the user input flags.
            b) downloader: Instance of the Downloader class to download all the datasets.
            c) config: A dictionary that contains the total configurations based on the config file. 
            d) outcome: True if the files have been updated successfully, False otherwise.
            e) libpath: The absolute path to the library folder.
        '''

        # self.final_ixp2asn: A dictionary with {IXP IP}=[ASN].
        self.final_ixp2asn = None
        # self.final_sub2name: A dictionary with {Subnet}=[IXP long name, IXP
        # short name].
        self.final_sub2name = None
        # self.reserved_sub_tree: A Subnet Tree with {reserved subnet}=reserved
        # subnet.
        self.reserved_sub_tree = None
        # self.asn_memb: A dictionary with {ASN}=[list of IXP names].
        self.asnmemb = None
        # self.asn_routeviews: A Subnet Tree with {Subnet}=[ASN1, ASN2,...]
        # from routeviews.
        self.asn_routeviews = None
        # self.subTree: A Subnet Tree with {Subnet}=[IXP long name, IXP short
        # name].
        self.subTree = None
        # self.cc_tree: A Subnet Tree with {Subnet}=[Contry, City].
        self.cc_tree = None

        # self.remote_peering: A dictionary {IP}={IXP short name: {IXP Country,
        # IXP City}} containing remote peering related information.
        self.remote_peering = None

        # self.merge_flag: Flag to export the merged IXP IPs and IXP subnets to
        # files.
        self.merge_flag = traixroute_parser.flags['merge']
        # self.update: Flag to update the database.
        self.update = traixroute_parser.flags['update']
        # self.print_db: Flag to output the db stats.
        self.print_db = traixroute_parser.flags['db']

        # self.reserved_names: The reservedIPs.txt file.
        self.reserved_names = 'reservedIPs.txt'
        # self.config: Contains the config file dictionary.
        self.config = config
        # self.mypath: The directory path of the traIXroute folder.
        self.outcome = outcome

        self.downloader = downloader

        self.homepath = downloader.getDestinationPath()
        self.libpath = libpath

    def dbextract(self):
        ''' 
        Handles all the methods to extract information from the databases.
        '''

        json_handle = handle_json.handle_json()
        output = traixroute_output.traixroute_output()
        lst_modified = output.read_lst_mod(
            self.homepath + '/lst_mod.txt',
            self.homepath + '/configuration/additional_info.txt')

        try:
            with open(self.homepath + '/configuration/check_update.txt', 'r') as f:
                chk_update = f.readline()
        except:
            chk_update = False

        # Imports the reserved IPs.
        reserved = handle_complementary.reserved_handle()
        reserved.reserved_extract()

        self.reserved_sub_tree = reserved.reserved_sub_tree
        reserved_list = reserved.reserved_list
        lenreserved = reserved.lenreserved

        # Extracts the ASNs from routeviews file
        asn_hand = handle_complementary.asn_handle(
            self.downloader, self.libpath)
        Sub_hand = handle_complementary.Subnet_handle()

        flag = False
        if (lst_modified and not chk_update and not self.merge_flag) or not self.outcome:
            print("Loading from Database.")
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["num_of_cores"]) as executor:
                results.append(executor.submit(
                    json_handle.import_IXP_dict, self.homepath + '/database/Merged/IXPIP2ASN.json'))
                results.append(executor.submit(
                    json_handle.import_IXP_dict, self.homepath + '/database/Merged/trIX_subnet2name.json'))
                results.append(executor.submit(
                    json_handle.import_IXP_dict, self.homepath + '/database/Merged/asn_memb.json'))
                results.append(executor.submit(
                    json_handle.import_IXP_dict, self.homepath + '/database/Merged/sub2country.json'))
                results.append(executor.submit(
                    json_handle.import_IXP_dict, self.homepath + '/database/Merged/routeviews.json'))

            for item in results:
                flag = flag or item.result()[1]

            if not flag:
                self.final_ixp2asn = results[0].result()[0]
                self.final_sub2name = results[1].result()[0]
                self.asnmemb = results[2].result()[0]
                final_subnet2country = results[3].result()[0]
                self.asn_routeviews = self.dict2tree(results[4].result()[0])
                self.subTree = self.dict2tree(self.final_sub2name)
                if self.print_db:
                    output.print_pr_db_stats(self.homepath + '/db.txt')

        if (not lst_modified or flag or chk_update or self.merge_flag) and self.outcome:
            if chk_update or flag:
                print("Loading from PCH, PDB, Routeviews and additional_info.txt.")
                if exists(self.homepath + "/configuration/check_update.txt"):
                    remove(self.homepath + "/configuration/check_update.txt")
            elif not lst_modified:
                print("Loading from database and additional_info.txt.")
            else:
                print("Loading from database.")

            user_imports = handle_complementary.extract_additional_info()
            pch = handle_pch.pch_handle(
                self.downloader, self.libpath)
            peeringdb = handle_pdb.peering_handle(
                self.downloader, self.libpath)
            dict_merge = dict_merger.dict_merger()
            asn_hand_info = handle_complementary.asn_memb_info()

            user_imports.extract_additional_info(self.homepath)
            additional_ip2asn = user_imports.IXP_dict
            additional_subnet2name = user_imports.Subnet
            additional_info_tree = user_imports.additional_info_tree
            additional_info_help_tree = user_imports.additional_info_help_tree
            additional_pfx2cc = user_imports.pfx2cc

            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["num_of_cores"]) as executor:
                results.append(executor.submit(
                    asn_hand.routeviews_extract, self.reserved_sub_tree))
                results.append(executor.submit(peeringdb.peering_handle_main,
                                               additional_info_tree, self.reserved_sub_tree, country2cc))
                results.append(executor.submit(
                    pch.pch_handle_main, self.reserved_sub_tree, additional_info_tree, country2cc))

            self.asn_routeviews = results[0].result()[0]
            routeviews_dict = results[0].result()[1]

            peering_subnet2name = results[1].result()[0]
            peering_ip2asn = results[1].result()[1]
            peering_subnet2country = results[1].result()[2]

            pch_subnet2names = results[2].result()[0]
            pch_ixp2asn = results[2].result()[1]
            pch_subnet2country = results[2].result()[2]

            len_pch_ixp2asn = len(pch_ixp2asn)
            len_peering_ip2asn = len(peering_ip2asn)
            len_pch_subnet2names = len(pch_subnet2names)
            len_peering_subnet2name = len(peering_subnet2name)

            # Merges the dictionaries from pch, peeringdb and the
            # additional_info file.
            final_subnet2country = dict_merge.merge_cc(
                peering_subnet2country, pch_subnet2country)
            merged_sub2name = dict_merge.merge_keys2names(
                pch_subnet2names, peering_subnet2name)

            [self.subTree, self.final_sub2name, help_tree] = Sub_hand.Subnet_tree(
                merged_sub2name, additional_info_help_tree, self.reserved_sub_tree, final_subnet2country)
            [self.subTree, self.final_sub2name] = Sub_hand.exclude_reserved_subpref(
                self.subTree, self.final_sub2name, reserved_list, final_subnet2country)
            [self.subTree, self.final_sub2name, final_subnet2country] = dict_merge.include_additional(
                self.final_sub2name, self.subTree, additional_subnet2name, final_subnet2country, additional_pfx2cc, help_tree)

            [merged_ixp2asn, dirty_count] = dict_merge.merge_ixp2asns(
                pch_ixp2asn, peering_ip2asn, True, self.subTree)

            self.final_ixp2asn = dict_merge.merge_ixp2asns(
                additional_ip2asn, merged_ixp2asn, False, self.subTree, replace=True)
            self.asnmemb = asn_hand_info.asn_memb(
                self.final_ixp2asn, self.subTree)
            if not exists(self.homepath + '/database/Merged'):
                makedirs(self.homepath + '/database/Merged')
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["num_of_cores"]) as executor:
                executor.submit(json_handle.export_IXP_dict,
                                self.asnmemb, self.homepath + '/database/Merged/asn_memb.json')
                executor.submit(json_handle.export_IXP_dict, routeviews_dict,
                                self.homepath + '/database/Merged/routeviews.json')
                executor.submit(json_handle.export_IXP_dict,
                                self.final_ixp2asn, self.homepath + '/database/Merged/IXPIP2ASN.json')
                executor.submit(json_handle.export_IXP_dict, self.final_sub2name,
                                self.homepath + '/database/Merged/trIX_subnet2name.json')
                executor.submit(json_handle.export_IXP_dict, final_subnet2country,
                                self.homepath + '/database/Merged/sub2country.json')

            output.print_db_stats(len_peering_ip2asn, len_peering_subnet2name, len_pch_ixp2asn, len_pch_subnet2names, self.final_ixp2asn,
                                  self.final_sub2name, dirty_count, additional_ip2asn, additional_subnet2name, lenreserved, self.print_db, self.homepath + '/')

        # Adds country and city related information of IXPs
        self.cc_tree = self.dict2tree(final_subnet2country)
        # Imports the remote peering datasets
        self.remote_peering = handle_remote.handle_remote(self.homepath,
                                                          self.libpath).handle_import(json_handle)

        if self.merge_flag:
            self.subs_to_file(additional_subnet2name,
                              merged_sub2name)
            self.ips_to_file(additional_ip2asn, additional_info_tree,
                             merged_ixp2asn)
            print("The files ixp_prefixes.txt and ixp_membership.txt have been created.")

    def dict2tree(self, d1):
        '''
        Takes as input a dictionary with Subnets as keys and converts it to a SubnetTree.
        Input:
            a) d1: The dictionary with Subnets as keys.
        Output:
            a) tree: The SubnetTree.
        '''

        tree = SubnetTree.SubnetTree()

        for node in d1:
            tree[node] = d1[node]
        return tree

    def subs_to_file(self, d1, d2):
        '''
        Prints the IXP subnets with their corresponding IXP names to the ixp_prefixes.txt file.
        Input:
            a) d1: The dictionary with the IXP subnets-to-IXP names from the additional_info.txt file.
            b) d2: The dictionary with the IXP subnets-to-IXP names from the database (after merging pch and peeringdb).
        '''

        filename = open(self.homepath + '/ixp_prefixes.txt', 'w')
        output = ''
        number = 0
        for key in d1.keys():
            output = output + str(number) + ', ' + '+' + ', ' + key
            if key in self.subTree:
                for IXP in self.subTree[key]:
                    output = output + ', ' + IXP[1] + ', ' + IXP[0]
                if key in self.cc_tree:
                    output = output + ', ' + \
                        self.cc_tree[key][1] + ', ' + self.cc_tree[key][0]
                output = output + '\n'
                number = number + 1
        for key in d2.keys():

            if key not in d1.keys():
                if key in self.subTree:
                    if len(self.subTree[key]) > 1:
                        output = output + str(number) + ', ' + '?' + ', ' + key
                    else:
                        output = output + str(number) + ', ' + '!' + ', ' + key
                    for IXP in self.subTree[key]:
                        output = output + ', ' + IXP[1] + ', ' + IXP[0]
                    if key in self.cc_tree:
                        output = output + ', ' + \
                            self.cc_tree[key][0] + ', ' + self.cc_tree[key][1]

                output = output + '\n'
                number = number + 1
        filename.write(output)
        filename.close()

    def ips_to_file(self, additional_ip2asn, additional_ip2name, merged_ixp2asn):
        '''
        Prints all the IXP IP-ASN-IXP long name-IXP short name entries to the ixp_membership.txt file.
        Input:
            a) additional_ip2asn: additional_ip2name: The dictionary with {IXP IP}=[ASN] specified by the user.
            b) additional_ip2name: The dictionary with {IXP IP}=[IXP long name,IXP short name] specified by the user.
            c) merged_ixp2asn: The merged dictionary with IXP IP-to-ASN from peeringdb and pch.
        '''

        filename = open(self.homepath + '/ixp_membership.txt', 'w')
        output = ''
        number = 0
        add_keys = additional_ip2asn.keys()
        for key in add_keys:
            if key in self.subTree:
                output = output + str(number) + ', ' + '+' + ', ' + key
                for node in additional_ip2asn[key]:
                    output = output + ', AS' + node
                for IXP in self.subTree[key]:
                    output = output + ', ' + IXP[1] + ', ' + IXP[0]
                if key in self.cc_tree:
                    output = output + ', ' + \
                        self.cc_tree[key][1] + ', ' + self.cc_tree[key][0]
                output = output + '\n'
                number = number + 1

        merged_keys = merged_ixp2asn.keys()

        for key in merged_keys:
            if key not in add_keys and key in self.subTree:
                if len(self.subTree[key]) > 1:
                    output = output + str(number) + ', ' + '?' + ', ' + key
                else:
                    output = output + str(number) + ', ' + '!' + ', ' + key
                for node in merged_ixp2asn[key]:
                    output = output + ', AS' + node

                    for IXP in self.subTree[key]:
                        output = output + ', ' + IXP[1] + ', ' + IXP[0]

                if key in self.cc_tree:
                    output = output + ', ' + \
                        self.cc_tree[key][0] + ', ' + self.cc_tree[key][1]
                output = output + '\n'
                number = number + 1
        filename.write(output)
        filename.close()


# Dictionary that contains country names to country codes.
country2cc = {
    'Afghanistan': 'AF',
    'Albania': 'AL',
    'Algeria': 'DZ',
    'American Samoa': 'AS',
    'Andorra': 'AD',
    'Angola': 'AO',
    'Anguilla': 'AI',
    'Antarctica': 'AQ',
    'Antigua and Barbuda': 'AG',
    'Argentina': 'AR',
    'Armenia': 'AM',
    'Aruba': 'AW',
    'Australia': 'AU',
    'Austria': 'AT',
    'Azerbaijan': 'AZ',
    'Bahamas': 'BS',
    'Bahrain': 'BH',
    'Bangladesh': 'BD',
    'Barbados': 'BB',
    'Belarus': 'BY',
    'Belgium': 'BE',
    'Belize': 'BZ',
    'Benin': 'BJ',
    'Bermuda': 'BM',
    'Bhutan': 'BT',
    'Bolivia, Plurinational State of': 'BO',
    'Bonaire, Sint Eustatius and Saba': 'BQ',
    'Bosnia and Herzegovina': 'BA',
    'Botswana': 'BW',
    'Bouvet Island': 'BV',
    'Brazil': 'BR',
    'British Indian Ocean Territory': 'IO',
    'Brunei Darussalam': 'BN',
    'Bulgaria': 'BG',
    'Burkina Faso': 'BF',
    'Burundi': 'BI',
    'Cambodia': 'KH',
    'Cameroon': 'CM',
    'Canada': 'CA',
    'Cape Verde': 'CV',
    'Cayman Islands': 'KY',
    'Central African Republic': 'CF',
    'Chad': 'TD',
    'Chile': 'CL',
    'China': 'CN',
    'Christmas Island': 'CX',
    'Cocos (Keeling) Islands': 'CC',
    'Colombia': 'CO',
    'Comoros': 'KM',
    'Congo': 'CG',
    'Congo, the Democratic Republic of the': 'CD',
    'Cook Islands': 'CK',
    'Costa Rica': 'CR',
    'Country name': 'Code',
    'Croatia': 'HR',
    'Cuba': 'CU',
    'Curaçao': 'CW',
    'Cyprus': 'CY',
    'Czech Republic': 'CZ',
    "Côte d'Ivoire": 'CI',
    "Cote D'Ivoire": 'CI',
    'Denmark': 'DK',
    'Djibouti': 'DJ',
    'Dominica': 'DM',
    'Dominican Republic': 'DO',
    'Ecuador': 'EC',
    'Egypt': 'EG',
    'El Salvador': 'SV',
    'Equatorial Guinea': 'GQ',
    'Eritrea': 'ER',
    'Estonia': 'EE',
    'Ethiopia': 'ET',
    'Falkland Islands (Malvinas)': 'FK',
    'Faroe Islands': 'FO',
    'Fiji': 'FJ',
    'Finland': 'FI',
    'France': 'FR',
    'French Guiana': 'GF',
    'French Polynesia': 'PF',
    'French Southern Territories': 'TF',
    'Gabon': 'GA',
    'Gambia': 'GM',
    'Georgia': 'GE',
    'Germany': 'DE',
    'Ghana': 'GH',
    'Gibraltar': 'GI',
    'Greece': 'GR',
    'Greenland': 'GL',
    'Grenada': 'GD',
    'Guadeloupe': 'GP',
    'Guam': 'GU',
    'Guatemala': 'GT',
    'Guernsey': 'GG',
    'Guinea': 'GN',
    'Guinea-Bissau': 'GW',
    'Guyana': 'GY',
    'Haiti': 'HT',
    'Heard Island and McDonald Islands': 'HM',
    'Holy See (Vatican City State)': 'VA',
    'Honduras': 'HN',
    'Hong Kong': 'HK',
    'Hungary': 'HU',
    'ISO 3166-2:GB': '(.uk)',
    'Iceland': 'IS',
    'India': 'IN',
    'Indonesia': 'ID',
    'Iran, Islamic Republic of': 'IR',
    'Iraq': 'IQ',
    'Ireland': 'IE',
    'Isle of Man': 'IM',
    'Israel': 'IL',
    'Italy': 'IT',
    'Jamaica': 'JM',
    'Japan': 'JP',
    'Jersey': 'JE',
    'Jordan': 'JO',
    'Kazakhstan': 'KZ',
    'Kenya': 'KE',
    'Kiribati': 'KI',
    "Korea, Democratic People's Republic of": 'KP',
    'Korea, Republic of': 'KR',
    'Kuwait': 'KW',
    'Kyrgyzstan': 'KG',
    "Lao People's Democratic Republic": 'LA',
    'Latvia': 'LV',
    'Lebanon': 'LB',
    'Lesotho': 'LS',
    'Liberia': 'LR',
    'Libya': 'LY',
    'Liechtenstein': 'LI',
    'Lithuania': 'LT',
    'Luxembourg': 'LU',
    'Macao': 'MO',
    'Macedonia, the former Yugoslav Republic of': 'MK',
    'Madagascar': 'MG',
    'Malawi': 'MW',
    'Malaysia': 'MY',
    'Maldives': 'MV',
    'Mali': 'ML',
    'Malta': 'MT',
    'Marshall Islands': 'MH',
    'Martinique': 'MQ',
    'Mauritania': 'MR',
    'Mauritius': 'MU',
    'Mayotte': 'YT',
    'Mexico': 'MX',
    'Micronesia, Federated States of': 'FM',
    'Moldova, Republic of': 'MD',
    'Monaco': 'MC',
    'Mongolia': 'MN',
    'Montenegro': 'ME',
    'Montserrat': 'MS',
    'Morocco': 'MA',
    'Mozambique': 'MZ',
    'Myanmar': 'MM',
    'Namibia': 'NA',
    'Nauru': 'NR',
    'Nepal': 'NP',
    'Netherlands': 'NL',
    'New Caledonia': 'NC',
    'New Zealand': 'NZ',
    'Nicaragua': 'NI',
    'Niger': 'NE',
    'Nigeria': 'NG',
    'Niue': 'NU',
    'Norfolk Island': 'NF',
    'Northern Mariana Islands': 'MP',
    'Norway': 'NO',
    'Oman': 'OM',
    'Pakistan': 'PK',
    'Palau': 'PW',
    'Palestine, State of': 'PS',
    'Palestine': 'PS',
    'Panama': 'PA',
    'Papua New Guinea': 'PG',
    'Paraguay': 'PY',
    'Peru': 'PE',
    'Philippines': 'PH',
    'Pitcairn': 'PN',
    'Poland': 'PL',
    'Portugal': 'PT',
    'Puerto Rico': 'PR',
    'Qatar': 'QA',
    'Romania': 'RO',
    'Russian Federation': 'RU',
    'Russian': 'RU',
    'Russia': 'RU',
    'Rwanda': 'RW',
    'Réunion': 'RE',
    'Saint Barthélemy': 'BL',
    'Saint Helena, Ascension and Tristan da Cunha': 'SH',
    'Saint Kitts and Nevis': 'KN',
    'Saint Lucia': 'LC',
    'Saint Martin (French part)': 'MF',
    'Saint Pierre and Miquelon': 'PM',
    'Saint Vincent and the Grenadines': 'VC',
    'Samoa': 'WS',
    'San Marino': 'SM',
    'Sao Tome and Principe': 'ST',
    'Saudi Arabia': 'SA',
    'Senegal': 'SN',
    'Serbia': 'RS',
    'Seychelles': 'SC',
    'Sierra Leone': 'SL',
    'Singapore': 'SG',
    'Sint Maarten (Dutch part)': 'SX',
    'Slovakia': 'SK',
    'Slovenia': 'SI',
    'Solomon Islands': 'SB',
    'Somalia': 'SO',
    'South Africa': 'ZA',
    'South Georgia and the South Sandwich Islands': 'GS',
    'South Sudan': 'SS',
    'Spain': 'ES',
    'Sri Lanka': 'LK',
    'Sudan': 'SD',
    'Suriname': 'SR',
    'Svalbard and Jan Mayen': 'SJ',
    'Swaziland': 'SZ',
    'Sweden': 'SE',
    'Switzerland': 'CH',
    'Syrian Arab Republic': 'SY',
    'Taiwan, Province of China': 'TW',
    'Taiwan': 'TW',
    'Tajikistan': 'TJ',
    'Tanzania, United Republic of': 'TZ',
    'Tanzania': 'TZ',
    'Thailand': 'TH',
    'Timor-Leste': 'TL',
    'Togo': 'TG',
    'Tokelau': 'TK',
    'Tonga': 'TO',
    'Trinidad and Tobago': 'TT',
    'Tunisia': 'TN',
    'Turkey': 'TR',
    'Turkmenistan': 'TM',
    'Turks and Caicos Islands': 'TC',
    'Tuvalu': 'TV',
    'Uganda': 'UG',
    'Ukraine': 'UA',
    'United Arab Emirates': 'AE',
    'United Kingdom': 'GB',
    'United States': 'US',
    'United States Minor Outlying Islands': 'UM',
    'Uruguay': 'UY',
    'Uzbekistan': 'UZ',
    'Vanuatu': 'VU',
    'Venezuela, Bolivarian Republic of': 'VE',
    'Viet Nam': 'VN',
    'Virgin Islands, British': 'VG',
    'Virgin Islands, U.S.': 'VI',
    'Wallis and Futuna': 'WF',
    'Western Sahara': 'EH',
    'Yemen': 'YE',
    'Zambia': 'ZM',
    'Zimbabwe': 'ZW',
    'Åland Islands': 'AX'}
