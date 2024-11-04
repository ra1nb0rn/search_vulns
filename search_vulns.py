#!/usr/bin/env python3

import argparse
import datetime
import json
import re
import threading

from cpe_search.cpe_search import (
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    cpe_matches_query
)
from search_vulns_modules.config import _load_config, DEFAULT_CONFIG_FILE
from search_vulns_modules.generic_functions import *
from search_vulns_modules.search_vulns_functions import search_vulns
from search_vulns_modules.process_distribution_matches import (
    is_possible_distro_query, 
    seperate_distribution_information_from_query, 
    add_distribution_infos_to_cpe,
    get_distribution_data_from_version
)


def parse_args():
    '''Parse command line arguments'''

    parser = argparse.ArgumentParser(description='Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)')
    parser.add_argument('-u', '--update', action='store_true', help='Download the latest version of the the local vulnerability and software database')
    parser.add_argument('--full-update', action='store_true', help='Fully (re)build the local vulnerability and software database')
    parser.add_argument('-k', '--api-key', type=str, help='NVD API key to use for updating the local vulnerability and software database')
    parser.add_argument('-f', '--format', type=str, default='txt', choices={'txt', 'json'}, help='Output format, either \'txt\' or \'json\' (default: \'txt\')')
    parser.add_argument('-o', '--output', type=str, help='File to write found vulnerabilities to')
    parser.add_argument('-q', '--query', dest='queries', metavar='QUERY', action='append', help='A query, either software title like \'Apache 2.4.39\' or a CPE 2.3 string')
    parser.add_argument('-c', '--config', type=str, default=DEFAULT_CONFIG_FILE, help='A config file to use (default: config.json)')
    parser.add_argument('-V', '--version', action='store_true', help='Print the version of search_vulns')
    parser.add_argument('--cpe-search-threshold', type=float, default=CPE_SEARCH_THRESHOLD_MATCH, help='Similarity threshold used for retrieving a CPE via the cpe_search tool')
    parser.add_argument('--ignore-general-cpe-vulns', action='store_true', help='Ignore vulnerabilities that only affect a general CPE (i.e. without version)')
    parser.add_argument('--include-single-version-vulns', action='store_true', help='Include vulnerabilities that only affect one specific version of a product when querying a lower version')
    parser.add_argument('--ignore-general-distribution-vulns', action='store_true', help='Ignore vulnerabilities that neither have a NVD entry nor a matching distribution entry')
    parser.add_argument('--use-created-cpes', action='store_true', help='If no matching CPE exists in the software database, automatically use a matching CPE created by search_vulns')

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update and not args.version:
        parser.print_help()
    return args


def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.update == True:
        from updates.updater import run as run_updater
        run_updater(False, args.api_key, args.config)
    elif args.full_update == True:
        from updates.updater import run as run_updater
        run_updater(True, args.api_key, args.config)
    elif args.version == True:
        with open(VERSION_FILE) as f:
            print(f.read())
        return

    if not args.queries:
        return

    # get handle for vulnerability database
    config = _load_config(args.config)
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    # retrieve known vulnerabilities for every query and print them
    vulns = {}
    out_string = ''
    for query in args.queries:
        # if current query is not already a CPE, retrieve a CPE that matches the query
        query = query.strip()
        cpe = query
        distribution = ('', 'inf')
        # check if given query contains distribution information
        if is_possible_distro_query(query):
            distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            possible_versions = get_possible_versions_in_query(query)
            if possible_versions:
                distribution = get_distribution_data_from_version(possible_versions[0], db_cursor)
            cpe_search_query = query
        
        # query is not a cpe
        if not MATCH_CPE_23_RE.match(query):
            cpe_search_results = search_cpes(cpe_search_query, count=1, threshold=args.cpe_search_threshold, config=config['cpe_search'])
            if cpe_search_results.get('cpes', []):
                cpe = cpe_search_results['cpes'][0][0]
            else:
                cpe = None

            found_cpe = True
            if not cpe:
                found_cpe = False
            else:
                check_str = cpe[8:]
                if any(char.isdigit() for char in query) and not any(char.isdigit() for char in check_str):
                    found_cpe = False
                
            # if a good CPE couldn't be found, use a created one if configured
            if not found_cpe and args.use_created_cpes and cpe_search_results['pot_cpes']:
                for pot_cpe in cpe_search_results['pot_cpes']:
                    if cpe_matches_query(pot_cpe[0], query):
                        cpe = pot_cpe[0]
                        found_cpe = True
                        break

            if not found_cpe:
                if args.format.lower() == 'txt':
                    if not args.output:
                        print('Warning: Could not find matching software for query \'%s\'' % query)
                        if len(args.queries) > 1:
                            print()
                    else:
                        out_string = 'Warning: Could not find matching software for query \'%s\'\n' % query
                else:
                    vulns[query] = 'Warning: Could not find matching software for query \'%s\'' % query
                continue
        else:
            matching_cpe = match_cpe23_to_cpe23_from_dict(cpe, config=config['cpe_search'])
            if matching_cpe:
                cpe = matching_cpe

        # use the retrieved CPE to search for known vulnerabilities
        vulns[query] = {}
        equivalent_cpes = get_equivalent_cpes(cpe, config)
        
        # add distribution info to all found cpes
        if distribution[0]:
            cpe = add_distribution_infos_to_cpe(cpe, distribution)
            equivalent_cpes = [add_distribution_infos_to_cpe(cpe_, distribution) for cpe_ in equivalent_cpes]
        if args.format.lower() == 'txt':
            if not args.output:
                print()
                printit('[+] %s (%s)' % (query, '/'.join(equivalent_cpes)), color=BRIGHT_BLUE)

        not_affected_cve_ids = []
        eol_info = {}
        for cur_cpe in equivalent_cpes:
            cur_vulns, not_affected_cve_ids_returned = search_vulns(cur_cpe, db_cursor, args.cpe_search_threshold, False, True, args.ignore_general_cpe_vulns, args.include_single_version_vulns, args.ignore_general_distribution_vulns, config)
            not_affected_cve_ids += not_affected_cve_ids_returned
            
            for cve_id, vuln in cur_vulns[cur_cpe]['vulns'].items():
                if cve_id not in vulns[query]:
                    vulns[query][cve_id] = vuln
            if cur_vulns[cur_cpe]['version_status']:
                eol_info = cur_vulns[cur_cpe]['version_status']

        # delete not affected vulns
        for cve_id in not_affected_cve_ids:
            try:
                del vulns[query][cve_id]
            except:
                pass

        # print found vulnerabilities
        if args.format.lower() == 'txt':
            if not args.output:
                print_vulns(vulns[query])
            else:
                out_string += '\n' + '[+] %s (%s)\n' % (query, cpe)
                out_string += print_vulns(vulns[query], to_string=True)
        else:
            cpe_vulns = vulns[query]
            cve_ids_sorted = sorted(list(cpe_vulns), key=lambda cve_id: float(cpe_vulns[cve_id]['cvss']), reverse=True)
            cpe_vulns_sorted = {}
            for cve_id in cve_ids_sorted:
                cpe_vulns_sorted[cve_id] = cpe_vulns[cve_id]
            vulns[query] = {'cpe': '/'.join(equivalent_cpes), 'vulns': cpe_vulns_sorted,
                            'version_status': eol_info}

    if args.output:
        with open(args.output, 'w') as f:
            if args.format.lower() == 'json':
                f.write(json.dumps(vulns))
            else:
                f.write(out_string)
    elif args.format.lower() == 'json':
        print(json.dumps(vulns))

    db_cursor.close()
    db_conn.close()


if __name__ == '__main__':
    main()