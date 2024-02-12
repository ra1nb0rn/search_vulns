#!/usr/bin/env python3

import argparse
import json
import re
import sqlite3
import threading

from cpe_search.cpe_search import (
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    get_possible_versions_in_query,
)
from search_vulns_modules.config import _load_config, DEFAULT_CONFIG_FILE
from search_vulns_modules.generic_functions import get_equivalent_cpes, printit, print_vulns
from search_vulns_modules.search_vulns import search_vulns
from search_vulns_modules.process_distribution_matches import (
    is_possible_distro_query, 
    seperate_distribution_information_from_query, 
    get_distribution_data_from_version,
    add_distribution_infos_to_cpe
)
MATCH_CPE_23_RE = re.compile(r'cpe:2\.3:[aoh](:[^:]+){2,10}')
CPE_SEARCH_THRESHOLD = 0.72
MATCH_DISTRO_CPE_OTHER_FIELD = re.compile(r'([<>]?=?)(ubuntu|debian|rhel)_?([\d\.]{1,5}|inf|upstream|sid)?')
MATCH_DISTRO_QUERY = re.compile(r'(ubuntu|debian|redhat enterprise linux|redhat|rhel)[ _]?([\w\.]*)')
MATCH_DISTRO = re.compile(r'(ubuntu|debian|redhat|rhel)(?:[^\d]|$)')
MATCH_DISTRO_CPE = re.compile(r'cpe:2\.3:[aoh]:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:[<>]?=?(ubuntu|rhel|debian)_?([\d\.]+|upstream|sid)?$')
MATCH_TWO_SOFTWARES_AND_VERSIONS = re.compile(r'([\w\.\:\-\_\~]*\s){2,}')

EQUIVALENT_CPES = {}
LOAD_EQUIVALENT_CPES_MUTEX = threading.Lock()
DEDUP_LINEBREAKS_RE_1 = re.compile(r'(\r\n)+')
DEDUP_LINEBREAKS_RE_2 = re.compile(r'\n+')

UNIX_CPES = ['cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*', 'cpe:2.3:o:opengroup:unix:-:*:*:*:*:*:*:*', 'cpe:2.3:o:unix:unix:*:*:*:*:*:*:*:*']

# define ANSI color escape sequences
# Taken from: http://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html
# and: http://www.topmudsites.com/forums/showthread.php?t=413
SANE = '\u001b[0m'
GREEN = '\u001b[32m'
BRIGHT_GREEN = '\u001b[32;1m'
RED = '\u001b[31m'
YELLOW = '\u001b[33m'
BRIGHT_BLUE = '\u001b[34;1m'
MAGENTA = '\u001b[35m'
BRIGHT_CYAN = '\u001b[36;1m'


def parse_args():
    '''Parse command line arguments'''

    parser = argparse.ArgumentParser(description='Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)')
    parser.add_argument('-u', '--update', action='store_true', help='Download the latest version of the the local vulnerability and software database')
    parser.add_argument('--full-update', action='store_true', help='Fully (re)build the local vulnerability and software database')
    parser.add_argument('-k', '--api-key', type=str, help='NVD API key to use for updating the local vulnerability and software database')
    parser.add_argument('-f', '--format', type=str, default='txt', choices={'txt', 'json'}, help='Output format, either \'txt\' or \'json\' (default: \'txt\')')
    parser.add_argument('-o', '--output', type=str, help='File to write found vulnerabilities to')
    parser.add_argument('-q', '--query', dest='queries', metavar='QUERY', action='append', help='A query, either software title like \'Apache 2.4.39\' or a CPE 2.3 string')
    parser.add_argument('--cpe-search-threshold', type=float, default=CPE_SEARCH_THRESHOLD, help='Similarity threshold used for retrieving a CPE via the cpe_search tool')
    parser.add_argument('--ignore-general-cpe-vulns', action='store_true', help='Ignore vulnerabilities that only affect a general CPE (i.e. without version)')
    parser.add_argument('-c', '--config', type=str, default=DEFAULT_CONFIG_FILE, help='A config file to use (default: config.json)')

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update:
        parser.print_help()
    return args


def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.update == True:
        from updates.updater import run as run_updater
        run_updater(False, args.api_key)
    elif args.full_update == True:
        from updates.updater import run as run_updater
        run_updater(True, args.api_key)

    if not args.queries:
        return

    # get handle for vulnerability database
    config = _load_config(args.config)
    db_conn_file = sqlite3.connect(config['DATABASE_FILE'])
    db_cursor = db_conn_file.cursor()

    # retrieve known vulnerabilities for every query and print them
    vulns = {}
    out_string = ''
    for query in args.queries:
        # if current query is not already a CPE, retrieve a CPE that matches the query
        query = query.strip()
        cpe = query
        if is_possible_distro_query(query):
            distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            possible_versions = get_possible_versions_in_query(query)
            if possible_versions:
                distribution = get_distribution_data_from_version(possible_versions[0], db_cursor)
            cpe_search_query = query
        if not MATCH_CPE_23_RE.match(query): 
            cpe = search_cpes(cpe_search_query, count=1, threshold=args.cpe_search_threshold, config=config['cpe_search'])
            found_cpe = True
            if not cpe or not cpe[cpe_search_query]:
                found_cpe = False
            else:
                check_str = cpe[cpe_search_query][0][0][8:]
                if any(char.isdigit() for char in cpe_search_query) and not any(char.isdigit() for char in check_str):
                    found_cpe = False

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

            cpe = cpe[cpe_search_query][0][0]
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
        for cur_cpe in equivalent_cpes:
            cur_vulns, not_affected_cve_ids_returned = search_vulns(cur_cpe, db_cursor, args.cpe_search_threshold, False, False, True, args.ignore_general_cpe_vulns, config)
            not_affected_cve_ids += not_affected_cve_ids_returned
            
            for cve_id, vuln in cur_vulns.items():
                if cve_id not in vulns[query]:
                    vulns[query][cve_id] = vuln
    
        # delete not affected vulns
        for cve_id in not_affected_cve_ids:
            try:
                del vulns[cve_id]
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
            vulns[query] = {'cpe': '/'.join(equivalent_cpes), 'vulns': cpe_vulns_sorted}

    if args.output:
        with open(args.output, 'w') as f:
            if args.format.lower() == 'json':
                f.write(json.dumps(vulns))
            else:
                f.write(out_string)
    elif args.format.lower() == 'json':
        print(json.dumps(vulns))

    db_cursor.close()


if __name__ == '__main__':
    main()