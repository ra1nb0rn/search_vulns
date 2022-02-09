#!/usr/bin/env python3

import argparse
import os
import json
import sqlite3
import sys
import re

from cpe_version import CPEVersion
from cpe_search.cpe_search import search_cpes, get_all_cpes
from updater import run as run_updater

DATABASE_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulndb.db3')
MATCH_CPE_23_RE = re.compile(r'cpe:2\.3:[aoh](:[^:]+){2,10}')
CPE_SEARCH_THRESHOLD = 0.72
ALL_CPES = []

# define ANSI color escape sequences
# Taken from: http://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html
# and: http://www.topmudsites.com/forums/showthread.php?t=413
SANE = "\u001b[0m"
GREEN = "\u001b[32m"
BRIGHT_GREEN = "\u001b[32;1m"
RED = "\u001b[31m"
YELLOW = "\u001b[33m"
BRIGHT_BLUE = "\u001b[34;1m"
MAGENTA = "\u001b[35m"
BRIGHT_CYAN = "\u001b[36;1m"


def printit(text: str = "", end: str = "\n", color=SANE):
    """A small print wrapper function"""

    print(color, end="")
    print(text, end=end)
    if color != SANE:
        print(SANE, end="")
    sys.stdout.flush()


def get_exact_vuln_matches(cpe, db_cursor):
    """Get vulns whose cpe entry matches the given one exactly"""
    query = "SELECT DISTINCT cve_id, with_cpes FROM cve_cpe WHERE cpe=?"
    vulns = db_cursor.execute(query, (cpe, )).fetchall()
    return vulns


def get_vulns_version_start_end_matches(cpe, cpe_parts, db_cursor):
    """
    Get vulnerability data that is stored in the DB more generally,
    e.g. with version_start and version_end information
    """
    
    vulns = []
    cpe_version = ""

    if len(cpe_parts) > 5 and cpe_parts[5] not in ('-', '*'):  # for CPE 2.3
        cpe_version = cpe_parts[5]

    # query DB for general CPE-vuln data, potentially with cpe_version_start and cpe_version_end fields
    general_cpe_nvd_data = set()
    query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
             'is_cpe_version_end_including, with_cpes FROM cve_cpe WHERE cpe LIKE ? OR cpe LIKE ? OR cpe LIKE ?')

    for cur_part_idx in range(5, len(cpe_parts)):
        if cpe_parts[cur_part_idx] not in ('*', '-'):
            cur_cpe_prefix = ':'.join(cpe_parts[:cur_part_idx])
            cpe_wildcards = ["%s::%%" % cur_cpe_prefix, "%s:-:%%" % cur_cpe_prefix, "%s:*:%%" % cur_cpe_prefix]
            general_cpe_nvd_data |= set(db_cursor.execute(query, cpe_wildcards).fetchall())

    if not cpe_version:
        general_query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
                         'is_cpe_version_end_including, with_cpes FROM cve_cpe WHERE cpe LIKE ?')
        general_vulns = set(db_cursor.execute(general_query, (':'.join(cpe_parts[:5])+':%%', )))
        return general_cpe_nvd_data | general_vulns

    # check version information of potential vulns to determine whether given version is actually vulnerable
    vulns = []
    cpe_version = CPEVersion(cpe_version)
    for pot_vuln in general_cpe_nvd_data:
        vuln_cpe = pot_vuln[1]
        version_start, version_start_incl = pot_vuln[2], pot_vuln[3]
        version_end, version_end_incl = pot_vuln[4], pot_vuln[5]
        is_cpe_vuln = False

        if version_start and version_end:
            if version_start_incl == True and version_end_incl == True:
                is_cpe_vuln = CPEVersion(version_start) <= cpe_version <= CPEVersion(version_end)
            elif version_start_incl == True and version_end_incl == False:
                is_cpe_vuln = CPEVersion(version_start) <= cpe_version < CPEVersion(version_end)
            elif version_start_incl == False and version_end_incl == True:
                is_cpe_vuln = CPEVersion(version_start) < cpe_version <= CPEVersion(version_end)
            else:
                is_cpe_vuln = CPEVersion(version_start) < cpe_version < CPEVersion(version_end)
        elif version_start:
            if version_end_incl == True:
                is_cpe_vuln = CPEVersion(version_start) <= cpe_version
            elif version_end_incl == False:
                is_cpe_vuln = CPEVersion(version_start) < cpe_version
        elif version_end:
            if version_end_incl == True:
                is_cpe_vuln = cpe_version <= CPEVersion(version_end)
            elif version_end_incl == False:
                is_cpe_vuln = cpe_version < CPEVersion(version_end)
        else:
            is_cpe_vuln = is_cpe_included_after_version(cpe, vuln_cpe)

        # check that everything after the version field matches in the CPE
        if is_cpe_vuln:
            if cpe.count(':') > 5 and vuln_cpe.count(':') > 5:
                if not is_cpe_included_after_version(cpe, vuln_cpe):
                    is_cpe_vuln = False

        if is_cpe_vuln:
            vulns.append(pot_vuln)

    return vulns


def is_cpe_included_after_version(cpe1, cpe2):
    '''Return True if cpe1 is included in cpe2 after the version section'''

    cpe1_remainder_fields = ':'.join(cpe1.split(':')[6:])
    cpe2_remainder_fields = ':'.join(cpe2.split(':')[6:])

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        if cpe1_remainder_fields[i] in ('*', '-'):
            continue
        if cpe2_remainder_fields[i] in ('*', '-'):
            continue

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False
    return True


def get_vulns(cpe, db_cursor):
    """Get known vulnerabilities for the given CPE 2.3 string"""

    cpe_parts = cpe.split(':')
    vulns = []

    vulns += get_exact_vuln_matches(cpe, db_cursor)
    vulns += get_vulns_version_start_end_matches(cpe, cpe_parts, db_cursor)

    # retrieve more information about the found vulns, e.g. CVSS scores and possible exploits
    detailed_vulns = {}
    for vuln in vulns:
        cve_id = vuln[0]
        query = 'SELECT edb_ids, description, published, last_modified, cvss_version, base_score FROM cve WHERE cve_id = ?'
        edb_ids, descr, publ, last_mod, cvss_ver, score = db_cursor.execute(query, (cve_id,)).fetchone()
        detailed_vulns[cve_id] = {"id": cve_id, "description": descr, "published": publ, "modified": last_mod,
                                  "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id}

        edb_ids = edb_ids.strip()
        if edb_ids:
            detailed_vulns[cve_id]["exploits"] = []
            for edb_id in edb_ids.split(","):
                detailed_vulns[cve_id]["exploits"].append("https://www.exploit-db.com/exploits/%s" % edb_id)

        detailed_vulns[cve_id]['cvss_ver'] = cvss_ver
        detailed_vulns[cve_id]['cvss'] = score

    return detailed_vulns


def is_cpe_equal(cpe1, cpe2):
    """Return True if both CPEs are considered equal, False otherwise"""

    if len(cpe1) != len(cpe2):
        return False

    for i in range(len(cpe1)):
        if cpe1[i] != cpe2[i]:
            if not(cpe1[i] in ('*', '-') and cpe2[i] in('*', '-')):
                return False
    return True


def get_valid_cpe(cpe_in, keep_data_in_memory=False):
    """
    Try to return a valid CPE 2.3 string that exists in the NVD's CPE
    dictionary based on the given, potentially badly formed, CPE string.
    """

    global ALL_CPES

    if not ALL_CPES:
        all_cpes = get_all_cpes(version='2.3')
        if keep_data_in_memory:
            ALL_CPES = all_cpes
    else:
        all_cpes = ALL_CPES

    # if CPE is already in the NVD dictionary
    if cpe_in in all_cpes:
        return cpe_in

    # if the given CPE is simply not a full CPE 2.3 string
    if cpe_in.count(':') < 12:
        new_cpe = cpe_in
        if new_cpe.endswith(':'):
            new_cpe += '*'
        while new_cpe.count(':') < 12:
            new_cpe += ':*'
        for pot_cpe in all_cpes:
            if new_cpe == pot_cpe:
                return pot_cpe

    # try to "fix" badly formed CPE strings like
    # "cpe:2.3:a:proftpd:proftpd:1.3.3c:..." vs. "cpe:2.3:a:proftpd:proftpd:1.3.3:c:..."
    pre_cpe_in = cpe_in
    while pre_cpe_in.count(':') > 3:  # break if next cpe part would be vendor part
        pre_cpe_in = pre_cpe_in[:-1]
        if pre_cpe_in.endswith(':') or pre_cpe_in.count(':') > 9:  # skip rear parts in fixing process
            continue

        for pot_cpe in all_cpes:
            if pre_cpe_in in pot_cpe:

                # stitch together the found prefix and the remaining part of the original CPE
                if cpe_in[len(pre_cpe_in)] == ':':
                    cpe_in_add_back = cpe_in[len(pre_cpe_in)+1:]
                else:
                    cpe_in_add_back = cpe_in[len(pre_cpe_in):]
                new_cpe = '%s:%s' % (pre_cpe_in, cpe_in_add_back)

                # get new_cpe to full CPE 2.3 length by adding or removing wildcards
                while new_cpe.count(':') < 12:
                    new_cpe += ':*'
                if new_cpe.count(':') > 12:
                    new_cpe = new_cpe[:new_cpe.rfind(':')]

                # if a matching CPE was found, return it
                if is_cpe_equal(new_cpe, pot_cpe):
                    return pot_cpe

    return ''


def print_vulns(vulns, to_string=False):
    """Print the supplied vulnerabilities"""

    out_string = ''
    cve_ids_sorted = sorted(list(vulns), key=lambda cve_id: float(vulns[cve_id]["cvss"]), reverse=True)
    for cve_id in cve_ids_sorted:
        vuln_node = vulns[cve_id]
        description = vuln_node["description"].replace("\r\n\r\n", "\n").replace("\n\n", "\n").strip()

        if not to_string:
            print_str = GREEN + vuln_node["id"] + SANE
            print_str += " (" + MAGENTA + 'CVSSv' + vuln_node['cvss_ver'] + '/' + str(vuln_node["cvss"]) + SANE + "): %s\n" % description
        else:
            print_str = vuln_node["id"]
            print_str += " ("'CVSSv' + vuln_node['cvss_ver'] + '/' + str(vuln_node["cvss"]) + "): %s\n" % description

        if "exploits" in vuln_node:
            if not to_string:
                print_str += YELLOW + "Exploits:  " + SANE + vuln_node["exploits"][0] + "\n"
            else:
                print_str += "Exploits:  " + vuln_node["exploits"][0] + "\n"

            if len(vuln_node["exploits"]) > 1:
                for edb_link in vuln_node["exploits"][1:]:
                    print_str += len("Exploits:  ") * " " + edb_link + "\n"

        print_str += "Reference: " + vuln_node["href"]
        print_str += ", " + vuln_node["published"].split(" ")[0]
        if not to_string:
            printit(print_str)
        else:
            out_string += print_str + '\n'

    if to_string:
        return out_string


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False):
    """Search for known vulnerabilities based on the given query"""

    # create DB handle if not given
    close_cursor_after = False
    if not db_cursor:
        db_conn_file = sqlite3.connect(DATABASE_FILE)
        db_conn_mem = sqlite3.connect(':memory:')
        db_conn_file.backup(db_conn_mem)
        db_cursor = db_conn_mem.cursor()
        # db_cursor = db_conn_file.cursor()
        close_cursor_after = True

    # if given query is not already a CPE, retrieve a CPE that matches the query
    cpe = query
    if not MATCH_CPE_23_RE.match(query):
        cpe = search_cpes(query, cpe_version="2.3", count=1, threshold=software_match_threshold)

        if not cpe or not cpe[query]:
            return None

        matching_cpe = cpe[query][0][0]
    else:
        matching_cpe = get_valid_cpe(cpe, keep_data_in_memory=keep_data_in_memory)
        if matching_cpe:
            cpe = matching_cpe

    # use the retrieved, or found, CPE to search for known vulnerabilities
    if matching_cpe:
        vulns = get_vulns(matching_cpe, db_cursor)
    else:
        vulns = get_vulns(cpe, db_cursor)

    if close_cursor_after:
        db_cursor.close()

    return vulns


def parse_args():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(description="Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)")
    parser.add_argument("-u", "--update", action="store_true", help="Download the latest version of the the local vulnerability and software database")
    parser.add_argument("--full-update", action="store_true", help="Build complete update of the local vulnerability and software database")
    parser.add_argument("-f", "--format", type=str, default="txt", choices={"txt", "json"}, help="Output format, either 'txt' or 'json' (default: 'txt')")
    parser.add_argument("-o", "--output", type=str, help="File to write found vulnerabilities to")
    parser.add_argument("-q", "--query", dest="queries", metavar="QUERY", action="append", help="A query, either software title like 'Apache 2.4.39' or a CPE 2.3 string")

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update:
        parser.print_help()
    return args


def main():
    # parse args and run update routine if requested
    args = parse_args()
    if args.update == True:
        run_updater(False)
    elif args.full_update == True:
        run_updater(True)

    if not args.queries:
        return

    # get handle for vulnerability database
    db_conn_file = sqlite3.connect(DATABASE_FILE)
    db_conn_mem = sqlite3.connect(':memory:')
    db_conn_file.backup(db_conn_mem)
    db_cursor = db_conn_mem.cursor()
    # db_cursor = db_conn_file.cursor()

    # retrieve known vulnerabilities for every query and print them
    vulns = {}
    out_string = ''
    for query in args.queries:
        # if current query is not already a CPE, retrieve a CPE that matches the query
        cpe = query
        if not MATCH_CPE_23_RE.match(query):
            cpe = search_cpes(query, cpe_version="2.3", count=1, threshold=CPE_SEARCH_THRESHOLD)

            if not cpe or not cpe[query]:
                if args.format.lower() == 'txt':
                    print('Warning: Could not find matching software for query \'%s\'' % query)
                    if len(args.queries) > 1:
                        print()
                else:
                    vulns[query] = 'Warning: Could not find matching software for query \'%s\'' % query
                continue

            cpe = cpe[query][0][0]
        else:
            matching_cpe = get_valid_cpe(cpe)
            if matching_cpe:
                cpe = matching_cpe

        # retrieve known vulns and print
        if args.format.lower() == 'txt':
            if not args.output:
                print()
                printit('[+] %s (%s)' % (query, cpe), color=BRIGHT_BLUE)
                vulns[query] = search_vulns(cpe, db_cursor, CPE_SEARCH_THRESHOLD)
                print_vulns(vulns[query])
            else:
                out_string += '\n' + '[+] %s (%s)\n' % (query, cpe)
                vulns[query] = search_vulns(cpe, db_cursor, CPE_SEARCH_THRESHOLD)
                out_string += print_vulns(vulns[query], to_string=True)
        else:
            vulns[query] = search_vulns(cpe, db_cursor, CPE_SEARCH_THRESHOLD)

    if args.output:
        with open(args.output, 'w') as f:
            if args.format.lower() == 'json':
                f.write(json.dumps(vulns))
            else:
                f.write(out_string)
    elif args.format.lower() == 'json':
        print(json.dumps(vulns))

    db_cursor.close()


if __name__ == "__main__":
    main()
