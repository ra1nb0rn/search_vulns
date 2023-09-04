#!/usr/bin/env python3

import argparse
from collections import OrderedDict
import json
import os
import re
import sqlite3
import sys
import threading

from cpe_version import CPEVersion
from cpe_search.cpe_search import (
    is_cpe_equal,
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    create_cpe_from_base_cpe_and_query,
    create_base_cpe_if_versionless_query,
    VERSION_MATCH_CPE_CREATION_RE
)

DATABASE_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulndb.db3')
MATCH_CPE_23_RE = re.compile(r'cpe:2\.3:[aoh](:[^:]+){2,10}')
CPE_SEARCH_THRESHOLD = 0.72
CPE_DEPRECATIONS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "cpe_search/deprecated-cpes.json")
EQUIVALENT_CPES = {}
LOAD_EQUIVALENT_CPES_MUTEX = threading.Lock()
DEDUP_LINEBREAKS_RE_1 = re.compile(r'(\r\n)+')
DEDUP_LINEBREAKS_RE_2 = re.compile(r'\n+')

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


def get_vulns_version_start_end_matches(cpe, cpe_parts, db_cursor, ignore_general_cpe_vulns=False):
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
    get_cpes_query = 'SELECT cpe FROM cve_cpe WHERE cpe LIKE ? AND cve_id = ?'

    for cur_part_idx in range(5, len(cpe_parts)):
        if cpe_parts[cur_part_idx] not in ('*', '-'):
            cur_cpe_prefix = ':'.join(cpe_parts[:cur_part_idx])
            cpe_wildcards = ["%s::%%" % cur_cpe_prefix, "%s:-:%%" % cur_cpe_prefix, "%s:*:%%" % cur_cpe_prefix]
            general_cpe_nvd_data |= set(db_cursor.execute(query, cpe_wildcards).fetchall())

            # remove vulns that have a more specific exact CPE, which cur_cpe_prefix is a prefix of
            found_vulns_cpes = {}
            remove_vulns = set()
            for pot_vuln in general_cpe_nvd_data:
                cve_id, vuln_cpe, with_cpes = pot_vuln[0], pot_vuln[1], pot_vuln[6]
                version_start, version_end = pot_vuln[2], pot_vuln[4]

                if not version_start and not version_end:
                    if cve_id not in found_vulns_cpes:
                        vuln_cpes = set(db_cursor.execute(get_cpes_query, (cur_cpe_prefix+':%%', pot_vuln[0])))
                        found_vulns_cpes[cve_id] = vuln_cpes
                    if len(found_vulns_cpes[cve_id]) > 1:
                        remove_vulns.add(pot_vuln)

            general_cpe_nvd_data -= remove_vulns

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
            # if configured, ignore vulnerabilities that only affect a general CPE
            if ignore_general_cpe_vulns and all(val in ('*', '-') for val in vuln_cpe.split(':')[5:]):
                continue
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

    cpe1_remainder_fields = cpe1.split(':')[6:]
    cpe2_remainder_fields = cpe2.split(':')[6:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        if cpe1_remainder_fields[i] in ('*', '-'):
            continue
        if cpe2_remainder_fields[i] in ('*', '-'):
            continue

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False
    return True


def get_vulns(cpe, db_cursor, ignore_general_cpe_vulns=False, add_other_exploit_refs=False):
    """Get known vulnerabilities for the given CPE 2.3 string"""

    cpe_parts = cpe.split(':')
    vulns = []

    vulns += get_exact_vuln_matches(cpe, db_cursor)
    vulns += get_vulns_version_start_end_matches(cpe, cpe_parts, db_cursor, ignore_general_cpe_vulns)

    if ':-:' in cpe:
        # use '-' as wildcard and query for additional exact matches
        vulns += get_exact_vuln_matches(cpe.replace(':-:', ':*:'), db_cursor)

    # retrieve more information about the found vulns, e.g. CVSS scores and possible exploits
    detailed_vulns = {}
    for vuln in vulns:
        cve_id = vuln[0]
        if cve_id in detailed_vulns:
            continue

        query = 'SELECT edb_ids, description, published, last_modified, cvss_version, base_score, vector FROM cve WHERE cve_id = ?'
        edb_ids, descr, publ, last_mod, cvss_ver, score, vector = db_cursor.execute(query, (cve_id,)).fetchone()
        detailed_vulns[cve_id] = {"id": cve_id, "description": descr, "published": publ, "modified": last_mod,
                                  "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id, "cvss_ver": cvss_ver,
                                  "cvss": score, "cvss_vec": vector}

        edb_ids = edb_ids.strip()
        if edb_ids:
            detailed_vulns[cve_id]["exploits"] = []
            for edb_id in edb_ids.split(","):
                detailed_vulns[cve_id]["exploits"].append("https://www.exploit-db.com/exploits/%s" % edb_id)

        # add other exploit references
        if add_other_exploit_refs:
            # from NVD
            query = 'SELECT exploit_ref FROM nvd_exploits_refs INNER JOIN cve_nvd_exploits_refs ON nvd_exploits_refs.ref_id = cve_nvd_exploits_refs.ref_id WHERE cve_id = ?'
            nvd_exploit_refs = db_cursor.execute(query, (cve_id,)).fetchall()
            if nvd_exploit_refs:
                if "exploits" not in detailed_vulns[cve_id]:
                    detailed_vulns[cve_id]["exploits"] = []
                for nvd_exploit_ref in nvd_exploit_refs:
                    if (nvd_exploit_ref[0] not in detailed_vulns[cve_id]["exploits"] and
                            nvd_exploit_ref[0] + '/' not in detailed_vulns[cve_id]["exploits"] and
                            nvd_exploit_ref[0][:-1] not in detailed_vulns[cve_id]["exploits"]):
                        detailed_vulns[cve_id]["exploits"].append(nvd_exploit_ref[0])

            # from PoC-in-Github
            query = 'SELECT reference FROM cve_poc_in_github_map WHERE cve_id = ?'
            poc_in_github_refs = db_cursor.execute(query, (cve_id,)).fetchall()
            if poc_in_github_refs:
                if "exploits" not in detailed_vulns[cve_id]:
                    detailed_vulns[cve_id]["exploits"] = []
                for poc_in_github_ref in poc_in_github_refs:
                    if (poc_in_github_ref[0] not in detailed_vulns[cve_id]["exploits"] and
                            poc_in_github_ref[0] + '/' not in detailed_vulns[cve_id]["exploits"] and
                            poc_in_github_ref[0][:-1] not in detailed_vulns[cve_id]["exploits"] and
                            poc_in_github_ref[0] + '.git' not in detailed_vulns[cve_id]["exploits"]):
                        detailed_vulns[cve_id]["exploits"].append(poc_in_github_ref[0])

    return detailed_vulns


def print_vulns(vulns, to_string=False):
    """Print the supplied vulnerabilities"""

    out_string = ''
    cve_ids_sorted = sorted(list(vulns), key=lambda cve_id: float(vulns[cve_id]["cvss"]), reverse=True)
    for cve_id in cve_ids_sorted:
        vuln_node = vulns[cve_id]
        description = DEDUP_LINEBREAKS_RE_2.sub('\n', DEDUP_LINEBREAKS_RE_1.sub('\r\n', vuln_node["description"].strip()))

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


def load_equivalent_cpes():
    """Load dictionary containing CPE equivalences"""

    LOAD_EQUIVALENT_CPES_MUTEX.acquire()
    if not EQUIVALENT_CPES:
        # first add official deprecation information from the NVD
        with open(CPE_DEPRECATIONS_FILE, "r") as f:
            cpe_deprecations_raw = json.loads(f.read())
            for cpe, deprecations in cpe_deprecations_raw.items():
                cpe_short = ':'.join(cpe.split(':')[:5]) + ':'
                deprecations_short = []
                for deprecatedby_cpe in deprecations:
                    deprecatedby_cpe_short = ':'.join(deprecatedby_cpe.split(':')[:5]) + ':'
                    if deprecatedby_cpe_short not in deprecations_short:
                        deprecations_short.append(deprecatedby_cpe_short)

                if cpe_short not in EQUIVALENT_CPES:
                    EQUIVALENT_CPES[cpe_short] = deprecations_short
                else:
                    EQUIVALENT_CPES[cpe_short] = list(set(EQUIVALENT_CPES[cpe_short] + deprecations_short))

                for deprecatedby_cpe_short in deprecations_short:
                    if deprecatedby_cpe_short not in EQUIVALENT_CPES:
                        EQUIVALENT_CPES[deprecatedby_cpe_short] = [cpe_short]
                    elif cpe_short not in EQUIVALENT_CPES[deprecatedby_cpe_short]:
                        EQUIVALENT_CPES[deprecatedby_cpe_short].append(cpe_short)

        # then manually add further information
        manual_equivalent_cpes = {
            'cpe:2.3:a:redis:redis:': ['cpe:2.3:a:redislabs:redis:'],
            'cpe:2.3:a:jquery:jquery_ui:': ['cpe:2.3:a:jqueryui:jquery_ui:'],
        }

        for man_equiv_cpe, other_equiv_cpes in manual_equivalent_cpes.items():
            if man_equiv_cpe not in EQUIVALENT_CPES:
                EQUIVALENT_CPES[man_equiv_cpe] = other_equiv_cpes
            else:
                EQUIVALENT_CPES[man_equiv_cpe] = list(set(EQUIVALENT_CPES[man_equiv_cpe] + other_equiv_cpes))

            for other_equiv_cpe in other_equiv_cpes:
                if other_equiv_cpe not in EQUIVALENT_CPES:
                    EQUIVALENT_CPES[other_equiv_cpe] = [man_equiv_cpe]
                elif man_equiv_cpe not in EQUIVALENT_CPES[other_equiv_cpe]:
                    EQUIVALENT_CPES[other_equiv_cpe].append(man_equiv_cpe)

    LOAD_EQUIVALENT_CPES_MUTEX.release()


def get_equivalent_cpes(cpe):

    # make sure equivalent CPEs are loaded
    load_equivalent_cpes()

    cpes = [cpe]
    cpe_split = cpe.split(':')
    cpe_prefix = ':'.join(cpe_split[:5]) + ':'

    for equivalent_cpe in EQUIVALENT_CPES.get(cpe_prefix, []):
        equivalent_cpe_prefix = ':'.join(equivalent_cpe.split(':')[:5]) + ':'
        if equivalent_cpe != cpe_prefix:
            cpes.append(equivalent_cpe_prefix + ':'.join(cpe_split[5:]))

    return cpes


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False, add_other_exploit_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False):
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
        cpe = search_cpes(query, count=1, threshold=software_match_threshold, keep_data_in_memory=keep_data_in_memory)

        if not cpe or not cpe[query]:
            return None
        else:
            check_str = cpe[query][0][0][8:]
            if any(char.isdigit() for char in query) and not any(char.isdigit() for char in check_str):
                return None

        cpe = cpe[query][0][0]
    elif not is_good_cpe:
        pot_matching_cpe = match_cpe23_to_cpe23_from_dict(cpe, keep_data_in_memory=keep_data_in_memory)
        if pot_matching_cpe:
            cpe = pot_matching_cpe

    # use the retrieved CPE to search for known vulnerabilities
    vulns = {}
    if is_good_cpe:
        equivalent_cpes = [cpe]  # only use provided CPE
    else:
        equivalent_cpes = get_equivalent_cpes(cpe)  # also search and use equivalent CPEs

    for cur_cpe in equivalent_cpes:
        cur_vulns = get_vulns(cur_cpe, db_cursor, ignore_general_cpe_vulns=ignore_general_cpe_vulns, add_other_exploit_refs=add_other_exploit_refs)
        for cve_id, vuln in cur_vulns.items():
            if cve_id not in vulns:
                vulns[cve_id] = vuln

    if close_cursor_after:
        db_cursor.close()

    return vulns


def search_vulns_return_cpe(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False, add_other_exploits_refs=False, is_good_cpe=False, zero_extend_versions=False, ignore_general_cpe_vulns=False):
    """Search for known vulnerabilities based on the given query and return them with their CPE"""

    cpe, pot_cpes = query, []
    if not MATCH_CPE_23_RE.match(query):
        is_good_cpe = False
        cpes = search_cpes(query, count=4, threshold=0.25, zero_extend_versions=zero_extend_versions, keep_data_in_memory=keep_data_in_memory)

        if not cpes or not cpes[query]:
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': []}}

        if cpes[query][0][1] < software_match_threshold:
            # try to create valid new CPEs from the query, e.g. in case the queried software is too recent
            new_cpes = []
            for cpe, sim in cpes[query]:
                new_cpe = create_cpe_from_base_cpe_and_query(cpe, query)
                if new_cpe and not any(is_cpe_equal(new_cpe, other[0]) for other in new_cpes):
                    new_cpes.append((new_cpe, -1))
                if not any(is_cpe_equal(cpe, other[0]) for other in new_cpes):
                    new_cpes.append((cpe, sim))

            if new_cpes:
                cpes[query] = new_cpes
            else:
                # if query has no version but CPE does, return a general CPE as related query
                base_cpe = create_base_cpe_if_versionless_query(cpes[query][0][0], query)
                if base_cpe:
                    new_cpes = set([base_cpe])
                    for i in range(1, len(cpes[query])):
                        base_cpe = create_base_cpe_if_versionless_query(cpes[query][i][0], query)
                        new_cpes.add(base_cpe)

                    return {query: {'cpe': None, 'vulns': None, 'pot_cpes': [(cpe, -1) for cpe in new_cpes]}}

            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': cpes[query]}}


        # always create related queries with supplied version number
        for i in range(len(cpes[query])):
            new_cpe = create_cpe_from_base_cpe_and_query(cpes[query][i][0], query)
            if new_cpe and not any(is_cpe_equal(new_cpe, other[0]) for other in pot_cpes):
                pot_cpes.append((new_cpe, -1))
            if not any(is_cpe_equal(cpes[query][i][0], other[0]) for other in pot_cpes):
                pot_cpes.append(cpes[query][i])

        # catch bad CPE matches
        bad_match = False
        check_str = cpes[query][0][0][8:]

        # ensure that the retrieved CPE has a number if query has a number
        if any(char.isdigit() for char in query) and not any(char.isdigit() for char in check_str):
            bad_match = True

        # if a version number is clearly detectable in query, ensure this version is somewhat reflected in the CPE
        simple_query_version = VERSION_MATCH_CPE_CREATION_RE.search(query)
        if simple_query_version:
            for char in simple_query_version.group(1):
                if char.isdigit() and char not in check_str:
                    bad_match = True
                    break

        if bad_match:
            if cpes[query][0][1] > software_match_threshold:
                return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes}}
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': cpes[query]}}

        # if query has no version but CPE does, return a general CPE as related query
        cpe_version = cpes[query][0][0].split(':')[5] if cpes[query][0][0].count(':') > 5 else ""
        if cpe_version not in ('*', '-'):
            base_cpe = create_base_cpe_if_versionless_query(cpes[query][0][0], query)
            if base_cpe:
                new_cpes = set([base_cpe])
                for i in range(1, len(cpes[query])):
                    base_cpe = create_base_cpe_if_versionless_query(cpes[query][i][0], query)
                    new_cpes.add(base_cpe)

                return {query: {'cpe': None, 'vulns': None, 'pot_cpes': [(cpe, -1) for cpe in new_cpes]}}

        cpe = cpes[query][0][0]

    # use the retrieved CPE to search for known vulnerabilities
    vulns = {}
    if is_good_cpe:
        equivalent_cpes = [cpe]  # only use provided CPE
    else:
        equivalent_cpes = get_equivalent_cpes(cpe)  # also search and use equivalent CPEs

    for cur_cpe in equivalent_cpes:
        cur_vulns = search_vulns(cur_cpe, db_cursor, software_match_threshold, keep_data_in_memory, add_other_exploits_refs, True, ignore_general_cpe_vulns)
        for cve_id, vuln in cur_vulns.items():
            if cve_id not in vulns:
                vulns[cve_id] = vuln

    return {query: {'cpe': '/'.join(equivalent_cpes), 'vulns': vulns, 'pot_cpes': pot_cpes}}


def parse_args():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(description="Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)")
    parser.add_argument("-u", "--update", action="store_true", help="Download the latest version of the the local vulnerability and software database")
    parser.add_argument("--full-update", action="store_true", help="Fully (re)build the local vulnerability and software database")
    parser.add_argument("-k", "--api-key", type=str, help="NVD API key to use for updating the local vulnerability and software database")
    parser.add_argument("-f", "--format", type=str, default="txt", choices={"txt", "json"}, help="Output format, either 'txt' or 'json' (default: 'txt')")
    parser.add_argument("-o", "--output", type=str, help="File to write found vulnerabilities to")
    parser.add_argument("-q", "--query", dest="queries", metavar="QUERY", action="append", help="A query, either software title like 'Apache 2.4.39' or a CPE 2.3 string")
    parser.add_argument("--cpe-search-threshold", type=float, default=CPE_SEARCH_THRESHOLD, help="Similarity threshold used for retrieving a CPE via the cpe_search tool")
    parser.add_argument("--ignore-general-cpe-vulns", action="store_true", help="Ignore vulnerabilities that only affect a general CPE (i.e. without version)")

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update:
        parser.print_help()
    return args


def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.update == True:
        from updater import run as run_updater
        run_updater(False, args.api_key)
    elif args.full_update == True:
        from updater import run as run_updater
        run_updater(True, args.api_key)

    if not args.queries:
        return

    # get handle for vulnerability database
    db_conn_file = sqlite3.connect(DATABASE_FILE)
    # db_conn_mem = sqlite3.connect(':memory:')
    # db_conn_file.backup(db_conn_mem)
    # db_cursor = db_conn_mem.cursor()
    db_cursor = db_conn_file.cursor()

    # retrieve known vulnerabilities for every query and print them
    vulns = {}
    out_string = ''
    for query in args.queries:
        # if current query is not already a CPE, retrieve a CPE that matches the query
        cpe = query
        if not MATCH_CPE_23_RE.match(query):
            cpe = search_cpes(query, count=1, threshold=args.cpe_search_threshold)

            found_cpe = True
            if not cpe or not cpe[query]:
                found_cpe = False
            else:
                check_str = cpe[query][0][0][8:]
                if any(char.isdigit() for char in query) and not any(char.isdigit() for char in check_str):
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

            cpe = cpe[query][0][0]
        else:
            matching_cpe = match_cpe23_to_cpe23_from_dict(cpe)
            if matching_cpe:
                cpe = matching_cpe

        # use the retrieved CPE to search for known vulnerabilities
        vulns[query] = {}
        equivalent_cpes = get_equivalent_cpes(cpe)

        if args.format.lower() == 'txt':
            if not args.output:
                print()
                printit('[+] %s (%s)' % (query, '/'.join(equivalent_cpes)), color=BRIGHT_BLUE)

        for cur_cpe in equivalent_cpes:
            cur_vulns = search_vulns(cur_cpe, db_cursor, args.cpe_search_threshold, False, False, True, args.ignore_general_cpe_vulns)
            for cve_id, vuln in cur_vulns.items():
                if cve_id not in vulns[query]:
                    vulns[query][cve_id] = vuln

        # print found vulnerabilities
        if args.format.lower() == 'txt':
            if not args.output:
                print_vulns(vulns[query])
            else:
                out_string += '\n' + '[+] %s (%s)\n' % (query, cpe)
                out_string += print_vulns(vulns[query], to_string=True)
        else:
            cpe_vulns = vulns[query]
            cve_ids_sorted = sorted(list(cpe_vulns), key=lambda cve_id: float(cpe_vulns[cve_id]["cvss"]), reverse=True)
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


if __name__ == "__main__":
    main()
