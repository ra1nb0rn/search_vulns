#!/usr/bin/env python3

import argparse
from collections import OrderedDict
import json
import os
import re
import sys
import threading

from cpe_version import CPEVersion
from cpe_search.database_wrapper_functions import *
from cpe_search.cpe_search import (
    is_cpe_equal,
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    create_cpes_from_base_cpe_and_query,
    create_base_cpe_if_versionless_query,
    get_possible_versions_in_query
)
from cpe_search.cpe_search import _load_config as _load_config_cpe_search

DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config.json')
MATCH_CPE_23_RE = re.compile(r'cpe:2\.3:[aoh](:[^:]+){2,10}')
CPE_SEARCH_THRESHOLD = 0.72
EQUIVALENT_CPES = {}
LOAD_EQUIVALENT_CPES_MUTEX = threading.Lock()
DEDUP_LINEBREAKS_RE_1 = re.compile(r'(\r\n)+')
DEDUP_LINEBREAKS_RE_2 = re.compile(r'\n+')
CPE_COMPARISON_STOP_CHARS_RE = re.compile(r'[\+\-\_\~]')

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


def is_cpe_included_from_field(cpe1, cpe2, field=6):
    '''Return True if cpe1 is included in cpe2 starting from the provided field'''

    cpe1_remainder_fields = cpe1.split(':')[field:]
    cpe2_remainder_fields = cpe2.split(':')[field:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        # CPE wildcards
        if cpe1_remainder_fields[i] in ('*', '-'):
            continue
        if cpe2_remainder_fields[i] in ('*', '-'):
            continue

        # remove irrelevant chars
        cpe1_remainder_fields[i] = CPE_COMPARISON_STOP_CHARS_RE.sub('', cpe1_remainder_fields[i])
        cpe2_remainder_fields[i] = CPE_COMPARISON_STOP_CHARS_RE.sub('', cpe2_remainder_fields[i])

        # alpha and beta version abbreviations
        if cpe1_remainder_fields[i] == 'alpha' and cpe1_remainder_fields[i] == 'a':
            continue
        if cpe2_remainder_fields[i] == 'alpha' and cpe1_remainder_fields[i] == 'a':
            continue
        if cpe1_remainder_fields[i] == 'beta' and cpe1_remainder_fields[i] == 'b':
            continue
        if cpe2_remainder_fields[i] == 'beta' and cpe1_remainder_fields[i] == 'b':
            continue

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False

    return True


def is_cpe_included_after_version(cpe1, cpe2):
    '''Return True if cpe1 is included in cpe2 starting after the version'''

    return is_cpe_included_from_field(cpe1, cpe2)


def has_cpe_lower_versions(cpe1, cpe2):
    '''Return True if cpe1 is considered to have a lower product version than cpe2'''

    cpe1_remainder_fields = cpe1.split(':')[5:]
    cpe2_remainder_fields = cpe2.split(':')[5:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        if cpe1_remainder_fields[i] in ('*', '-'):
            continue
        if cpe2_remainder_fields[i] in ('*', '-'):
            continue

        if CPEVersion(cpe1_remainder_fields[i]) > CPEVersion(cpe2_remainder_fields[i]):
            return False
    return True


def is_more_specific_cpe_contained(vuln_cpe, cve_cpes):
    '''
    Return boolean whether a more specific CPE than vuln_cpe
    is contained in the CVE's list of affected CPEs.
    '''

    for vuln_other_cpe in cve_cpes:
        if vuln_cpe != vuln_other_cpe:
            if is_cpe_included_from_field(vuln_cpe, vuln_other_cpe, 5):
                # assume the number of fields is the same for both, since they're official NVD CPEs
                vuln_cpe_fields, vuln_other_cpe_fields = vuln_cpe.split(':'), vuln_other_cpe.split(':')
                for i in range(len(vuln_other_cpe_fields)-1, -1, -1):
                    if (not CPEVersion(vuln_cpe_fields[i])) and (not CPEVersion(vuln_other_cpe_fields[i])):
                        continue
                    elif CPEVersion(vuln_other_cpe_fields[i]):
                        return True
                    else:
                        break
    return False


def get_vuln_details(db_cursor, vulns, add_other_exploit_refs):
    '''Collect more detailed information about the given vulns and return it'''

    detailed_vulns = {}
    for vuln_info in vulns:
        vuln, match_reason = vuln_info
        cve_id = vuln
        if cve_id in detailed_vulns:
            continue

        query = 'SELECT edb_ids, description, published, last_modified, cvss_version, base_score, vector FROM cve WHERE cve_id = ?'
        db_cursor.execute(query, (cve_id,))
        edb_ids, descr, publ, last_mod, cvss_ver, score, vector = db_cursor.fetchone()
        detailed_vulns[cve_id] = {"id": cve_id, "description": descr, "published": str(publ), "modified": str(last_mod),
                                  "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id, "cvss_ver": str(float(cvss_ver)),
                                  "cvss": str(float(score)), "cvss_vec": vector, 'vuln_match_reason': match_reason}

        edb_ids = edb_ids.strip()
        if edb_ids:
            detailed_vulns[cve_id]["exploits"] = []
            for edb_id in edb_ids.split(","):
                detailed_vulns[cve_id]["exploits"].append("https://www.exploit-db.com/exploits/%s" % edb_id)

        # add other exploit references
        if add_other_exploit_refs:
            # from NVD
            query = 'SELECT exploit_ref FROM nvd_exploits_refs_view WHERE cve_id = ?'
            nvd_exploit_refs = ''
            db_cursor.execute(query, (cve_id,))
            if db_cursor:
                nvd_exploit_refs = db_cursor.fetchall()
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
            poc_in_github_refs = ''
            db_cursor.execute(query, (cve_id,))
            if db_cursor:
                poc_in_github_refs = db_cursor.fetchall()
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


def _is_version_start_end_matching(cpe_version, cpe_subversion, version_start, version_start_incl, version_end, version_end_incl):
    """Return boolean whether the provided CPE version lies within the provided range modifiers"""

    version_start = CPEVersion(version_start)
    version_end = CPEVersion(version_end)

    # combine version and subversion if NVD merged both for version_end as well
    if version_end and len(version_end.get_version_sections()) > len(cpe_version.get_version_sections()):
        cpe_version = (cpe_version + cpe_subversion)

    if version_start and version_end:
        if version_start_incl == True and version_end_incl == True:
            return version_start <= cpe_version <= version_end
        elif version_start_incl == True and version_end_incl == False:
            return version_start <= cpe_version < version_end
        elif version_start_incl == False and version_end_incl == True:
            return version_start < cpe_version <= version_end
        else:
            return version_start < cpe_version < version_end
    elif version_start:
        if version_end_incl == True:
            return version_start <= cpe_version
        elif version_end_incl == False:
            return version_start < cpe_version
    elif version_end:
        if version_end_incl == True:
            return cpe_version <= version_end
        elif version_end_incl == False:
            return cpe_version < version_end

    return False


def get_vulns(cpe, db_cursor, ignore_general_cpe_vulns=False, include_single_version_vulns=False, add_other_exploit_refs=False):
    """Get known vulnerabilities for the given CPE 2.3 string"""

    cpe_parts = cpe.split(':')
    cpe_version = CPEVersion(cpe_parts[5])
    cpe_subversion = CPEVersion(cpe_parts[6])
    vulns = []

    general_cpe_prefix = ':'.join(cpe.split(':')[:5]) + ':'
    query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
             'is_cpe_version_end_including FROM cve_cpe WHERE cpe LIKE ?')
    db_cursor.execute(query, (general_cpe_prefix + '%%', ))
    general_cpe_nvd_data = set()
    if db_cursor:
        general_cpe_nvd_data =  set(db_cursor.fetchall())
    general_cpe_nvd_data_structered = {}

    for cve_cpe_entry in general_cpe_nvd_data:
        if cve_cpe_entry[0] not in general_cpe_nvd_data_structered:
            general_cpe_nvd_data_structered[cve_cpe_entry[0]] = []
        general_cpe_nvd_data_structered[cve_cpe_entry[0]].append(cve_cpe_entry)

    for cve_id, cve_cpe_data in general_cpe_nvd_data_structered.items():
        cve_cpes = [cve_cpe_entry[1] for cve_cpe_entry in cve_cpe_data]
        for cve_cpe_entry in cve_cpe_data:
            vuln_cpe = cve_cpe_entry[1]
            version_start, version_start_incl = cve_cpe_entry[2:4]
            version_end, version_end_incl = cve_cpe_entry[4:]

            is_cpe_vuln, bad_nvd_entry = False, False
            match_reason = ''
            is_cpe_vuln = is_cpe_included_from_field(cpe, vuln_cpe, 5)

            if cpe_version and (version_start or version_end):
                # additionally check if version matches range
                is_cpe_vuln = _is_version_start_end_matching(cpe_version, cpe_subversion, version_start, version_start_incl, version_end, version_end_incl)
                match_reason = 'version_in_range'
            elif is_cpe_vuln:
                # check if the NVD's affected products entry for the CPE is considered faulty
                bad_nvd_entry = is_more_specific_cpe_contained(vuln_cpe, cve_cpes)

                # check for general CPE vuln match
                if not CPEVersion(vuln_cpe.split(':')[5]):
                    if not cpe_version:
                        match_reason = 'general_cpe_but_ok'
                    else:
                        match_reason = 'general_cpe'
                        if ignore_general_cpe_vulns:
                            is_cpe_vuln = False
            elif include_single_version_vulns:
                if len(cve_cpes) == 1 and has_cpe_lower_versions(cpe, vuln_cpe):
                    is_cpe_vuln = True
                    match_reason = 'single_higher_version_cpe'

            # final check that everything after the version field matches in the vuln's CPE
            if is_cpe_vuln:
                if cpe.count(':') > 5 and vuln_cpe.count(':') > 5:
                    if not is_cpe_included_after_version(cpe, vuln_cpe):
                        is_cpe_vuln = False

            if is_cpe_vuln and not bad_nvd_entry:
                vulns.append((cve_id, match_reason))
                break

    # retrieve more information about the found vulns, e.g. CVSS scores and possible exploits
    return get_vuln_details(db_cursor, vulns, add_other_exploit_refs)


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


def load_equivalent_cpes(config):
    """Load dictionary containing CPE equivalences"""

    LOAD_EQUIVALENT_CPES_MUTEX.acquire()
    if not EQUIVALENT_CPES:
        # first add official deprecation information from the NVD
        with open(config['cpe_search']['DEPRECATED_CPES_FILE'], "r") as f:
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
        with open(config['MAN_EQUIVALENT_CPES_FILE']) as f:
            manual_equivalent_cpes = json.loads(f.read())

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


def get_equivalent_cpes(cpe, config):

    # make sure equivalent CPEs are loaded
    load_equivalent_cpes(config)

    cpes = [cpe]
    cpe_split = cpe.split(':')
    cpe_prefix = ':'.join(cpe_split[:5]) + ':'
    cpe_version = cpe_split[5]
    cpe_subversion = cpe_split[6]

    # if version part consists of more than one version parts, split into two CPE fields
    cpe_version_sections = CPEVersion(cpe_version).get_version_sections()
    if len(cpe_version_sections) > 1 and cpe_subversion in ('*', '', '-'):
        cpe_split[5] = ''.join(cpe_version_sections[:-1])
        cpe_split[6] = cpe_version_sections[-1]
        cpes.append(':'.join(cpe_split))

    # if CPE has subversion, create equivalent query with main version and subversion combined in one CPE field
    if cpe_subversion not in ('*', '', '-'):
        cpe_split[5] = cpe_version + '-' + cpe_subversion
        cpe_split[6] = '*'
        cpes.append(':'.join(cpe_split))

    equiv_cpes = cpes.copy()
    for cpe in cpes:
        for equivalent_cpe in EQUIVALENT_CPES.get(cpe_prefix, []):
            equivalent_cpe_prefix = ':'.join(equivalent_cpe.split(':')[:5]) + ':'
            if equivalent_cpe != cpe_prefix:
                equiv_cpes.append(equivalent_cpe_prefix + ':'.join(cpe_split[5:]))

    return equiv_cpes


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False, add_other_exploit_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, include_single_version_vulns=False, config=None):
    """Search for known vulnerabilities based on the given query"""

    # create DB handle if not given
    if not config:
        config = _load_config()
    close_cursor_after = False
    if not db_cursor:
        db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
        if keep_data_in_memory and config['DATABASE']['TYPE'] == 'sqlite':
            db_conn_mem = sqlite3.connect(':memory:')
            db_conn.backup(db_conn_mem)
            db_cursor = db_conn_mem.cursor()
        else:
            db_cursor = db_conn.cursor()
        close_cursor_after = True

    # if given query is not already a CPE, retrieve a CPE that matches the query
    query = query.strip()
    cpe = query
    if not MATCH_CPE_23_RE.match(query):
        cpe = search_cpes(query, count=1, threshold=software_match_threshold, keep_data_in_memory=keep_data_in_memory, config=config['cpe_search'])

        if not cpe or not cpe[query]:
            return None
        else:
            check_str = cpe[query][0][0][8:]
            if any(char.isdigit() for char in query) and not any(char.isdigit() for char in check_str):
                return None

        cpe = cpe[query][0][0]
    elif not is_good_cpe:
        pot_matching_cpe = match_cpe23_to_cpe23_from_dict(cpe, keep_data_in_memory=keep_data_in_memory, config=config['cpe_search'])
        if pot_matching_cpe:
            cpe = pot_matching_cpe

    # use the retrieved CPE to search for known vulnerabilities
    vulns = {}
    if is_good_cpe:
        equivalent_cpes = [cpe]  # only use provided CPE
    else:
        equivalent_cpes = get_equivalent_cpes(cpe, config)  # also search and use equivalent CPEs

    for cur_cpe in equivalent_cpes:
        cur_vulns = get_vulns(cur_cpe, db_cursor, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, add_other_exploit_refs=add_other_exploit_refs)
        for cve_id, vuln in cur_vulns.items():
            if cve_id not in vulns:
                vulns[cve_id] = vuln

    if close_cursor_after:
        db_cursor.close()

    return vulns


def search_vulns_return_cpe(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False, add_other_exploits_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, include_single_version_vulns=False, config=None):
    """Search for known vulnerabilities based on the given query and return them with their CPE"""

    if not config:
        config = _load_config()

    query = query.strip()
    cpe, pot_cpes = query, []
    if not MATCH_CPE_23_RE.match(query):
        is_good_cpe = False
        cpes = search_cpes(query, count=5, threshold=0.25, keep_data_in_memory=keep_data_in_memory, config=config['cpe_search'])

        if not cpes or not cpes[query]:
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': []}}

        # always create related queries with supplied version number
        versions_in_query = get_possible_versions_in_query(query)
        for cpe, sim in cpes[query]:
            new_cpes = create_cpes_from_base_cpe_and_query(cpe, query)
            for new_cpe in new_cpes:
                # do not overwrite sim score of an existing CPE
                if any(is_cpe_equal(new_cpe, existing_cpe[0]) for existing_cpe in cpes[query]):
                    continue
                # only add CPE if it was not seen before
                if new_cpe and not any(is_cpe_equal(new_cpe, other[0]) for other in pot_cpes):
                    pot_cpes.append((new_cpe, -1))

            if not any(is_cpe_equal(cpe, other[0]) for other in pot_cpes):
                pot_cpes.append((cpe, sim))

        # always create related queries without version number if query is versionless
        versionless_cpe_inserts, new_idx = [], 0
        for cpe, _ in pot_cpes:
            base_cpe = create_base_cpe_if_versionless_query(cpe, query)
            if base_cpe:
                if ((not any(is_cpe_equal(base_cpe, other[0]) for other in pot_cpes)) and
                     not any(is_cpe_equal(base_cpe, other[0][0]) for other in versionless_cpe_inserts)):
                    versionless_cpe_inserts.append(((base_cpe, -1), new_idx))
                    new_idx += 1
            new_idx += 1

        for new_cpe, idx in versionless_cpe_inserts:
            pot_cpes.insert(idx, new_cpe)

        if cpes[query][0][1] < software_match_threshold:
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes}}

        # catch bad CPE matches
        bad_match = False
        check_str = cpes[query][0][0][8:]

        # ensure that the retrieved CPE has a number if query has a number
        if any(char.isdigit() for char in query) and not any(char.isdigit() for char in check_str):
            bad_match = True

        # if a version number is clearly detectable in query, ensure this version is somewhat reflected in the CPE
        if not bad_match:
            cpe_has_matching_version = False
            for possible_version in versions_in_query:
                # ensure version has at least two parts to avoid using a short version for checking
                if '.' not in possible_version:
                    continue

                idx_pos_ver, idx_check_str = 0, 0
                while idx_pos_ver < len(possible_version) and idx_check_str < len(check_str):
                    while idx_pos_ver < len(possible_version) and not possible_version[idx_pos_ver].isdigit():
                        idx_pos_ver += 1
                    if idx_pos_ver < len(possible_version) and possible_version[idx_pos_ver] == check_str[idx_check_str]:
                        idx_pos_ver += 1
                    idx_check_str += 1

                if idx_pos_ver == len(possible_version):
                    cpe_has_matching_version = True
                    break
            if not cpe_has_matching_version:
                bad_match = True

        if bad_match:
            if cpes[query][0][1] > software_match_threshold:
                return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes}}
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': cpes[query]}}

        # also catch bad match if query is versionless, but retrieved CPE is not
        cpe_version = cpes[query][0][0].split(':')[5] if cpes[query][0][0].count(':') > 5 else ""
        if cpe_version not in ('*', '-'):
            base_cpe = create_base_cpe_if_versionless_query(cpes[query][0][0], query)
            if base_cpe:
                # remove CPEs from related queries that have a version
                pot_cpes_versionless = []
                for i, (pot_cpe, score) in enumerate(pot_cpes):
                    cpe_version_iter = pot_cpe.split(':')[5] if pot_cpe.count(':') > 5 else ""
                    if cpe_version_iter in ('', '*', '-'):
                        pot_cpes_versionless.append((pot_cpe, score))

                return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes_versionless}}

        cpe = cpes[query][0][0]

    # use the retrieved CPE to search for known vulnerabilities
    vulns = {}
    if is_good_cpe:
        equivalent_cpes = [cpe]  # only use provided CPE
    else:
        equivalent_cpes = get_equivalent_cpes(cpe, config)  # also search and use equivalent CPEs

    for cur_cpe in equivalent_cpes:
        cur_vulns = search_vulns(cur_cpe, db_cursor, software_match_threshold, keep_data_in_memory, add_other_exploits_refs, True, ignore_general_cpe_vulns, include_single_version_vulns, config)
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
    parser.add_argument("--include-single-version-vulns", action="store_true", help="Include vulnerabilities that only affect one specific version of a product when querying a lower version")
    parser.add_argument("-c", "--config", type=str, default=DEFAULT_CONFIG_FILE, help="A config file to use (default: config.json)")

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update:
        parser.print_help()
    return args


def _load_config(config_file=DEFAULT_CONFIG_FILE):
    """Load config from file"""

    config = _load_config_cpe_search(config_file)
    config['cpe_search']['DATABASE'] = config['DATABASE']
    config['cpe_search']['NVD_API_KEY'] = config['NVD_API_KEY']

    return config


def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.update == True:
        from updater import run as run_updater
        run_updater(False, args.api_key, args.config)
    elif args.full_update == True:
        from updater import run as run_updater
        run_updater(True, args.api_key, args.config)

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
        if not MATCH_CPE_23_RE.match(query):
            cpe = search_cpes(query, count=1, threshold=args.cpe_search_threshold, config=config['cpe_search'])

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
            matching_cpe = match_cpe23_to_cpe23_from_dict(cpe, config=config['cpe_search'])
            if matching_cpe:
                cpe = matching_cpe

        # use the retrieved CPE to search for known vulnerabilities
        vulns[query] = {}
        equivalent_cpes = get_equivalent_cpes(cpe, config)

        if args.format.lower() == 'txt':
            if not args.output:
                print()
                printit('[+] %s (%s)' % (query, '/'.join(equivalent_cpes)), color=BRIGHT_BLUE)

        for cur_cpe in equivalent_cpes:
            cur_vulns = search_vulns(cur_cpe, db_cursor, args.cpe_search_threshold, False, False, True, args.ignore_general_cpe_vulns, args.include_single_version_vulns, config)
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
