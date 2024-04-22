#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import re
import sys
import threading

from cpe_version import CPEVersion
from cpe_search.database_wrapper_functions import *
from cpe_search.cpe_search import (
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    cpe_matches_query,
    MATCH_CPE_23_RE
)
from cpe_search.cpe_search import _load_config as _load_config_cpe_search

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CONFIG_FILE = os.path.join(PROJECT_DIR, 'config.json')
MAN_EQUIVALENT_CPES_FILE = os.path.join(PROJECT_DIR, os.path.join('resources', 'man_equiv_cpes.json'))
DEBIAN_EQUIV_CPES_FILE = os.path.join(PROJECT_DIR, os.path.join('resources', 'debian_equiv_cpes.json'))
VERSION_FILE = os.path.join(PROJECT_DIR, 'version.txt')
CPE_SEARCH_THRESHOLD_MATCH = 0.72
EQUIVALENT_CPES = {}
LOAD_EQUIVALENT_CPES_MUTEX = threading.Lock()
DEDUP_LINEBREAKS_RE_1 = re.compile(r'(\r\n)+')
DEDUP_LINEBREAKS_RE_2 = re.compile(r'\n+')
CPE_COMPARISON_STOP_CHARS_RE = re.compile(r'[\+\-\_\~]')
NUMERIC_VERSION_RE = re.compile(r'[\d\.]+')
NON_ALPHANUMERIC_SPLIT_RE = re.compile(r'[^a-zA-Z]')
CPE_SEARCH_COUNT = 5

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
        if cpe1_remainder_fields[i] == 'alpha' and cpe2_remainder_fields[i] == 'a':
            continue
        if cpe2_remainder_fields[i] == 'alpha' and cpe1_remainder_fields[i] == 'a':
            continue
        if cpe1_remainder_fields[i] == 'beta' and cpe2_remainder_fields[i] == 'b':
            continue
        if cpe2_remainder_fields[i] == 'beta' and cpe1_remainder_fields[i] == 'b':
            continue

        if field + i == 5 or field + i == 6:  # CPE version or subversion field
            if CPEVersion(cpe1_remainder_fields[i]) == CPEVersion(cpe2_remainder_fields[i]):
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
                    vuln_cpe_field_version = CPEVersion(vuln_cpe_fields[i])
                    vuln_other_cpe_field_version = CPEVersion(vuln_other_cpe_fields[i])
                    if (not vuln_cpe_field_version) and (not vuln_other_cpe_field_version):
                        continue
                    elif (not vuln_cpe_field_version) and vuln_other_cpe_field_version:
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

        query = 'SELECT edb_ids, description, published, last_modified, cvss_version, base_score, vector, cisa_known_exploited FROM cve WHERE cve_id = ?'
        db_cursor.execute(query, (cve_id,))
        edb_ids, descr, publ, last_mod, cvss_ver, score, vector, cisa_known_exploited = db_cursor.fetchone()
        detailed_vulns[cve_id] = {"id": cve_id, "description": descr, "published": str(publ), "modified": str(last_mod),
                                  "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id, "cvss_ver": str(float(cvss_ver)),
                                  "cvss": str(float(score)), "cvss_vec": vector, "vuln_match_reason": match_reason,
                                  "cisa_known_exploited": bool(cisa_known_exploited)}

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


def _is_version_start_end_matching(cpe_parts, version_start, version_start_incl, version_end, version_end_incl):
    """Return boolean whether the provided CPE version lies within the provided range modifiers"""

    version_start = CPEVersion(version_start)
    version_end = CPEVersion(version_end)

    # combine version and subversion if NVD merged both for version_end as well
    cpe_product = cpe_parts[4]
    cpe_version, cpe_subversion = CPEVersion(cpe_parts[5]), CPEVersion(cpe_parts[6])
    if version_end:
        version_end_sections = version_end.get_version_sections()
        cpe_version_subsections = cpe_version.get_version_sections()
        if len(version_end_sections) > len(cpe_version_subsections):
            # if queried CPE has a subversion / patch-level, merge this with the base version
            if cpe_subversion:
                cpe_version = (cpe_version + cpe_subversion)
                cpe_version_sections = cpe_version.get_version_sections()
                if len(cpe_version_sections) != len(version_end_sections):
                    # try to adjust cpe_version, such that it ideally has the same number of sections as version_end
                    final_cpe_version_sections = []
                    i, j = 0, 0
                    while i < len(cpe_version_sections) and j < len(version_end_sections):
                        # if same version type (numeric or alphanumeric), use version field, otherwise leave it out
                        cpe_version_section_numeric_match = NUMERIC_VERSION_RE.match(cpe_version_sections[i])
                        version_end_section_numeric_match = NUMERIC_VERSION_RE.match(version_end_sections[j])

                        if cpe_version_section_numeric_match and version_end_section_numeric_match:
                            final_cpe_version_sections.append(cpe_version_sections[i])
                            j += 1
                        elif not cpe_version_section_numeric_match and not version_end_section_numeric_match:
                            final_cpe_version_sections.append(cpe_version_sections[i])
                            j += 1
                        i += 1
                    cpe_version = CPEVersion(' '.join(final_cpe_version_sections))
            else:
                # check if the version_end string starts with the product name
                # (e.g. 'esxi70u1c-17325551' from https://nvd.nist.gov/vuln/detail/CVE-2020-3999)
                product_parts = [word.strip() for word in NON_ALPHANUMERIC_SPLIT_RE.split(cpe_product)]
                cpe_version_sections = cpe_version.get_version_sections()
                for part in product_parts:
                    # ... if it does, prefix cpe_version with the CPE product name
                    if str(version_end).startswith(part):
                        if '.' not in str(version_end):
                            cpe_version = CPEVersion(str(cpe_version).replace('.', ''))
                        cpe_version = CPEVersion(part) + cpe_version
                        break

        # fallback if subversion merging did not work
        if not cpe_version:
            cpe_version = CPEVersion(cpe_parts[5])
    else:
        # set a max version if end is not given explicitly
        version_end = CPEVersion('~' * 256)

    # check if version start or end matches exactly, otherwise return if in range
    if version_start_incl and cpe_version == version_start:
        return True
    if version_end_incl and cpe_version == version_end:
        return True
    return version_start < cpe_version < version_end


def get_vulns(cpe, db_cursor, ignore_general_cpe_vulns=False, include_single_version_vulns=False, add_other_exploit_refs=False):
    """Get known vulnerabilities for the given CPE 2.3 string"""

    cpe_parts = cpe.split(':')
    cpe_version = CPEVersion(cpe_parts[5])
    vulns = []

    general_cpe_prefix_query = ':'.join(cpe.split(':')[:5]) + ':'
    if 'mariadb' in str(type(db_cursor)):  # backslashes have to be escaped for MariaDB
        general_cpe_prefix_query = general_cpe_prefix_query.replace('\\', '\\\\')

    query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
             'is_cpe_version_end_including FROM cve_cpe WHERE cpe LIKE ?')
    db_cursor.execute(query, (general_cpe_prefix_query + '%%', ))
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
                is_cpe_vuln = _is_version_start_end_matching(cpe_parts, version_start, version_start_incl, version_end, version_end_incl)
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
            print_str += " (" + MAGENTA + 'CVSSv' + vuln_node['cvss_ver'] + '/' + str(vuln_node["cvss"]) + SANE + ")"
            if vuln_node['cisa_known_exploited']:
                print_str += " (" + RED + "Actively exploited" + SANE + ")"
        else:
            print_str = vuln_node["id"]
            print_str += " ("'CVSSv' + vuln_node['cvss_ver'] + '/' + str(vuln_node["cvss"]) + ")"
            if vuln_node['cisa_known_exploited']:
                print_str += " (Actively exploited)"
        print_str += ': '+description+'\n'

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
        equivalent_cpes_dicts_list, deprecated_cpes = [], {}

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

                if cpe_short not in deprecated_cpes:
                    deprecated_cpes[cpe_short] = deprecations_short
                else:
                    deprecated_cpes[cpe_short] = list(set(deprecated_cpes[cpe_short] + deprecations_short))

                for deprecatedby_cpe_short in deprecations_short:
                    if deprecatedby_cpe_short not in EQUIVALENT_CPES:
                        deprecated_cpes[deprecatedby_cpe_short] = [cpe_short]
                    elif cpe_short not in EQUIVALENT_CPES[deprecatedby_cpe_short]:
                        deprecated_cpes[deprecatedby_cpe_short].append(cpe_short)
        equivalent_cpes_dicts_list.append(deprecated_cpes)

        # then manually add further information
        with open(MAN_EQUIVALENT_CPES_FILE) as f:
            manual_equivalent_cpes = json.loads(f.read())
        equivalent_cpes_dicts_list.append(manual_equivalent_cpes)

        # finally add further information from https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/master/data/CPE/aliases
        with open(DEBIAN_EQUIV_CPES_FILE) as f:
            debian_equivalent_cpes = json.loads(f.read())
        equivalent_cpes_dicts_list.append(debian_equivalent_cpes)

        # unite the infos from the different sources
        for equivalent_cpes_dict in equivalent_cpes_dicts_list:
            for equiv_cpe, other_equiv_cpes in equivalent_cpes_dict.items():
                if equiv_cpe not in EQUIVALENT_CPES:
                    EQUIVALENT_CPES[equiv_cpe] = other_equiv_cpes
                else:
                    EQUIVALENT_CPES[equiv_cpe].extend(other_equiv_cpes)

        # ensure that each entry and its equivalents are properly linked in both directions
        for equiv_cpe in list(EQUIVALENT_CPES):
            other_equiv_cpes = list(EQUIVALENT_CPES[equiv_cpe])
            for other_equiv_cpe in other_equiv_cpes:
                other_relevant_equiv_cpes = [equiv_cpe if cpe == other_equiv_cpe else cpe for cpe in other_equiv_cpes]
                if other_equiv_cpe not in EQUIVALENT_CPES:
                    EQUIVALENT_CPES[other_equiv_cpe] = other_relevant_equiv_cpes
                elif equiv_cpe not in EQUIVALENT_CPES[other_equiv_cpe]:
                    EQUIVALENT_CPES[other_equiv_cpe].extend(other_relevant_equiv_cpes)

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
    for cur_cpe in cpes:
        cur_cpe_split = cur_cpe.split(':')
        for equivalent_cpe in EQUIVALENT_CPES.get(cpe_prefix, []):
            equivalent_cpe_prefix = ':'.join(equivalent_cpe.split(':')[:5]) + ':'
            if equivalent_cpe != cpe_prefix:
                equiv_cpes.append(equivalent_cpe_prefix + ':'.join(cur_cpe_split[5:]))

    return equiv_cpes


def retrieve_eol_info(cpe, db_cursor):
    """Retrieve information from endoflife.date whether the provided version is eol or outdated"""

    version_status = {}
    cpe_split = cpe.split(':')
    cpe_prefix, query_version = ':'.join(cpe_split[:5]) + ':', CPEVersion(cpe_split[5])
    eol_releases = []
    db_cursor.execute('SELECT eold_id, version_start, version_latest, eol_info FROM eol_date_data WHERE cpe_prefix = ? ORDER BY release_id DESC', (cpe_prefix,))
    if db_cursor:
        eol_releases = db_cursor.fetchall()

    latest = ''
    for i, release in enumerate(eol_releases):
        # set up release information
        eol_ref = 'https://endoflife.date/' + release[0]
        release_start, release_end = CPEVersion(release[1]), CPEVersion(release[2])
        release_eol, now = release[3], datetime.datetime.now()
        if release_eol not in ('true', 'false'):
            release_eol = datetime.datetime.strptime(release_eol, '%Y-%m-%d')
        elif release_eol != 'true':
            release_eol = False

        # set latest version in first iteration
        if not latest:
            latest = release_end

        if not query_version:
            if release_eol and now >= release_eol:
                version_status = {'status': 'eol', 'latest': str(latest), 'ref': eol_ref}
            else:
                version_status = {'status': 'N/A', 'latest': str(latest), 'ref': eol_ref}
        else:
            # check query version status
            if query_version >= release_end:
                if release_eol and (release_eol == 'true' or now >= release_eol):
                    version_status = {'status': 'eol', 'latest': str(latest), 'ref': eol_ref}
                else:
                    version_status = {'status': 'current', 'latest': str(latest), 'ref': eol_ref}
            elif ((release_start <= query_version < release_end) or
                  (i == len(eol_releases) - 1 and query_version <= release_start)):
                if release_eol and (release_eol == 'true' or now >= release_eol):
                    version_status = {'status': 'eol', 'latest': str(latest), 'ref': eol_ref}
                else:
                    version_status = {'status': 'outdated', 'latest': str(latest), 'ref': eol_ref}

        if version_status:
            break

    return version_status


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD_MATCH, add_other_exploit_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, include_single_version_vulns=False, config=None):
    """Search for known vulnerabilities based on the given query"""

    # create DB handle if not given
    if not config:
        config = _load_config()
    close_cursor_after = False
    if not db_cursor:
        db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
        db_cursor = db_conn.cursor()
        close_cursor_after = True

    # if given query is not already a CPE, try to retrieve a CPE that matches
    # the query or create alternative CPEs that could match the query
    query_stripped = query.strip()
    cpe, pot_cpes = query_stripped, []
    if not MATCH_CPE_23_RE.match(query_stripped):
        is_good_cpe = False
        cpe_search_results = search_cpes(query_stripped, count=CPE_SEARCH_COUNT, threshold=software_match_threshold, config=config['cpe_search'])

        if not cpe_search_results['cpes']:
            return {query: {'cpe': None, 'vulns': {}, 'pot_cpes': cpe_search_results['pot_cpes'], 'version_status': {}}}

        cpes = cpe_search_results['cpes']
        pot_cpes = cpe_search_results['pot_cpes']

        if not cpes:
            return {query: {'cpe': None, 'vulns': {}, 'pot_cpes': pot_cpes, 'version_status': {}}}

        cpe = cpes[0][0]

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

    # add outdated software / endoflife.date information
    eol_info = {}
    for equiv_cpe in equivalent_cpes:
        eol_info = retrieve_eol_info(equiv_cpe, db_cursor)
        if eol_info:
            break

    if close_cursor_after:
        db_cursor.close()
        db_conn.close()

    return {query: {'cpe': '/'.join(equivalent_cpes), 'vulns': vulns, 'pot_cpes': pot_cpes, 'version_status': eol_info}}


def parse_args():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(description="Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)")
    parser.add_argument("-u", "--update", action="store_true", help="Download the latest version of the the local vulnerability and software database")
    parser.add_argument("--full-update", action="store_true", help="Fully (re)build the local vulnerability and software database")
    parser.add_argument("-k", "--api-key", type=str, help="NVD API key to use for updating the local vulnerability and software database")
    parser.add_argument("-f", "--format", type=str, default="txt", choices={"txt", "json"}, help="Output format, either 'txt' or 'json' (default: 'txt')")
    parser.add_argument("-o", "--output", type=str, help="File to write found vulnerabilities to")
    parser.add_argument("-q", "--query", dest="queries", metavar="QUERY", action="append", help="A query, either software title like 'Apache 2.4.39' or a CPE 2.3 string")
    parser.add_argument("-c", "--config", type=str, default=DEFAULT_CONFIG_FILE, help="A config file to use (default: config.json)")
    parser.add_argument("-V", "--version", action='store_true', help="Print the version of search_vulns")
    parser.add_argument("--cpe-search-threshold", type=float, default=CPE_SEARCH_THRESHOLD_MATCH, help="Similarity threshold used for retrieving a CPE via the cpe_search tool")
    parser.add_argument("--ignore-general-cpe-vulns", action="store_true", help="Ignore vulnerabilities that only affect a general CPE (i.e. without version)")
    parser.add_argument("--include-single-version-vulns", action="store_true", help="Include vulnerabilities that only affect one specific version of a product when querying a lower version")
    parser.add_argument("--use-created-cpes", action="store_true", help="If no matching CPE exists in the software database, automatically use a matching CPE created by search_vulns")

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update and not args.version:
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
        if not MATCH_CPE_23_RE.match(query):
            cpe_search_results = search_cpes(query, count=1, threshold=args.cpe_search_threshold, config=config['cpe_search'])
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

        if args.format.lower() == 'txt':
            if not args.output:
                print()
                printit('[+] %s (%s)' % (query, '/'.join(equivalent_cpes)), color=BRIGHT_BLUE)

        eol_info = {}
        for cur_cpe in equivalent_cpes:
            cur_vulns = search_vulns(cur_cpe, db_cursor, args.cpe_search_threshold, False, True, args.ignore_general_cpe_vulns, args.include_single_version_vulns, config)
            for cve_id, vuln in cur_vulns[cur_cpe]['vulns'].items():
                if cve_id not in vulns[query]:
                    vulns[query][cve_id] = vuln
            if cur_vulns[cur_cpe]['version_status']:
                eol_info = cur_vulns[cur_cpe]['version_status']

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


if __name__ == "__main__":
    main()
