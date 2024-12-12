#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import re
import sys
import threading
import itertools

from cpe_version import CPEVersion
from cpe_search.database_wrapper_functions import *
from cpe_search.cpe_search import MATCH_CPE_23_RE
from cpe_search.database_wrapper_functions import get_database_connection
from search_vulns_modules.config import _load_config, DEFAULT_CONFIG_FILE

CPE_SEARCH_THRESHOLD_MATCH = 0.72

MATCH_DISTRO_CPE_OTHER_FIELD = re.compile(r'([<>]?=?)(ubuntu|debian|rhel)_?((?:[\d\.]{1,5}|inf|upstream|sid)?(?:_esm)?)')
MATCH_DISTRO = re.compile(r'(ubuntu|debian|redhat|rhel|\.el)(?:\d)?(?:[^\d]|$)')
MATCH_DISTRO_CPE = re.compile(r'cpe:2\.3:[aoh]:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:[<>]?=?(ubuntu|rhel|debian)_?([\d\.]+|upstream|sid)?(_esm)?$')
UNIX_CPES = ['cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*', 'cpe:2.3:o:opengroup:unix:-:*:*:*:*:*:*:*', 'cpe:2.3:o:unix:unix:*:*:*:*:*:*:*:*']

MATCH_TWO_SOFTWARES_AND_VERSIONS = re.compile(r'([\w\.\:\-\_\~]+(\s|(ubuntu|redhat|debian|rhel|\.el))){2,}')
VERSION_MATCH_CPE_CREATION_RE = re.compile(r'\b((\d[\da-zA-Z\.]{0,6})([\+\-\.\_\~ ][\da-zA-Z\.]+){0,4})[^\w\n]*$')
NUMERIC_VERSION_RE = re.compile(r'[\d\.]+')
NON_ALPHANUMERIC_SPLIT_RE = re.compile(r'[^a-zA-Z]')

PROJECT_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
DEFAULT_CONFIG_FILE = os.path.join(PROJECT_DIR, 'config.json')
MAN_EQUIVALENT_CPES_FILE = os.path.join(PROJECT_DIR, os.path.join('resources', 'man_equiv_cpes.json'))
DEBIAN_EQUIV_CPES_FILE = os.path.join(PROJECT_DIR, os.path.join('resources', 'debian_equiv_cpes.json'))
VERSION_FILE = os.path.join(PROJECT_DIR, 'version.txt')

EQUIVALENT_CPES = {}
LOAD_EQUIVALENT_CPES_MUTEX = threading.Lock()
DEDUP_LINEBREAKS_RE_1 = re.compile(r'(\r\n)+')
DEDUP_LINEBREAKS_RE_2 = re.compile(r'\n+')
CPE_COMPARISON_STOP_CHARS_RE = re.compile(r'[\+\-\_\~]')
CPE_SEARCH_COUNT = 5

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


def printit(text: str = '', end: str = '\n', color=SANE):
    '''A small print wrapper function'''

    print(color, end='')
    print(text, end=end)
    if color != SANE:
        print(SANE, end='')
    sys.stdout.flush()
    

def get_cpe_parts(cpe):
    '''Get all thirteen parts of a cpe'''
    return re.split(r'(?<!\\):', cpe)


def is_cpe_included_from_field(cpe1, cpe2, field=6):
    '''Return True if cpe1 is included in cpe2 starting from the provided field'''

    cpe1_remainder_fields = get_cpe_parts(cpe1)[field:]
    cpe2_remainder_fields = get_cpe_parts(cpe2)[field:]

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

        # cpe fields with distribution data are always considered equal
        if MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe1_remainder_fields[i]) \
                and MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe2_remainder_fields[i]):
                continue

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False

    return True


def print_vulns(vulns, to_string=False):
    '''Print the supplied vulnerabilities'''

    out_string = ''
    cve_ids_sorted = sorted(list(vulns), key=lambda cve_id: float(vulns[cve_id]['cvss']), reverse=True)
    for cve_id in cve_ids_sorted:
        vuln_node = vulns[cve_id]
        description = DEDUP_LINEBREAKS_RE_2.sub('\n', DEDUP_LINEBREAKS_RE_1.sub('\r\n', vuln_node['description'].strip()))

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

        if 'exploits' in vuln_node:
            if not to_string:
                print_str += YELLOW + 'Exploits:  ' + SANE + vuln_node['exploits'][0] + '\n'
            else:
                print_str += 'Exploits:  ' + vuln_node['exploits'][0] + '\n'

            if len(vuln_node['exploits']) > 1:
                for edb_link in vuln_node['exploits'][1:]:
                    print_str += len('Exploits:  ') * ' ' + edb_link + '\n'

        print_str += 'Reference: ' + vuln_node['href']
        print_str += ', ' + vuln_node['published'].split(' ')[0]
        if not to_string:
            printit(print_str)
        else:
            out_string += print_str + '\n'

    if to_string:
        return out_string


def load_equivalent_cpes(config):
    '''Load dictionary containing CPE equivalences'''

    LOAD_EQUIVALENT_CPES_MUTEX.acquire()
    if not EQUIVALENT_CPES:
        equivalent_cpes_dicts_list, deprecated_cpes = [], {}

        # first add official deprecation information from the NVD
        with open(config['cpe_search']['DEPRECATED_CPES_FILE'], 'r') as f:
            cpe_deprecations_raw = json.loads(f.read())
            for cpe, deprecations in cpe_deprecations_raw.items():
                cpe_short = ':'.join(get_cpe_parts(cpe)[:5]) + ':'
                deprecations_short = []
                for deprecatedby_cpe in deprecations:
                    deprecatedby_cpe_short = ':'.join(get_cpe_parts(deprecatedby_cpe)[:5]) + ':'
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
    cpe_split = get_cpe_parts(cpe)
    cpe_prefix = ':'.join(cpe_split[:5]) + ':'
    cpe_version, cpe_subversion = '*', '*'
    if len(cpe_split) > 5:
        cpe_version = cpe_split[5]
    if len(cpe_split) > 6:
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
        cur_cpe_split = get_cpe_parts(cur_cpe)
        for equivalent_cpe in EQUIVALENT_CPES.get(cpe_prefix, []):
            equivalent_cpe_prefix = ':'.join(get_cpe_parts(equivalent_cpe)[:5]) + ':'
            if equivalent_cpe != cpe_prefix:
                equiv_cpes.append(equivalent_cpe_prefix + ':'.join(cur_cpe_split[5:]))

    return list(set(equiv_cpes))


def is_cpe_included_after_version(cpe1, cpe2):
    '''Return True if cpe1 is included in cpe2 after the version section'''

    return is_cpe_included_from_field(cpe1, cpe2)


def get_cpe_version(cpe_version, cpe_parts, version_end):
    # combine version and subversion if NVD merged both for version_end as well
    version_end_sections = version_end.get_version_sections()
    cpe_version_subsections = cpe_version.get_version_sections()
    cpe_subversion = CPEVersion('*')
    if len(cpe_parts) > 6:
        cpe_subversion = CPEVersion(cpe_parts[6])
    cpe_product = cpe_parts[4]

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
    return cpe_version


def are_versions_considered_equal(cpe_version, version_start, version_start_incl, version_end, version_end_incl):
    '''Return boolean whether the provided versions are considered equal, e.g. 5.5.5 and 5.5.5-6'''
    
    version_start_considered_equal = version_start.considered_equal(cpe_version)
    version_end_considered_equal = version_end.considered_equal(cpe_version)

    # version start and version end given, both has to match
    if version_start and version_end:
        if version_start_incl and version_end_incl:
            return (version_start <= cpe_version <= version_end or 
                           version_start_considered_equal or 
                           version_end_considered_equal)
        elif version_start_incl and not version_end_incl:
            return (version_start <= cpe_version < version_end or 
                           version_start_considered_equal) and not version_end_considered_equal
        elif not version_start_incl and version_end_incl:
            return (version_start < cpe_version <= version_end or 
                           version_end_considered_equal) and not version_start_considered_equal
        else:  # not version_start_incl and not version_end_incl
            return (version_start < cpe_version < version_end) and not version_start_considered_equal and not version_end_considered_equal
    # only start version given 
    elif version_start:
        if version_start_incl:
            return (version_start <= cpe_version or 
                           version_start_considered_equal)
        else:
            return (version_start < cpe_version) and not version_start_considered_equal
    # only end version given 
    elif version_end:
        if version_end_incl:
            return (cpe_version <= version_end or 
                           version_end_considered_equal)
        else:
            return (cpe_version < version_end) and not version_end_considered_equal


def is_version_start_end_matching(cpe_parts, version_start, version_start_incl, version_end, version_end_incl, is_distro = False):
    """Return boolean whether the provided CPE version lies within the provided range modifiers"""

    version_start = CPEVersion(version_start)
    version_end = CPEVersion(version_end)

    cpe_version = CPEVersion(cpe_parts[5])
    cpe_version = CPEVersion('*')
    # check that CPE is not short/incomplete
    if len(cpe_parts) > 5:
        cpe_version = CPEVersion(cpe_parts[5])

    if version_end:
        cpe_version = get_cpe_version(cpe_version, cpe_parts, version_end)
    else:
        # set a max version if end is not given explicitly
        version_end = CPEVersion('~' * 256)

    # considered equal check only for distribution results
    if is_distro:
        return are_versions_considered_equal(cpe_version, version_start, version_start_incl, version_end, version_end_incl)
    else:
        # check if version start or end matches exactly, otherwise return if in range
        if version_start_incl and cpe_version == version_start:
            return True
        if version_end_incl and cpe_version == version_end:
            return True
        return version_start < cpe_version < version_end


def has_cpe_lower_versions(cpe1, cpe2, is_distro_query=False):
    '''Return True if cpe1 is considered to have a lower product version than cpe2'''

    cpe1_remainder_fields = get_cpe_parts(cpe1)[5:]
    cpe2_remainder_fields = get_cpe_parts(cpe2)[5:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        # same distro for distributions in other field
        if i ==4 and is_distro_query and \
            MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe1_remainder_fields[i]) and MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe2_remainder_fields[i]) \
            and (MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe1_remainder_fields[i]).group(2) == MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe2_remainder_fields[i]).group(2)):
            continue
        if i == 6 and is_distro_query:
            continue

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


def get_possible_versions_in_query(query):
    '''
    Return all version parts from query
    '''
    version_parts = []
    version_str_match = VERSION_MATCH_CPE_CREATION_RE.search(query)
    if version_str_match:
        full_version_str = version_str_match.group(1).strip()
        version_parts.append(full_version_str)
        version_parts += re.split(r'[\+\-\_\~ ]', full_version_str)

        # remove first element in case of duplicate
        if len(version_parts) > 1 and version_parts[0] == version_parts[1]:
            version_parts = version_parts[1:]
    return version_parts


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