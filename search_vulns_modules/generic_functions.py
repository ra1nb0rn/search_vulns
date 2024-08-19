#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
import threading
import itertools

from cpe_version import CPEVersion
from cpe_search.database_wrapper_functions import *
from cpe_search.cpe_search import (
    MATCH_CPE_23_RE
)
from cpe_search.database_wrapper_functions import get_database_connection
from search_vulns_modules.config import _load_config, DEFAULT_CONFIG_FILE

CPE_SEARCH_THRESHOLD_MATCH = 0.72

MATCH_DISTRO_CPE_OTHER_FIELD = re.compile(r'([<>]?=?)(ubuntu|debian|rhel)_?([\d\.]{1,5}|inf|upstream|sid)?')
MATCH_DISTRO = re.compile(r'(ubuntu|debian|redhat|rhel)(?:[^\d]|$)')
MATCH_DISTRO_CPE = re.compile(r'cpe:2\.3:[aoh]:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:[<>]?=?(ubuntu|rhel|debian)_?([\d\.]+|upstream|sid)?$')
MATCH_TWO_SOFTWARES_AND_VERSIONS = re.compile(r'([\w\.\:\-\_\~]*\s){2,}')
VERSION_MATCH_CPE_CREATION_RE = re.compile(r'\b((\d[\da-zA-Z\.]{0,6})([\+\-\.\_\~ ][\da-zA-Z\.]+){0,4})[^\w\n]*$')
DEBIAN_EQUIV_CPES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../debian_equiv_cpes.json')

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
    return re.split(r'(?<!\\):', cpe)


def is_useful_cpe(cpe, version_end, distribution):
    '''Return whether a given cpe is useful (nvd cpe or suiting distro cpe)'''

    cpe_other_field = get_cpe_parts(cpe)[12]
    if not MATCH_DISTRO_CPE.match(cpe) or not MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_other_field):
        return True
    distro, distro_version = distribution
    if distro_version == 'upstream' or distro_version == 'sid':
        distro_version = 'inf'
    try:
        operator, distro_cpe, distro_version_cpe = MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_other_field).groups()[0:3]
    except:
        operator, distro_cpe, distro_version_cpe = '', '', ''
    if distro == distro_cpe or (distribution[0] and distro_version == 'inf'):
        if not operator and distro_version_cpe == distro_version:
            return True
        elif operator == '<=' and float(distro_version) <= float(distro_version_cpe):
            return True
        elif operator == '>=':
            return True
    if operator == '>=' and float(distro_version) >= float(distro_version_cpe):
        return True and version_end != '-1'
    return False


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
        with open(config['MAN_EQUIVALENT_CPES_FILE']) as f:
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
            equivalent_cpe_prefix = ':'.join(get_cpe_parts(equivalent_cpe)[:5]) + ':'
            if equivalent_cpe != cpe_prefix:
                equiv_cpes.append(equivalent_cpe_prefix + ':'.join(cpe_split[5:]))

    return equiv_cpes


def is_cpe_included_after_version(cpe1, cpe2):
    '''Return True if cpe1 is included in cpe2 after the version section'''

    return is_cpe_included_from_field(cpe1, cpe2)


def get_cpe_version(cpe_version, cpe_subversion, version_end):
    # combine version and subversion if NVD merged both for version_end as well
    if version_end and len(version_end.get_version_sections()) > len(cpe_version.get_version_sections()):
        cpe_version = (cpe_version + cpe_subversion)
    return cpe_version


def are_versions_considered_equal(cpe_version, version_start, version_start_incl, version_end, version_end_incl):
    '''Return boolean whether the provided versions are considered equal, e.g. 5.5.5 and 5.5.5-6'''
    
    version_start_considered_equal = version_start.considered_equal(cpe_version)
    version_end_considered_equal = version_end.considered_equal(cpe_version)

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
    
    elif version_start:
        if version_start_incl:
            return (version_start <= cpe_version or 
                           version_start_considered_equal)
        else:
            return (version_start < cpe_version) and not version_start_considered_equal
    
    elif version_end:
        if version_end_incl:
            return (cpe_version <= version_end or 
                           version_end_considered_equal)
        else:
            return (cpe_version < version_end) and not version_end_considered_equal


def is_version_start_end_matching(cpe_version, cpe_subversion, version_start, version_start_incl, version_end, version_end_incl, is_distro = False):
    """Return boolean whether the provided CPE version lies within the provided range modifiers"""

    version_start = CPEVersion(version_start)
    version_end = CPEVersion(version_end)
    is_matching = False

    cpe_version = get_cpe_version(cpe_version, cpe_subversion, version_end)

    if is_distro:
        is_matching = are_versions_considered_equal(cpe_version, version_start, version_start_incl, version_end, version_end_incl)
    else:
        if version_start and version_end:
            if version_start_incl == True and version_end_incl == True:
                is_matching = version_start <= cpe_version <= version_end
            elif version_start_incl == True and version_end_incl == False:
                is_matching = version_start <= cpe_version < version_end
            elif version_start_incl == False and version_end_incl == True:
                is_matching = version_start < cpe_version <= version_end
            else:
                is_matching = version_start < cpe_version < version_end
        elif version_start:
            if version_start_incl == True:
                is_matching = version_start <= cpe_version
            elif version_start_incl == False:
                is_matching = version_start < cpe_version
        elif version_end:
            if version_end_incl == True:
                is_matching = cpe_version <= version_end
            elif version_end_incl == False:
                is_matching = cpe_version < version_end
    
    return is_matching


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
                vuln_cpe_fields, vuln_other_cpe_fields = get_cpe_parts(vuln_cpe), get_cpe_parts(vuln_other_cpe)
                for i in range(len(vuln_other_cpe_fields)-1, -1, -1):
                    if (not CPEVersion(vuln_cpe_fields[i])) and (not CPEVersion(vuln_other_cpe_fields[i])):
                        continue
                    elif CPEVersion(vuln_other_cpe_fields[i]):
                        return True
                    else:
                        break
    return False


def get_possible_versions_in_query(query):
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