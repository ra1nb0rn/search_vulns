#!/usr/bin/env python3

import argparse
from collections import OrderedDict
import json
import re
import sqlite3
import sys
import threading

from cpe_version import CPEVersion
from cpe_search.cpe_search import get_cpe_parts

MATCH_CPE_23_RE = re.compile(r'cpe:2\.3:[aoh](:[^:]+){2,10}')
CPE_SEARCH_THRESHOLD = 0.72
MATCH_DISTRO_CPE_OTHER_FIELD = re.compile(r'([<>]?=?)(ubuntu|debian|rhel)_?([\d\.]{1,5}|inf|upstream|sid)?')
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


def printit(text: str = '', end: str = '\n', color=SANE):
    '''A small print wrapper function'''

    print(color, end='')
    print(text, end=end)
    if color != SANE:
        print(SANE, end='')
    sys.stdout.flush()


def is_useful_cpe(cpe, version_end, distribution):
    '''Return whether a given cpe is useful (nvd cpe or suiting distro cpe)'''

    cpe_other_field = get_cpe_parts(cpe)[12]
    if not MATCH_DISTRO_CPE.match(cpe) or not MATCH_DISTRO.search(cpe_other_field):
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


def check_version_start_end(cpe, cpe_version, pot_vuln, distribution, ignore_general_cpe_vulns):
    '''Check whether vuln_version is in range '''
    vuln_cpe = pot_vuln[1]
    version_start, version_start_incl = pot_vuln[2], pot_vuln[3]
    version_end, version_end_incl = pot_vuln[4], pot_vuln[5]
    is_cpe_vuln, vuln_match_reason = False, 'version_in_range'
    cpe_version_start, cpe_version_end = CPEVersion(version_start), CPEVersion(version_end)
    cpe_version_start_considered_equal = cpe_version_start.considered_equal(cpe_version)

    if version_start and version_end:
        if version_start_incl == True and version_end_incl == True:
            is_cpe_vuln = cpe_version_start <= cpe_version <= cpe_version_end
            if not is_cpe_vuln:
                is_cpe_vuln = cpe_version_start_considered_equal and cpe_version <= cpe_version_end
        elif version_start_incl == True and version_end_incl == False:
            if version_end == '-1':
                vuln_match_reason = 'not_affected'
                is_cpe_vuln = True
                # filter out distro vulns not relevant b/c of version_start not matching
                if not is_cpe_vuln:
                    vuln_match_reason = 'version_start_not_included'
            elif version_end == str(sys.maxsize) or (version_end == str(sys.maxsize-1) and distribution[0] != MATCH_DISTRO.search(get_cpe_parts(vuln_cpe)[12]).group(1)):
                # handle sys.maxsize or not-fixed from another distro as general info
                vuln_match_reason = 'general_cpe'
                is_cpe_vuln = True
            else:
                is_cpe_vuln = cpe_version_start <= cpe_version < cpe_version_end
                if not is_cpe_vuln:
                    is_cpe_vuln = cpe_version_start_considered_equal and cpe_version < cpe_version_end
        elif version_start_incl == False and version_end_incl == True:
            is_cpe_vuln = cpe_version_start < cpe_version <= cpe_version_end
            if not is_cpe_vuln:
                is_cpe_vuln = cpe_version_start_considered_equal and cpe_version <= cpe_version_end
        else:
            is_cpe_vuln = cpe_version_start < cpe_version < cpe_version_end
            if not is_cpe_vuln:
                is_cpe_vuln = cpe_version_start_considered_equal and cpe_version < cpe_version_end
    elif version_start:
        if version_end_incl == True:
            is_cpe_vuln = cpe_version_start <= cpe_version
        elif version_end_incl == False:
            is_cpe_vuln = cpe_version_start < cpe_version
        if not is_cpe_vuln:
            is_cpe_vuln = cpe_version_start_considered_equal
    elif version_end:
        if version_end == '-1':
            vuln_match_reason = 'not_affected'
            is_cpe_vuln = True
        elif version_end == str(sys.maxsize) or (version_end == str(sys.maxsize-1) and distribution[0] != MATCH_DISTRO.search(get_cpe_parts(vuln_cpe)[12]).group(1)):
            # handle sys.maxsize or not-fixed from another distro as general info
            vuln_match_reason = 'general_cpe'
            is_cpe_vuln = True
        elif version_end_incl == True:
            is_cpe_vuln = cpe_version <= cpe_version_end
        elif version_end_incl == False:
            is_cpe_vuln = cpe_version < cpe_version_end
    else:
        # if configured, ignore vulnerabilities that only affect a general CPE
        if ignore_general_cpe_vulns and all(val in ('*', '-') for val in get_cpe_parts(vuln_cpe)[5:]):
            is_cpe_vuln = False
        else:
            is_cpe_vuln = is_cpe_included_after_version(cpe, vuln_cpe)
        vuln_match_reason = 'general_cpe'

    # if configured, ignore general vulns from distro
    if ignore_general_cpe_vulns and vuln_match_reason == 'general_cpe':
        is_cpe_vuln = False

    # check that everything after the version field matches in the CPE
    if is_cpe_vuln:
        if cpe.count(':') > 5 and vuln_cpe.count(':') > 5:
            if not is_cpe_included_after_version(cpe, vuln_cpe, bool(distribution[0])):
                if MATCH_DISTRO_CPE.match(vuln_cpe):
                    is_cpe_vuln = True
                else:
                    is_cpe_vuln = False

    return is_cpe_vuln, vuln_match_reason


def print_vulns(vulns, to_string=False):
    '''Print the supplied vulnerabilities'''

    out_string = ''
    cve_ids_sorted = sorted(list(vulns), key=lambda cve_id: float(vulns[cve_id]['cvss']), reverse=True)
    for cve_id in cve_ids_sorted:
        vuln_node = vulns[cve_id]
        description = DEDUP_LINEBREAKS_RE_2.sub('\n', DEDUP_LINEBREAKS_RE_1.sub('\r\n', vuln_node['description'].strip()))

        if not to_string:
            print_str = GREEN + vuln_node['id'] + SANE
            print_str += ' (' + MAGENTA + 'CVSSv' + vuln_node['cvss_ver'] + '/' + str(vuln_node['cvss']) + SANE + '): %s\n' % description
        else:
            print_str = vuln_node['id']
            print_str += ' (''CVSSv' + vuln_node['cvss_ver'] + '/' + str(vuln_node['cvss']) + '): %s\n' % description

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
    cpe_split = get_cpe_parts(cpe)
    cpe_prefix = ':'.join(cpe_split[:5]) + ':'

    for equivalent_cpe in EQUIVALENT_CPES.get(cpe_prefix, []):
        equivalent_cpe_prefix = ':'.join(get_cpe_parts(equivalent_cpe)[:5]) + ':'
        if equivalent_cpe != cpe_prefix:
            cpes.append(equivalent_cpe_prefix + ':'.join(cpe_split[5:]))

    return cpes


def is_cpe_included_after_version(cpe1, cpe2, is_distro_query=False):
    '''Return True if cpe1 is included in cpe2 after the version section'''

    cpe1_remainder_fields = get_cpe_parts(cpe1)[6:]
    cpe2_remainder_fields = get_cpe_parts(cpe2)[6:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        if cpe1_remainder_fields[i] in ('*', '-'):
            continue
        if cpe2_remainder_fields[i] in ('*', '-'):
            continue

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False
    return True