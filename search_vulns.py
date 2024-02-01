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
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    get_cpe_parts,
    MATCH_CPE_23_RE
)
from cpe_search.cpe_search import _load_config as _load_config_cpe_search

DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config.json')
DEBIAN_EQUIV_CPES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'debian_equiv_cpes.json')
CPE_SEARCH_THRESHOLD_MATCH = 0.72

MATCH_DISTRO_CPE_OTHER_FIELD = re.compile(r'([<>]?=?)(ubuntu|debian|rhel)_?([\d\.]{1,5}|inf|upstream|sid)?')
MATCH_DISTRO_QUERY = re.compile(r'(ubuntu|debian|redhat enterprise linux|redhat|rhel)[ _]?([\w\.]*)')
MATCH_DISTRO = re.compile(r'(ubuntu|debian|redhat|rhel)(?:[^\d]|$)')
MATCH_DISTRO_CPE = re.compile(r'cpe:2\.3:[aoh]:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:.*?:[<>]?=?(ubuntu|rhel|debian)_?([\d\.]+|upstream|sid)?$')
MATCH_TWO_SOFTWARES_AND_VERSIONS = re.compile(r'([\w\.\:\-\_\~]*\s){2,}')

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


def add_distribution_infos_to_cpe(cpe, distribution):
    cpe_parts = get_cpe_parts(cpe)
    if distribution[1] == 'inf':
        cpe_parts[12] = distribution[0]
    else:
        cpe_parts[12] = '%s_%s' %(distribution)
    return ':'.join(cpe_parts)


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

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False

    return True


def check_version_start_end(cpe, cpe_version, pot_vuln, distribution, ignore_general_cpe_vulns):
    '''Check whether vuln_version is in range '''
    vuln_cpe = pot_vuln[1]
    version_start, version_start_incl = pot_vuln[2], pot_vuln[3]
    version_end, version_end_incl = pot_vuln[4], pot_vuln[5]
    is_cpe_vuln, vuln_match_reason = False, 'version_in_range'

    if version_start and version_end:
        if version_start_incl == True and version_end_incl == True:
            is_cpe_vuln = CPEVersion(version_start) <= cpe_version <= CPEVersion(version_end)
        elif version_start_incl == True and version_end_incl == False:
            if version_end == '-1':
                vuln_match_reason = 'not_affected'
                is_cpe_vuln = is_useful_cpe(vuln_cpe, version_end, distribution) and CPEVersion(version_start) <= cpe_version
                # filter out distro vulns not relevant b/c of version_start not matching
                if not is_cpe_vuln:
                    vuln_match_reason = 'version_start_not_included'
            elif version_end == str(sys.maxsize) or (version_end == str(sys.maxsize-1) and distribution[0] != MATCH_DISTRO.search(get_cpe_parts(vuln_cpe)[12]).group(1)):
                # handle sys.maxsize or not-fixed from another distro as general info
                vuln_match_reason = 'general_cpe'
                is_cpe_vuln = is_useful_cpe(vuln_cpe, version_end, distribution) and not ignore_general_cpe_vulns
            else:
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
        if version_end == '-1':
            vuln_match_reason = 'not_affected'
            is_cpe_vuln = True
        elif version_end == str(sys.maxsize) or (version_end == str(sys.maxsize-1) and distribution[0] != MATCH_DISTRO.search(get_cpe_parts(vuln_cpe)[12]).group(1)):
            # handle sys.maxsize or not-fixed from another distro as general info
            vuln_match_reason = 'general_cpe'
            is_cpe_vuln = is_useful_cpe(vuln_cpe, version_end, distribution) and not ignore_general_cpe_vulns
        elif version_end_incl == True:
            is_cpe_vuln = cpe_version <= CPEVersion(version_end)
        elif version_end_incl == False:
            is_cpe_vuln = cpe_version < CPEVersion(version_end)
    else:
        # if configured, ignore vulnerabilities that only affect a general CPE
        if ignore_general_cpe_vulns and all(val in ('*', '-') for val in get_cpe_parts(vuln_cpe)[5:]):
            is_cpe_vuln = False
        else:
            is_cpe_vuln = is_cpe_included_after_version(cpe, vuln_cpe)
        vuln_match_reason = 'general_cpe'

    # check that everything after the version field matches in the CPE
    if is_cpe_vuln:
        if cpe.count(':') > 5 and vuln_cpe.count(':') > 5:
            if not is_cpe_included_after_version(cpe, vuln_cpe, bool(distribution[0])):
                if MATCH_DISTRO_CPE.match(cpe):
                    is_cpe_vuln = True
                    vuln_match_reason = 'distro_cpe_in_range'
                else:
                    is_cpe_vuln = False

    return is_cpe_vuln, vuln_match_reason


def get_most_specific_cpe(vuln_cpes_distro, distribution, cpe_version, vuln_cpes_nvd):
    '''Return the best suiting cpe'''
    query_distro_version = distribution[1] if not distribution[1] in ('upstream', 'sid') else 'inf'
    greater_than_cpe = ''
    minor_version_cpe = ''
    for cpe_infos in vuln_cpes_distro:
        cpe_parts = get_cpe_parts(cpe_infos[0])
        cpe_version_start = cpe_infos[2]
        cpe_operator, distro, distro_version = MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_parts[12]).groups()
        if distro_version in ('upstream', 'sid'):
            distro_version = '-1'
        # cpe not relevant because version_start < given cpe_version
        if cpe_version_start and cpe_version and cpe_version < CPEVersion(cpe_version_start):
            continue
        if not cpe_operator:
            if distro_version == query_distro_version:
                return cpe_infos[0] 
            # use closest minor version if no entry for queried distro version
            # e.g. '7' is no minor version of '7.9', but '7.0' is
            split_distro_version = distro_version.split('.')
            split_query_distro_version = query_distro_version.split('.')
            if len(split_distro_version) > 1 and len(split_query_distro_version) > 1 and split_distro_version[0] == split_query_distro_version[0] and int(split_distro_version[1]) < int(split_query_distro_version[1]):
                if not minor_version_cpe:
                    minor_version_cpe = cpe_infos[0]
                elif float(MATCH_DISTRO_CPE_OTHER_FIELD.match(get_cpe_parts(minor_version_cpe)[12]).group(3)) < float(distro_version):
                    minor_version_cpe = cpe_infos[0]
        elif cpe_operator == '<=':
            if float(query_distro_version) <= float(distro_version):
                return cpe_infos[0]
        else:
            if float(query_distro_version) >= float(distro_version):
                return cpe_infos[0] 
            else:
                greater_than_cpe = cpe_infos[0]
    # minor version handling only for RedHat
    if minor_version_cpe and distribution[0] in ('rhel', 'redhat'):
        return minor_version_cpe
    if vuln_cpes_nvd:
        return ''
    return greater_than_cpe


def query_distribution_matches(cpe_parts, distribution, db_cursor):
    '''Return useful distribution matches'''
    query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
                         'is_cpe_version_end_including FROM cve_cpe WHERE cpe LIKE ?')
    
    # query for all distro cpes
    query_cpe_parameters = ['%s:>=%s%%' % (':'.join(cpe_parts[:12]), '%%')]
    if distribution[1] != 'inf':
        query_cpe_parameters.append('%s:%%:%s_%s' % (':'.join(cpe_parts[:5]), distribution[0], distribution[1]))
        query_cpe_parameters.append('%s:%%:<=%s%%' % (':'.join(cpe_parts[:5]), distribution[0]))
        # query with same main release
        query_cpe_parameters.append('%s:%%:%s_%s.%%' % (':'.join(cpe_parts[:5]), distribution[0], distribution[1].split('.')[0]))

    pot_vulns = set()
    for query_cpe_parameter in query_cpe_parameters:
        pot_vulns |= set(db_cursor.execute(query, (query_cpe_parameter, )))

    return pot_vulns


def get_distribution_matches(cpe, cpe_parts, db_cursor, distribution, ignore_general_cpe_vulns=False):
    '''
    Get vulnerability data that is stored in the DB 
    with a distribution cpe
    '''
    vulns = []
    if len(cpe_parts) > 5 and cpe_parts[5] not in ('-', '*'):  # for CPE 2.3
        cpe_version = CPEVersion(cpe_parts[5])
        cpe_parts[5] = '*'
    else:
        cpe_version = None
    if cpe_parts[5] == '-':
        cpe_parts[5] = '*'
    
    pot_vulns = query_distribution_matches(cpe_parts, distribution, db_cursor)

    vulns = []

    found_vulns_cpes = {}

    for pot_vuln in pot_vulns:
        cve_id, vuln_cpe, version_end = pot_vuln[0], pot_vuln[1], pot_vuln[4]

        if cve_id not in found_vulns_cpes:
            found_vulns_cpes[cve_id] = query_vuln_cpes(cpe_parts, db_cursor, distribution, cpe_version, cve_id)

        vuln_cpes_nvd, vuln_cpes_distro, most_specific_cpe = found_vulns_cpes[cve_id]
        vuln_cpe_parts = get_cpe_parts(vuln_cpe)
        cpe_operator = vuln_cpe_parts[12][0:2] if vuln_cpe_parts[12][0:2] in ('<=', '>=') else ''
        same_distro = distribution[0] == MATCH_DISTRO.search(vuln_cpe_parts[12]).group(1)

        if most_specific_cpe and most_specific_cpe != vuln_cpe:
            continue
        if same_distro:
            if not distribution[1] and cpe_operator != '>=':
                is_cpe_vuln = False
                continue
        else:
            if len(vuln_cpes_nvd) > 0 or len(vuln_cpes_distro) > 0:
                is_cpe_vuln = False
                continue
            if version_end == '-1':
                continue

        # nvd has information and current cpe not most_specific cpe or no distribution given -> skip distro info
        if len(vuln_cpes_nvd) > 0 and (most_specific_cpe and most_specific_cpe != vuln_cpe or not distribution[0]):
            is_cpe_vuln = False
            continue

        if cpe_version:
            is_cpe_vuln, vuln_match_reason = check_version_start_end(cpe, cpe_version, pot_vuln, distribution, ignore_general_cpe_vulns)
        else:
            is_cpe_vuln = pot_vuln[4] != '-1'
            vuln_match_reason = 'general_cpe_but_ok'
        if (not is_useful_cpe(cpe=pot_vuln[1], version_end=pot_vuln[4], distribution=distribution)) or vuln_match_reason == 'version_start_not_included':
            is_cpe_vuln = False
        elif not is_cpe_vuln:
            is_cpe_vuln, vuln_match_reason = True, 'not_affected'
        if is_cpe_vuln:
            vulns.append((pot_vuln[0], vuln_match_reason))
    return vulns


def query_vuln_cpes(cpe_parts, db_cursor, distribution, cpe_version, cve_id):
    '''Return all cpes for a given cve_id (nvd_cpes, given distro_cpes, most_specific_distro_cpe)'''
    get_cpes_query = 'SELECT cpe, source, cpe_version_start FROM cve_cpe WHERE cpe LIKE ? AND cve_id == ?'
    vuln_cpes = set(db_cursor.execute(get_cpes_query, (':'.join(cpe_parts[:5])+'%%', cve_id)))
    # use '-' and '*' as equal wildcards
    if cpe_parts[5] == '-':
        cpe_parts[5] = '*'
        vuln_cpes |= set(db_cursor.execute(get_cpes_query, (':'.join(cpe_parts[:5])+'%%', cve_id)))
    elif cpe_parts[5] == '*':
        cpe_parts[5] = '-'
        vuln_cpes |= set(db_cursor.execute(get_cpes_query, (':'.join(cpe_parts[:5])+'%%', cve_id)))
    vuln_cpes_nvd = set([cpe for cpe in vuln_cpes if cpe[1] == 'nvd'])
    vuln_cpes_distro = set([cpe for cpe in vuln_cpes if cpe[1] == distribution[0]])
    most_specific_cpe  = get_most_specific_cpe(vuln_cpes_distro, distribution, cpe_version, vuln_cpes_nvd)
    return (vuln_cpes_nvd,vuln_cpes_distro,most_specific_cpe)


def is_cpe_included_after_version(cpe1, cpe2, is_distro_query=False):
    '''Return True if cpe1 is included in cpe2 after the version section'''

    return is_cpe_included_from_field(cpe1, cpe2)


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


def get_not_affected_cve_ids(vulns):
    '''Get cve_ids of not-affected vulns'''
    not_affected_cve_ids = []
    for vuln in vulns:
        if vuln[1] == 'not_affected':
            not_affected_cve_ids.append(vuln[0][0])
        else:
            try:
                version_end = vuln[0][4]
                if version_end == '-1':
                    not_affected_cve_ids.append(vuln[0][0])
            except:
                pass
    return not_affected_cve_ids


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
            detailed_vulns[cve_id]['exploits'] = []
            for edb_id in edb_ids.split(','):
                detailed_vulns[cve_id]['exploits'].append('https://www.exploit-db.com/exploits/%s' % edb_id)

        # add other exploit references
        if add_other_exploit_refs:
            # from NVD
            query = 'SELECT exploit_ref FROM nvd_exploits_refs_view WHERE cve_id = ?'
            nvd_exploit_refs = ''
            db_cursor.execute(query, (cve_id,))
            if db_cursor:
                nvd_exploit_refs = db_cursor.fetchall()
            if nvd_exploit_refs:
                if 'exploits' not in detailed_vulns[cve_id]:
                    detailed_vulns[cve_id]['exploits'] = []
                for nvd_exploit_ref in nvd_exploit_refs:
                    if (nvd_exploit_ref[0] not in detailed_vulns[cve_id]['exploits'] and
                            nvd_exploit_ref[0] + '/' not in detailed_vulns[cve_id]['exploits'] and
                            nvd_exploit_ref[0][:-1] not in detailed_vulns[cve_id]['exploits']):
                        detailed_vulns[cve_id]['exploits'].append(nvd_exploit_ref[0])

            # from PoC-in-Github
            query = 'SELECT reference FROM cve_poc_in_github_map WHERE cve_id = ?'
            poc_in_github_refs = ''
            db_cursor.execute(query, (cve_id,))
            if db_cursor:
                poc_in_github_refs = db_cursor.fetchall()
            if poc_in_github_refs:
                if 'exploits' not in detailed_vulns[cve_id]:
                    detailed_vulns[cve_id]['exploits'] = []
                for poc_in_github_ref in poc_in_github_refs:
                    if (poc_in_github_ref[0] not in detailed_vulns[cve_id]['exploits'] and
                            poc_in_github_ref[0] + '/' not in detailed_vulns[cve_id]['exploits'] and
                            poc_in_github_ref[0][:-1] not in detailed_vulns[cve_id]['exploits'] and
                            poc_in_github_ref[0] + '.git' not in detailed_vulns[cve_id]['exploits']):
                        detailed_vulns[cve_id]['exploits'].append(poc_in_github_ref[0])

    return detailed_vulns, get_not_affected_cve_ids(vulns)


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


def get_vulns(cpe, db_cursor, ignore_general_cpe_vulns=False, include_single_version_vulns=False, add_other_exploit_refs=False, distribution=('', 'inf')):
    """Get known vulnerabilities for the given CPE 2.3 string"""

    cpe_parts = get_cpe_parts(cpe)
    cpe_version = CPEVersion(cpe_parts[5])
    cpe_subversion = CPEVersion(cpe_parts[6])
    vulns = []

    general_cpe_prefix = ':'.join(get_cpe_parts(cpe)[:5]) + ':'
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
                if not CPEVersion(get_cpe_parts(vuln_cpe)[5]):
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
    
    if cpe_parts[12] in ('-', '*') or MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_parts[12]):
        vulns += get_distribution_matches(cpe, cpe_parts, db_cursor, distribution, ignore_general_cpe_vulns)

    # reverse the list b/c distro information should be considered first
    vulns.reverse()

    # retrieve more information about the found vulns, e.g. CVSS scores and possible exploits
    return get_vuln_details(db_cursor, vulns, add_other_exploit_refs)


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


def handle_subversion_of_distro_version(distro, distro_version):
    '''Strip subversion from distro version'''
    if distro == 'ubuntu':
        if len(distro_version.split('.')) == 3:
            distro_version = '.'.join(distro_version.split('.')[:2])
    elif distro == 'debian':
        if distro_version not in ('', 'inf'):
            distro_version_parts = distro_version.split('.')
            # versions < 7 -> e.g. 6.0.3
            if CPEVersion(distro_version) < CPEVersion('7.0'):
                if len(distro_version_parts) == 3:
                    distro_version = '.'.join(distro_version_parts[:2])
            # versions >= 7 -> e.g. 7.3
            elif len(distro_version_parts) == 2:
                distro_version = distro_version_parts[0]

    return (distro, distro_version)


def get_distro_infos_from_query(original_query, db_cursor):
    '''
    Extract distro version or codename from query and 
    query in the database for a suiting distro_version
    '''
 
    db_distro_query = 'SELECT version, codename FROM distribution_codename_version_mapping'
    all_distro_versions_codenames_tuples = db_cursor.execute(db_distro_query).fetchall()
    # turn list of version_codename tuples in one list
    all_distro_versions_codenames = [version for distro_version in all_distro_versions_codenames_tuples for version in distro_version]
    possible_distro_query = MATCH_DISTRO_QUERY.search(original_query.lower())
    if MATCH_CPE_23_RE.match(original_query):
        possible_distro_query = MATCH_DISTRO_QUERY.search(get_cpe_parts(original_query)[12])
    if possible_distro_query:
        distro, distro_version = possible_distro_query.groups()
        distro, distro_version = handle_subversion_of_distro_version(distro.lower(), distro_version)
        if distro_version and distro_version in all_distro_versions_codenames:
            for version, codename in all_distro_versions_codenames_tuples:
                if distro_version == version or distro_version == codename:
                    distro_version = version
                    break
        else:
            distro_version = 'inf' # float of 'inf' is a value higher than any other value
    else:
        return (('', 'inf'))    
    return (distro, distro_version)


def seperate_distribution_information_from_query(query, db_cursor):
    distribution = get_distro_infos_from_query(query, db_cursor)
    if distribution[0] and not MATCH_CPE_23_RE.match(query):
        query = re.sub(MATCH_DISTRO_QUERY, '', query.lower(), 1)
    # special handling of redhat
    if distribution[0] == 'redhat':
        distribution = ('rhel', distribution[1])
    return distribution, query


def is_known_distribution_version(distribution, db_cursor):
    db_distro_query = 'SELECT version, codename FROM distribution_codename_version_mapping WHERE source = ? AND version = ?'
    return bool(db_cursor.execute(db_distro_query, distribution).fetchone())


def get_distribution_data_from_version(version, db_cursor):
    '''Extract distribution data from version if version is clearly '''
    distribution = ('', 'inf')
    # get ubuntu data
    split_version = version.split('ubuntu')
    if len(split_version) == 2:
        split_ubuntu_version = split_version[1].split('.')
        if len(split_ubuntu_version) == 4 and not '~' in split_ubuntu_version[1]:
            distribution = ('ubuntu', '.'.join(split_ubuntu_version[1:-1]))
        else:
            split_ubuntu_version = split_version[1].split('~')[0].split('.')
            distribution = ('ubuntu', '.'.join(split_ubuntu_version[:-1]))
    # get build data -> only nvd and ubuntu has it in the version
    split_version = version.split('build')
    if len(split_version) == 2:
        split_ubuntu_version = split_version[1].split('.')
        if len(split_ubuntu_version) == 4 and not '~' in split_ubuntu_version[1]:
            distribution = ('ubuntu', '.'.join(split_ubuntu_version[1:-1]))
        else:
            split_ubuntu_version = split_version[1].split('~')[0].split('.')
            distribution = ('ubuntu', '.'.join(split_ubuntu_version[:-1]))
    # get debian data
    split_version = version.split('deb')
    if len(split_version) == 2 and not distribution[0] and not 'debian' in version:
        distribution = ('debian', '.'.join(split_version[1].split('u')))
    # get redhat data
    split_version = version.split('el')
    if len(split_version) == 2 and not distribution[0]:
        distribution = ('redhat', '.'.join(split_version[1].split('.')[0].split('_')))
    if distribution[0] and is_known_distribution_version(distribution, db_cursor):
        return distribution
    else:
        return ('', 'inf')


def is_possible_distro_query(query):
    return (MATCH_DISTRO.search(query.lower()) and MATCH_TWO_SOFTWARES_AND_VERSIONS.match(query.lower())) or MATCH_DISTRO_CPE.match(query)


def get_distro_infos_from_query(original_query, config):
    '''
    Extract distro version or codename from query and 
    query in the database for a suiting distro_version
    '''
 
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    db_distro_query = 'SELECT version, codename FROM distribution_codename_version_mapping'
    all_distro_versions_codenames_tuples = db_cursor.execute(db_distro_query).fetchall()
    # turn list of version_codename tuples in one list
    all_distro_versions_codenames = [version for distro_version in all_distro_versions_codenames_tuples for version in distro_version]
    possible_distro_query = MATCH_DISTRO_QUERY.search(original_query)
    if MATCH_CPE_23_RE.match(original_query):
        possible_distro_query = MATCH_DISTRO_QUERY.search(get_cpe_parts(original_query)[12])
    if possible_distro_query:
        distro, distro_version = possible_distro_query.groups()
        if distro_version in all_distro_versions_codenames:
            for version, codename in all_distro_versions_codenames_tuples:
                if distro_version == version or distro_version == codename:
                    distro_version = version
                    break
        else:
            distro_version = 'inf' # float of 'inf' is a value higher than any other value
    else:
        return (('', 'inf'))
    db_conn.close()
    return (distro.lower(), distro_version)


def seperate_distribution_information_from_query(query, config):
    distribution = get_distro_infos_from_query(query, config)
    if distribution[0] and not MATCH_CPE_23_RE.match(query):
        query = re.sub(MATCH_DISTRO_QUERY, '', query, 1)
    return distribution, query


def is_possible_distro_query(query):
    return MATCH_DISTRO.search(query.lower()) and MATCH_TWO_SOFTWARES_AND_VERSIONS.match(query.lower())


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD_MATCH, add_other_exploit_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, include_single_version_vulns=False, config=None):
    '''Search for known vulnerabilities based on the given query'''

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
        if is_possible_distro_query(query):
            # remove distro information before searching for a cpe
            distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            distribution, cpe_search_query = (('', 'inf')), query
        cpe_search_results = search_cpes(cpe_search_query, count=CPE_SEARCH_COUNT, threshold=software_match_threshold, config=config['cpe_search'])

        if not cpe_search_results['cpes']:
            return {query: {'cpe': None, 'vulns': {}, 'pot_cpes': cpe_search_results['pot_cpes']}}, []

        cpes = cpe_search_results['cpes']
        pot_cpes = cpe_search_results['pot_cpes']

        if not cpes:
            return {query: {'cpe': None, 'vulns': {}, 'pot_cpes': pot_cpes}}, []

        cpe = cpes[0][0]

    distribution = ('', 'inf')
    if is_possible_distro_query(cpe):
        distribution = get_distro_infos_from_query(cpe, db_cursor)

    # use the retrieved CPE to search for known vulnerabilities
    vulns = {}
    if is_good_cpe:
        equivalent_cpes = [cpe]  # only use provided CPE
    else:
        equivalent_cpes = get_equivalent_cpes(cpe, config)  # also search and use equivalent CPEs
    # change cpes to distribution cpes
    if distribution[0]:
        equivalent_cpes = [add_distribution_infos_to_cpe(cpe_, distribution) for cpe_ in equivalent_cpes]

    not_affected_cve_ids = []
    for cur_cpe in equivalent_cpes:
        cur_vulns, not_affected_cve_ids_returned = get_vulns(cur_cpe, db_cursor, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, add_other_exploit_refs=add_other_exploit_refs, distribution=distribution)
        not_affected_cve_ids += not_affected_cve_ids_returned
        for cve_id, vuln in cur_vulns.items():
            if cve_id not in vulns:
                vulns[cve_id] = vuln

    # delete not affected vulns
    for cve_id in not_affected_cve_ids:
        try:
            del vulns[cve_id]
        except:
            pass

    if close_cursor_after:
        db_cursor.close()
        db_conn.close()

    return {query: {'cpe': '/'.join(equivalent_cpes), 'vulns': vulns, 'pot_cpes': pot_cpes}}, not_affected_cve_ids


def parse_args():
    '''Parse command line arguments'''

    parser = argparse.ArgumentParser(description="Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)")
    parser.add_argument("-u", "--update", action="store_true", help="Download the latest version of the the local vulnerability and software database")
    parser.add_argument("--full-update", action="store_true", help="Fully (re)build the local vulnerability and software database")
    parser.add_argument("-k", "--api-key", type=str, help="NVD API key to use for updating the local vulnerability and software database")
    parser.add_argument("-f", "--format", type=str, default="txt", choices={"txt", "json"}, help="Output format, either 'txt' or 'json' (default: 'txt')")
    parser.add_argument("-o", "--output", type=str, help="File to write found vulnerabilities to")
    parser.add_argument("-q", "--query", dest="queries", metavar="QUERY", action="append", help="A query, either software title like 'Apache 2.4.39' or a CPE 2.3 string")
    parser.add_argument("--cpe-search-threshold", type=float, default=CPE_SEARCH_THRESHOLD_MATCH, help="Similarity threshold used for retrieving a CPE via the cpe_search tool")
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
        from updates.updater import run as run_updater
        run_updater(False, args.api_key, args.config)
    elif args.full_update == True:
        from updates.updater import run as run_updater
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
        if is_possible_distro_query(query):
            distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            distribution, cpe_search_query = ('', 'inf'), query
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
        for cur_cpe in equivalent_cpes:
            cur_vulns, not_affected_cve_ids_returned = search_vulns(cur_cpe, db_cursor, args.cpe_search_threshold, False, True, args.ignore_general_cpe_vulns, args.include_single_version_vulns, config)
            not_affected_cve_ids += not_affected_cve_ids_returned
            
            for cve_id, vuln in cur_vulns.items():
                if cve_id not in vulns[query]:
                    vulns[query][cve_id] = vuln
    
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
    db_conn.close()


if __name__ == '__main__':
    main()
