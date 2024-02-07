#!/usr/bin/env python3

from .generic_functions import *
from .process_distribution_matches import distribution_in_with_cpes


def get_exact_vuln_matches(cpe, cpe_parts, distribution_name, db_cursor):
    '''Get vulns whose cpe entry matches the given one exactly'''

    query_cpe1 = ':'.join(cpe_parts[:6]) + '%%:' + cpe_parts[6] + ':%%'

    # create main CPE to query for and alt cpes with wildcards '*' and '-' replaced by each other
    query_cpes = [query_cpe1]
    repl_version, repl_update = '', ''
    if cpe_parts[5] == '*':
        repl_version = '-'
    elif cpe_parts[5] == '-':
        repl_version = '*'

    if repl_version:
        query_cpes.append(':'.join(cpe_parts[:5]) + ':' + repl_version + '%%:' + cpe_parts[6] + ':%%')

    if cpe_parts[6] == '*':
        repl_update = '-'
    elif cpe_parts[6] == '-':
        repl_update = '*'

    if repl_update:
        query_cpes.append(':'.join(cpe_parts[:6]) + ':' + repl_update + '%%')

    if repl_version and repl_update:
        query_cpes.append(':'.join(cpe_parts[:5]) + ':' + repl_version + '%%:' + repl_update + ':%%')

    # query for vulns with all retrieved variants of the supplied CPE
    or_str = 'OR cpe LIKE ?' * (len(query_cpes) - 1)
    query = 'SELECT DISTINCT cpe, cve_id, with_cpes FROM cve_cpe WHERE cpe LIKE ? ' + or_str
    pot_vulns = db_cursor.execute(query, query_cpes).fetchall()
    vulns = []
    for vuln_cpe, cve_id, with_cpes in pot_vulns:
        # if with_cpes and distribution given, check  if current cpe is a distro_cpe and if distro in with_cpes
        if with_cpes and distribution_name:
            if not (MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_parts[12]) and distribution_in_with_cpes(with_cpes, distribution_name)):
                continue
        version_cpe = get_cpe_parts(vuln_cpe)[5]
        is_version_matching = (cpe_parts[5] == version_cpe) or (CPEVersion(version_cpe).considered_equal(CPEVersion(cpe_parts[5])))
        if is_cpe_included_after_version(cpe, vuln_cpe) and is_version_matching:
            vulns.append(((cve_id, with_cpes), 'exact_cpe'))
    return vulns


def get_vulns_version_start_end_matches(cpe, cpe_parts, db_cursor, distribution, ignore_general_cpe_vulns=False):
    '''
    Get vulnerability data that is stored in the DB more generally,
    e.g. with version_start and version_end information
    '''
    
    vulns = []
    cpe_version = ''

    if len(cpe_parts) > 5 and cpe_parts[5] not in ('-', '*'):  # for CPE 2.3
        cpe_version = cpe_parts[5]

    # query DB for general CPE-vuln data, potentially with cpe_version_start and cpe_version_end fields
    general_cpe_nvd_data = set()
    query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
             'is_cpe_version_end_including, with_cpes FROM cve_cpe WHERE cpe LIKE ? OR cpe LIKE ? OR cpe LIKE ? AND source = \'nvd\'')
    get_cpes_query = 'SELECT cpe FROM cve_cpe WHERE cpe LIKE ? AND cve_id = ? AND source = \'nvd\''

    for cur_part_idx in range(5, len(cpe_parts)):
        if cpe_parts[cur_part_idx] not in ('*', '-'):
            cur_cpe_prefix = ':'.join(cpe_parts[:cur_part_idx])
            cpe_wildcards = ['%s::%%' % cur_cpe_prefix, '%s:-:%%' % cur_cpe_prefix, '%s:*:%%' % cur_cpe_prefix]
            general_cpe_nvd_data |= set(db_cursor.execute(query, cpe_wildcards).fetchall())

            # remove vulns that have a more specific exact CPE, which cur_cpe_prefix is a prefix of
            found_vulns_cpes = {}
            remove_vulns = set()
            for pot_vuln in general_cpe_nvd_data:
                cve_id, vuln_cpe, with_cpes = pot_vuln[0], pot_vuln[1], pot_vuln[6]
                version_start, version_end = pot_vuln[2], pot_vuln[4]
                # if with_cpes and distribution given, check  if current cpe is a distro_cpe and if distro in with_cpes
                if with_cpes and distribution[0]:
                    if not (MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_parts[12]) and distribution_in_with_cpes(with_cpes, distribution[0])):
                        remove_vulns.add(pot_vuln)
                        continue
                if not version_start and not version_end:
                    if cve_id not in found_vulns_cpes:
                        vuln_cpes = set(db_cursor.execute(get_cpes_query, (cur_cpe_prefix+':%%', cve_id)))
                        found_vulns_cpes[cve_id] = vuln_cpes
                    if len(found_vulns_cpes[cve_id]) > 1:
                        remove_vulns.add(pot_vuln)
            general_cpe_nvd_data -= remove_vulns

    if not cpe_version:
        found_vulns_cpes = {}
        general_query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
                         'is_cpe_version_end_including, with_cpes FROM cve_cpe WHERE cpe LIKE ?')
        general_vulns = set(db_cursor.execute(general_query, (':'.join(cpe_parts[:5])+':%%', )))
        all_general_vulns = []
        for vuln_data in (general_cpe_nvd_data | general_vulns):
            if not MATCH_DISTRO_CPE.match(vuln_data[1]):
                all_general_vulns.append((vuln_data, 'general_cpe_but_ok'))
        return all_general_vulns

    # check version information of potential vulns to determine whether given version is actually vulnerable
    vulns = []
    cpe_version = CPEVersion(cpe_version)
    for pot_vuln in general_cpe_nvd_data:
        is_cpe_vuln, vuln_match_reason = check_version_start_end(cpe, cpe_version, pot_vuln, distribution, ignore_general_cpe_vulns)
        if is_cpe_vuln:
            vulns.append((pot_vuln, vuln_match_reason))
    return vulns