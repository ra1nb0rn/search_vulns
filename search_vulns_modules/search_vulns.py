#!/usr/bin/env python3

from .generic_functions import *
from .process_nvd_matches import *
from .process_distribution_matches import (
    get_distribution_matches, 
    get_not_affected_cve_ids, 
    is_possible_distro_query, 
    seperate_distribution_information_from_query, 
    add_distribution_infos_to_cpe, 
    get_distro_infos_from_query, 
    get_distribution_data_from_version
)
from cpe_search.cpe_search import (
    is_cpe_equal,
    search_cpes,
    match_cpe23_to_cpe23_from_dict,
    create_cpes_from_base_cpe_and_query,
    create_base_cpe_if_versionless_query,
    get_possible_versions_in_query,
    get_cpe_parts,
)
from search_vulns_modules.config import _load_config
from updates.update_distributions_generic import get_clean_version

def get_vulns(cpe, db_cursor, ignore_general_cpe_vulns=False, add_other_exploit_refs=False, distribution=('', 'inf')):
    '''Get known vulnerabilities for the given CPE 2.3 string'''

    cpe_parts = get_cpe_parts(cpe)
    vulns = []

    # change current version to a suitable version for search vulns
    if cpe_parts[5] not in ('*', '-'):
        cpe_parts[5] = get_clean_version(cpe_parts[5], True)

    vulns += get_exact_vuln_matches(cpe, cpe_parts, distribution[0], db_cursor)
    vulns += get_vulns_version_start_end_matches(cpe, cpe_parts, db_cursor, distribution, ignore_general_cpe_vulns)
    if len(cpe_parts) > 12 and (cpe_parts[12] in ('-', '*') or MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_parts[12])):
        vulns += get_distribution_matches(cpe, cpe_parts, db_cursor, distribution, ignore_general_cpe_vulns)

    # reverse the list b/c distro information should be considered first
    vulns.reverse()

    # retrieve more information about the found vulns, e.g. CVSS scores and possible exploits
    detailed_vulns = {}
    for vuln_info in vulns:
        vuln, match_reason = vuln_info
        cve_id = vuln[0]
        if cve_id in detailed_vulns:
            continue

        query = 'SELECT edb_ids, description, published, last_modified, cvss_version, base_score, vector FROM cve WHERE cve_id = ?'
        edb_ids, descr, publ, last_mod, cvss_ver, score, vector = db_cursor.execute(query, (cve_id,)).fetchone()
        detailed_vulns[cve_id] = {'id': cve_id, 'description': descr, 'published': publ, 'modified': last_mod,
                                  'href': 'https://nvd.nist.gov/vuln/detail/%s' % cve_id, 'cvss_ver': cvss_ver,
                                  'cvss': score, 'cvss_vec': vector, 'vuln_match_reason': match_reason}

        edb_ids = edb_ids.strip()
        if edb_ids:
            detailed_vulns[cve_id]['exploits'] = []
            for edb_id in edb_ids.split(','):
                detailed_vulns[cve_id]['exploits'].append('https://www.exploit-db.com/exploits/%s' % edb_id)

        # add other exploit references
        if add_other_exploit_refs:
            # from NVD
            query = 'SELECT exploit_ref FROM nvd_exploits_refs INNER JOIN cve_nvd_exploits_refs ON nvd_exploits_refs.ref_id = cve_nvd_exploits_refs.ref_id WHERE cve_id = ?'
            nvd_exploit_refs = db_cursor.execute(query, (cve_id,)).fetchall()
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
            poc_in_github_refs = db_cursor.execute(query, (cve_id,)).fetchall()
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


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False, add_other_exploit_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, config=None):
    '''Search for known vulnerabilities based on the given query'''

    # create DB handle if not given
    if not config:
        config = _load_config()
    close_cursor_after = False
    if not db_cursor:
        db_conn_file = sqlite3.connect(config['DATABASE_FILE'])
        if keep_data_in_memory:
            db_conn_mem = sqlite3.connect(':memory:')
            db_conn_file.backup(db_conn_mem)
            db_cursor = db_conn_mem.cursor()
        else:
            db_cursor = db_conn_file.cursor()
        close_cursor_after = True

    # if given query is not already a CPE, retrieve a CPE that matches the query
    query = query.strip()
    cpe = query
    distribution = ('', 'inf')
    if not MATCH_CPE_23_RE.match(query):
        if is_possible_distro_query(query):
            # remove distro information before searching for a cpe
            distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            distribution, cpe_search_query = (('', 'inf')), query
        cpe = search_cpes(cpe_search_query, count=1, threshold=software_match_threshold, keep_data_in_memory=keep_data_in_memory, config=config['cpe_search'])
        if not cpe or not cpe[cpe_search_query]:
            return None
        else:
            check_str = cpe[cpe_search_query][0][0][8:]
            if any(char.isdigit() for char in cpe_search_query) and not any(char.isdigit() for char in check_str):
                return None

        cpe = cpe[cpe_search_query][0][0]
    elif not is_good_cpe:
        pot_matching_cpe = match_cpe23_to_cpe23_from_dict(cpe, keep_data_in_memory=keep_data_in_memory, config=config['cpe_search'])
        if pot_matching_cpe:
            cpe = pot_matching_cpe

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
        cur_vulns, not_affected_cve_ids_returned = get_vulns(cur_cpe, db_cursor, ignore_general_cpe_vulns=ignore_general_cpe_vulns, add_other_exploit_refs=add_other_exploit_refs, distribution=distribution)
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

    return vulns, not_affected_cve_ids


def search_vulns_return_cpe(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD, keep_data_in_memory=False, add_other_exploits_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, config=None):
    '''Search for known vulnerabilities based on the given query and return them with their CPE'''

    if not config:
        config = _load_config()

    query = query.strip()
    cpe, pot_cpes = query, []
    distribution = ('', 'inf')
    if not MATCH_CPE_23_RE.match(query):
        # if current query is not already a CPE, retrieve a CPE that matches the query
        cpe = query
        if is_possible_distro_query(query):
            distribution, distributionsless_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            distribution, distributionsless_query = ((None, 'inf')), query
        is_good_cpe = False
        cpes = search_cpes(distributionsless_query, count=5, threshold=0.25, keep_data_in_memory=keep_data_in_memory, config=config['cpe_search'])

        if not cpes or not cpes[distributionsless_query]:
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': []}}

        # always create related queries with supplied version number
        versions_in_query = get_possible_versions_in_query(distributionsless_query)
        # try to extract distribution information from version
        if not distribution[0] and versions_in_query:
            # versions_in_query[0] = complete version
            distribution = get_distribution_data_from_version(versions_in_query[0], db_cursor)
        for cpe, sim in cpes[distributionsless_query]:
            new_cpes = create_cpes_from_base_cpe_and_query(cpe, distributionsless_query)
            for new_cpe in new_cpes:
                # do not overwrite sim score of an existing CPE
                if any(is_cpe_equal(new_cpe, existing_cpe[0]) for existing_cpe in cpes[distributionsless_query]):
                    continue
                # add distribution infos to CPE if distribution query
                if new_cpe and distribution[0]:
                    new_cpe_distro = add_distribution_infos_to_cpe(new_cpe, distribution)
                    if not any(is_cpe_equal(new_cpe_distro, other[0]) for other in pot_cpes):
                        pot_cpes.append((new_cpe_distro, -1))
                # only add CPE if it was not seen before
                if new_cpe and not any(is_cpe_equal(new_cpe, other[0]) for other in pot_cpes):
                    pot_cpes.append((new_cpe, -1))

            if not any(is_cpe_equal(cpe, other[0]) for other in pot_cpes):
                pot_cpes.append((cpe, sim))

        # always create related queries without version number if query is versionless
        versionless_cpe_inserts, new_idx = [], 0
        for cpe, _ in pot_cpes:
            base_cpe = create_base_cpe_if_versionless_query(cpe, distributionsless_query.strip())
            if base_cpe:
                if ((not any(is_cpe_equal(base_cpe, other[0]) for other in pot_cpes)) and
                     not any(is_cpe_equal(base_cpe, other[0][0]) for other in versionless_cpe_inserts)):
                    versionless_cpe_inserts.append(((base_cpe, -1), new_idx))
                    new_idx += 1
                # add distribution_infos to cpe if distribution query
                if distribution[0]:
                    base_cpe_distro = add_distribution_infos_to_cpe(base_cpe, distribution)
                    if ((not any(is_cpe_equal(base_cpe_distro, other[0]) for other in pot_cpes)) and
                         not any(is_cpe_equal(base_cpe_distro, other[0][0]) for other in versionless_cpe_inserts)):
                        versionless_cpe_inserts.append(((base_cpe_distro, -1), new_idx))
                        new_idx += 1
            new_idx += 1

        for new_cpe, idx in versionless_cpe_inserts:
            pot_cpes.insert(idx, new_cpe)

        if cpes[distributionsless_query][0][1] < software_match_threshold:
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes}}

        # catch bad CPE matches
        bad_match = False
        check_str = cpes[distributionsless_query][0][0][8:]

        # ensure that the retrieved CPE has a number if query has a number
        if any(char.isdigit() for char in distributionsless_query) and not any(char.isdigit() for char in check_str):
            bad_match = True

        # if a version number is clearly detectable in query, ensure this version is somewhat reflected in the CPE
        cpe_has_matching_version = False
        for possible_version in versions_in_query:
            if any(char.isdigit() and char not in check_str for char in possible_version):
                continue
            cpe_has_matching_version = True
            break
        if not cpe_has_matching_version:
            bad_match = True

        if bad_match:
            if cpes[distributionsless_query][0][1] > software_match_threshold:
                return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes}}
            return {query: {'cpe': None, 'vulns': None, 'pot_cpes': cpes[distributionsless_query]}}

        # also catch bad match if query is versionless, but retrieved CPE is not
        cpe_version = get_cpe_parts(cpes[distributionsless_query][0][0])[5] if cpes[distributionsless_query][0][0].count(':') > 5 else ''
        if cpe_version not in ('*', '-'):
            base_cpe = create_base_cpe_if_versionless_query(cpes[distributionsless_query][0][0], distributionsless_query)
            if base_cpe:
                # add distribution_infos to cpe if distribution query
                if distribution[0]:
                    base_cpe = add_distribution_infos_to_cpe(base_cpe, distribution)
                # remove CPEs from related queries that have a version
                pot_cpes_versionless = []
                for i, (pot_cpe, score) in enumerate(pot_cpes):
                    cpe_version_iter = get_cpe_parts(pot_cpe)[5] if pot_cpe.count(':') > 5 else ''
                    if cpe_version_iter in ('', '*', '-'):
                        pot_cpes_versionless.append((pot_cpe, score))

                return {query: {'cpe': None, 'vulns': None, 'pot_cpes': pot_cpes_versionless}}

        cpe = cpes[distributionsless_query][0][0]

        if distribution[0]:
            cpe = add_distribution_infos_to_cpe(cpe, distribution)

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
        cur_vulns, not_affected_cve_ids_returned = search_vulns(cur_cpe, db_cursor, software_match_threshold, keep_data_in_memory, add_other_exploits_refs, True, ignore_general_cpe_vulns, config)
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

    return {query: {'cpe': '/'.join(equivalent_cpes), 'vulns': vulns, 'pot_cpes': pot_cpes}}