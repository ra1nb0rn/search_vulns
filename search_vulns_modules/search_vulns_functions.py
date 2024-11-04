#!/usr/bin/env python3

from .generic_functions import *
from .process_distribution_matches import (
    get_distribution_matches, 
    get_not_affected_cve_ids, 
    is_possible_distro_query, 
    seperate_distribution_information_from_query, 
    add_distribution_infos_to_cpe, 
    get_distro_infos_from_query, 
    get_distribution_data_from_version
)
from cpe_search.cpe_search import search_cpes
from search_vulns_modules.config import _load_config

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
                                  "href": "https://nvd.nist.gov/vuln/detail/%s" % cve_id, "cvss_ver": str(cvss_ver),
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
    return detailed_vulns


def get_vulns(cpe, db_cursor, ignore_general_cpe_vulns=False, ignore_general_distribution_vulns= False, include_single_version_vulns=False, add_other_exploit_refs=False, distribution=('', 'inf')):
    """Get known vulnerabilities for the given CPE 2.3 string"""

    cpe_parts = get_cpe_parts(cpe)
    cpe_version = CPEVersion(cpe_parts[5])
    vulns = []
    not_affected_cve_ids = []

    general_cpe_prefix_query = ':'.join(get_cpe_parts(cpe)[:5]) + ':'
    if 'mariadb' in str(type(db_cursor)):  # backslashes have to be escaped for MariaDB
        general_cpe_prefix_query = general_cpe_prefix_query.replace('\\', '\\\\')

    query = ('SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, ' +
             'is_cpe_version_end_including FROM cve_cpe WHERE cpe LIKE ? AND source == "nvd"')
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
                is_cpe_vuln = is_version_start_end_matching(cpe_parts, version_start, version_start_incl, version_end, version_end_incl)
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

    # query for non-nvd entries, either b/c of given cpes or for entries with no nvd data  
    if cpe_parts[12] in ('-', '*') or MATCH_DISTRO_CPE_OTHER_FIELD.match(cpe_parts[12]):
        vulns_distro = get_distribution_matches(cpe, cpe_parts, db_cursor, distribution, ignore_general_distribution_vulns)
        not_affected_cve_ids = get_not_affected_cve_ids(vulns_distro)
        vulns += vulns_distro

    # reverse the list b/c distro information should be considered first
    vulns.reverse()

    # retrieve more information about the found vulns, e.g. CVSS scores and possible exploits
    return get_vuln_details(db_cursor, vulns, add_other_exploit_refs), not_affected_cve_ids


def search_vulns(query, db_cursor=None, software_match_threshold=CPE_SEARCH_THRESHOLD_MATCH, add_other_exploit_refs=False, is_good_cpe=False, ignore_general_cpe_vulns=False, include_single_version_vulns=False, ignore_general_distribution_vulns=False, config=None):
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
    distribution = ('', 'inf')

    # check if given query contains distribution information
    if is_possible_distro_query(query):
        distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
    else:
        possible_versions = get_possible_versions_in_query(query)
        if possible_versions:
            distribution = get_distribution_data_from_version(possible_versions[0], db_cursor)
        cpe_search_query = query

    # query is not a cpe
    if not MATCH_CPE_23_RE.match(query_stripped):
        is_good_cpe = False
        if is_possible_distro_query(query):
            # remove distro information before searching for a cpe
            distribution, cpe_search_query = seperate_distribution_information_from_query(query, db_cursor)
        else:
            distribution, cpe_search_query = (('', 'inf')), query

        cpe_search_results = search_cpes(cpe_search_query, count=CPE_SEARCH_COUNT, threshold=software_match_threshold, config=config['cpe_search'])

        pot_cpes = cpe_search_results['pot_cpes']
        cpes = cpe_search_results['cpes']
        # add distribution information to all cpes
        if distribution[0]:
            pot_cpes = [(add_distribution_infos_to_cpe(cpe_[0], distribution), cpe_[1]) for cpe_ in pot_cpes]

        if not cpes:
            return {query: {'cpe': None, 'vulns': {}, 'pot_cpes': pot_cpes, 'version_status': {}}}, []

        if not cpes:
            return {query: {'cpe': None, 'vulns': {}, 'pot_cpes': pot_cpes}}, []

        cpe = cpes[0][0]

    # get distribution information from cpe
    if is_possible_distro_query(cpe):
        distribution = get_distro_infos_from_query(cpe, db_cursor)

    # remove unused subversion from distribution version, e.g. 9.2.3 -> 9.2
    if distribution[0]:
        distro_version_parts = distribution[1].split('.')
        distribution_version = '.'.join(distro_version_parts[:2])
        if distribution[1].endswith('_esm'):
            distribution_version += '_esm'
        if len(distro_version_parts) > 2:
            distribution = (distribution[0], distribution_version)

    # use the retrieved CPE to search for known vulnerabilities
    vulns = {}
    if is_good_cpe:
        equivalent_cpes = [cpe]  # only use provided CPE
    else:
        equivalent_cpes = get_equivalent_cpes(cpe, config)  # also search and use equivalent CPEs
    # change cpes to distribution cpes
    if distribution[0]:
        equivalent_cpes = [add_distribution_infos_to_cpe(cpe_, distribution) for cpe_ in equivalent_cpes]

    # actual query for vulns
    not_affected_cve_ids = []
    for cur_cpe in equivalent_cpes:
        cur_vulns, not_affected_cve_ids_returned = get_vulns(cur_cpe, db_cursor, ignore_general_cpe_vulns=ignore_general_cpe_vulns, ignore_general_distribution_vulns=ignore_general_distribution_vulns, include_single_version_vulns=include_single_version_vulns, add_other_exploit_refs=add_other_exploit_refs, distribution=distribution)
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

    # add outdated software / endoflife.date information
    eol_info = {}
    for equiv_cpe in equivalent_cpes:
        eol_info = retrieve_eol_info(equiv_cpe, db_cursor)
        if eol_info:
            break

    if close_cursor_after:
        db_cursor.close()
        db_conn.close()

    return {query: {'cpe': '/'.join(equivalent_cpes), 'vulns': vulns, 'pot_cpes': pot_cpes, 'version_status': eol_info}}, not_affected_cve_ids