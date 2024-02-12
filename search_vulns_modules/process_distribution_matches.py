#!/usr/bin/env python3

from .generic_functions import *
from updates.update_distributions_generic import GENERAL_DISTRIBUTION_CPES

MATCH_DISTRO_QUERY = re.compile(r'(ubuntu|debian|redhat enterprise linux|redhat|rhel)[ _]?([\w\.]*)')
UNIX_CPES = ['cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*', 'cpe:2.3:o:opengroup:unix:-:*:*:*:*:*:*:*', 'cpe:2.3:o:unix:unix:*:*:*:*:*:*:*:*']


def add_distribution_infos_to_cpe(cpe, distribution):
    cpe_parts = get_cpe_parts(cpe)
    if distribution[1] == 'inf':
        cpe_parts[12] = distribution[0]
    else:
        cpe_parts[12] = '%s_%s' %(distribution)
    return ':'.join(cpe_parts)


def distribution_in_with_cpes(with_cpes, distribution_name):
    with_cpes_list = with_cpes.split(',')
    if any(cpe in with_cpes_list for cpe in UNIX_CPES) or GENERAL_DISTRIBUTION_CPES[distribution_name] in with_cpes_list:
        return True
    return False


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
        if cpe_version_start and cpe_version and cpe_version < CPEVersion(cpe_version_start) and not CPEVersion(cpe_version_start).considered_equal(cpe_version):
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
    query_cpe_parameters = ['%s:%%:>=%s' % (':'.join(cpe_parts[:5]), '%')]
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
        cpe_operator = get_cpe_parts(vuln_cpe)[12][0:2] if vuln_cpe.split(':')[12][0:2] in ('<=', '>=') else ''
        same_distro = distribution[0] == MATCH_DISTRO.search(get_cpe_parts(vuln_cpe)[12]).group(1)

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
        if len(vuln_cpes_nvd) > 0 and (most_specific_cpe and most_specific_cpe != vuln_cpe or not distribution[0] or not most_specific_cpe):
            is_cpe_vuln = False
            continue

        if cpe_version:
            is_cpe_vuln, vuln_match_reason = check_version_start_end(cpe, cpe_version, pot_vuln, distribution, ignore_general_cpe_vulns)
        else:
            is_cpe_vuln = pot_vuln[4] != '-1'
            vuln_match_reason = 'general_cpe_but_ok'
        if vuln_match_reason == 'version_start_not_included':
            is_cpe_vuln = False
        elif not is_cpe_vuln and same_distro:
            is_cpe_vuln, vuln_match_reason = True, 'not_affected'
        if is_cpe_vuln:
            vulns.append((pot_vuln, vuln_match_reason))            
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
    distro = distribution[0] if distribution[0] != 'rhel' else 'redhat'
    vuln_cpes_distro = set([cpe for cpe in vuln_cpes if cpe[1] == distro])
    most_specific_cpe  = get_most_specific_cpe(vuln_cpes_distro, distribution, cpe_version, vuln_cpes_nvd)
    return (vuln_cpes_nvd,vuln_cpes_distro,most_specific_cpe)


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
    distro, distro_version = distribution
    if distro == 'rhel':
        distro = 'redhat'
    db_distro_query = 'SELECT version, codename FROM distribution_codename_version_mapping WHERE source = ? AND version = ?'
    return bool(db_cursor.execute(db_distro_query, (distro, distro_version)).fetchone())


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
        distribution = ('rhel', '.'.join(split_version[1].split('.')[0].split('_')))
    if distribution[0] and is_known_distribution_version(distribution, db_cursor):
        return distribution
    else:
        return ('', 'inf')


def is_possible_distro_query(query):
    return (MATCH_DISTRO.search(query.lower()) and MATCH_TWO_SOFTWARES_AND_VERSIONS.match(query.lower())) or MATCH_DISTRO_CPE.match(query)