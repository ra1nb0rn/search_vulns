from cpe_search.cpe_search import (
    search_cpes,
    perform_calculations,
    escape_string,
    get_cpe_parts
    )
from cpe_search.cpe_search import VERSION_MATCH_CPE_CREATION_RE
from thefuzz import  fuzz
import re
import sys
import os
import requests
import string
from cpe_version import CPEVersion
from .update_generic import *

SPLIT_VERSION = re.compile(r'^([v\d\~:]{0,2}[\d\.\-]+\w{0,2}[\d\.\-]+)(?<=\w)')
SPLIT_STRING_LETTERS_NUMBERS = re.compile(r'([a-z\-]+)([0-9]+[\.]?[0-9]*)(?:[^a-zA-Z0-9]+|$)')
ESCAPE_VERSION = re.compile(r'([\+\-\~\:])')
MAN_MAPPING_JSON_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'man_mapping.json')
CPE_SEARCH_RESULT_DICT = {}
PACKAGE_CPE_MATCH_THRESHOLD = 0.42
NEW_CPES_INFOS = []
GENERAL_DISTRIBUTION_CPES = [
    'cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*', 
    'cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*', 
    'cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*', 
    'cpe:2.3:o:fedoraproject:fedora:*:*:*:*:*:*:*:*'
]
NAME_CPE_DICT = {}


def init_manual_mapping():
    with open(MAN_MAPPING_JSON_FILE, 'r') as f:
        global NAME_CPE_DICT
        man_mappings = json.loads(f.read())
        for name, cpe in man_mappings.items():
            NAME_CPE_DICT[name] = cpe


def get_general_cpe(cpe):
    '''Return general cpe with no version set'''
    return ':'.join(get_cpe_parts(cpe)[:5]+['*' for _ in range(8)])


def get_versionless_cpe(cpe):
    '''Return general cpe with no version set'''
    cpe_parts = get_cpe_parts(cpe)
    # override version
    cpe_parts[5] = '*'
    # override update
    cpe_parts[6] = '*'
    return ':'.join(cpe_parts)


def equal_name(name1, name2):
    '''Check whether two names are considered equal'''
    return name1.replace('-', ' ').replace('_', ' ') == name2.replace('-', ' ').replace('_', ' ')


def get_matching_cpe(name, original_package_name, name_version, version, search, cpes):
    '''Get matching cpe for a given package '''
    unique_cpes = set([get_versionless_cpe(cpe[1]) for cpe in cpes])
    matching_cpe = ''
    # special handling of linux-* packages
    if name.startswith('kernel-source') or name.startswith('linux-source') or name == 'linux':
        return 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'
    elif name.startswith('linux-'):
        return
    # skip flatpak b/c it gets updates from software vendor and not os vendor
    elif 'flatpak' in name:
        return
    # if only one cpe in given cpes
    if len(unique_cpes) == 1:
        for name_ in re.findall(r'[a-zA-Z+\.]+', name):
            if name_ in cpes[0][1]:
                matching_cpe = get_versionless_cpe(cpes[0][1])
                break
    else:
        # count occurences of product name in given cpes
        # if only one entry. return this entry
        count_name_matches = 0
        for cpe_ in unique_cpes:
            if original_package_name in cpe_:
                matching_cpe = cpe_
                count_name_matches += 1
        if count_name_matches > 1:
            matching_cpe = ''

    if not matching_cpe:
        # name in given cpes
        for cpe in unique_cpes:
            cpe_parts = get_cpe_parts(cpe)
            if cpe_parts[4] == name or name == cpe_parts[4]:
                matching_cpe = cpe
                break
        else:
            matching_cpe = get_matching_general_cpe(name, original_package_name, version, cpes, unique_cpes, search)
            if not matching_cpe:
                return
            if len(unique_cpes) > 1:
                NAME_CPE_DICT[name] = get_versionless_cpe(matching_cpe)
    
    # used for subpackages of a package
    cpe_parts = get_cpe_parts(matching_cpe)
    name_cpe = cpe_parts[4]
    if name_version != '-1' and name != name_cpe and name_cpe in name:
        cpe_parts[4] = name.replace(name+'-', '')
        matching_cpe = ':'.join(cpe_parts)
    matching_cpe = get_versionless_cpe(matching_cpe)
    return matching_cpe


def get_matching_general_cpe(name, original_package_name, version, cpes, cpe_set, search):
    '''Get matching cpe for a given name '''
    # return hardcoded/ already found cpe for given name
    try:
        return NAME_CPE_DICT[name]
    except:
        try:
            return NAME_CPE_DICT[name+version]
        except:
            pass

    # stupid way of creating cpes, but it works sometimes
    custom_cpe = f'cpe:2.3:a:{name}:{name}:*:*:*:*:*:*:*:*'
    if len(name.split('-')) > 1:
        custom_cpe = f"cpe:2.3:a:{name.split('-')[0]}:{'_'.join(name.split('-')[1:]).replace(':', '_')}:*:*:*:*:*:*:*:*"
    if custom_cpe in cpe_set:
        return custom_cpe
     
    # check whether we already queried for the given search string
    try:
        matching_cpes = CPE_SEARCH_RESULT_DICT[search]
    except:
        try:
            iter_matching_cpes = iter(search_cpes(search, threshold=0.42, count=7, keep_data_in_memory=True).values())
            matching_cpes = next(iter_matching_cpes)
            if matching_cpes[0][1] > 0.85:
                return matching_cpes[0][0]
            matching_cpes = [get_versionless_cpe(cpe[0]) for cpe in matching_cpes]
        except:
            matching_cpes = []
        CPE_SEARCH_RESULT_DICT[search] = matching_cpes
        
    for cpe in matching_cpes:
        if  cpe in cpe_set:
            return cpe
        if get_cpe_parts(cpe)[4] == original_package_name:
            return cpe

    all_cpes = []
    # cpe, cpe_version, with_cpes
    all_cpes += [(cpe[1], cpe[4].split('.')[0]) for cpe in cpes]
    if matching_cpes:
        all_cpes += [(cpe,'0', '') for cpe in matching_cpes]

    possible_cpes = ['', '', '']
    highest_value = ('', 0)
    for cpe_infos in all_cpes:
        cpe, cpe_version = cpe_infos
        vendor, product = get_cpe_parts(cpe)[3:5]
        new_ratio =fuzz.token_set_ratio(cpe, search)/100.0
        if new_ratio > 0.24 and (cpe_version == version or cpe_version.split('.')[0] == version):
            new_ratio *= 1.4
        # prefer cpes with no os vendor
        if vendor in ['debian', 'ubuntu', 'redhat', 'gentoo', 'fedora']:
            new_ratio = new_ratio/4
        # prefer unix cpes
        if get_cpe_parts(cpe)[9] == 'windows':
            new_ratio *= 2/3
        
        if (name == product or search.split(' ')[-1] == product) and not possible_cpes[0]:
            possible_cpes[0] = cpe
            new_ratio *= 1.8
        elif equal_name(name, product) and not possible_cpes[1]:
            possible_cpes[1] = cpe
            new_ratio *= 1.5
        elif name.split('-')[0] in product and not possible_cpes[2]:
            possible_cpes[2] = cpe
            new_ratio *= 1.2

        if new_ratio > highest_value[1]:
            highest_value = (cpe, new_ratio)
    if highest_value[1] > 0.75 and not possible_cpes[0]:
        return highest_value[0]
    for cpe in possible_cpes:
        if cpe:
            return cpe
    if highest_value[1] > 0.49:
        return highest_value[0]
    return 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*'


def get_clean_version(version, is_good_version):
    '''Get clean version similar to the ones already in the database, e.g. 1:115.0.2+dfsg~ubuntu16.04 -> 115.0.2+dfsg~'''
    version_str_match = VERSION_MATCH_CPE_CREATION_RE.search(version)
    if version_str_match:
        # version_str_match(-1) = 1 -> hardcode version == '-1' to -1
        clean_version = version_str_match.group(0).strip() if version != '-1' else '-1'
        if ' ' in version:
            return ''
    else:
        if is_good_version:
            clean_version = version
            # 'released 0.10.3-1' -> '0.10.3-1'
            clean_version.replace('released ', '')
        else:
            return ''

    # split at distribution name
    for distro_name in ['ubuntu', 'debian', 'deb', '.rhel', '.el']:
        clean_version = clean_version.split(distro_name)[0]

    # remove special char at end of string
    if clean_version and clean_version[-1] in string.punctuation:
        clean_version = clean_version[:-1]
    
    # split at colon, e.g. '1:115.3.1' -> '115.3.1'
    split_colon = clean_version.split(':')
    if len(split_colon) == 2:
        if len(split_colon[0]) > len(split_colon[1]):
            clean_version = split_colon[0]
        else:
            clean_version = split_colon[1]
    return clean_version.lower()


def is_next_distro_version(version1,version2):
    '''Evaluates whether version2 is the next distro version after version1'''
    try:
        major1, month1 = version1.split('.')
    except:
        major1, month1 = version1, ''
    try:
        major2, month2 = version2.split('.')
    except:
        major2, month2 = version2, ''

    if major1 == major2:
        if month2 > month1:
            return True
        else:
            return False
    elif int(major1) == int(major2)-1:
        if not month1 and not month2:
            return True
        # only works because ubuntu has only two main releases per year
        if month2 < month1:
            return True
        else:
            return False
    else:
        return False


def summarize_statuses_with_version(statuses, dev_distro_name):
    '''Summarize statuses with same version to one entry'''
    relevant_statuses = []

    # filter out dev_distro_name
    if statuses[0][1] == '-1' or statuses[0][1] == dev_distro_name:
        relevant_statuses.append((statuses[0][0], dev_distro_name, ''))
        statuses = statuses[1:]

    start_status = None
    # only use '<=' for version_end == '-1' and not all statuses have version_end == '-1'
    possible_min = len(statuses) > 1 and statuses[0][0] == '-1' and not all(status[0] == '-1' for  status in statuses)
    temp_statuses = []
    last_distro_version = ''
    
    # try to summarize statuses until a certain status (<=) (possible_min)
    # and try the same from a certain status to the end (>=) (start_status)
    # summarizable if same version_end
    for i, (version_end, distro_version, operator) in enumerate(statuses):
        summarizable_status = True
        #check if last version == current version
        if temp_statuses:
            summarizable_status = version_end == temp_statuses[-1][0]
        elif relevant_statuses and relevant_statuses[-1][1] != dev_distro_name:
            summarizable_status = version_end == relevant_statuses[-1][0]
        # check if current distribution is the next after the last one or if current distro is not affected, undetermined or will not fix, 
        # b/c these statuses can be summarized no matter if it is the next distro version or not 
        summarizable_status = summarizable_status and ((last_distro_version and is_next_distro_version(last_distro_version, distro_version)) or version_end in ('-1', str(sys.maxsize), str(sys.maxsize-1)))
        if not summarizable_status:
            # use '<=' not only for one entry
            if possible_min:
                possible_min = False
                if i > 1:
                    relevant_statuses.append((statuses[i-1][0], statuses[i-1][1], '<='))
                else:
                    relevant_statuses.append((statuses[i-1][0], statuses[i-1][1], ''))
                # relevant_statuses.append((version_end, distro_version, ''))
                temp_statuses = []
                # continue
            elif start_status:
                for temp_status in temp_statuses:
                    relevant_statuses.append(temp_status)
                temp_statuses = []
                start_status = None
            else:
                relevant_statuses.append((version_end, distro_version, ''))
            last_distro_version = ''
        if not start_status and not possible_min:
            start_status = (version_end, distro_version, '>=')
        temp_statuses.append((version_end, distro_version, operator))
        last_distro_version = distro_version
    
    if possible_min and statuses:
        start_status = (statuses[0][0], statuses[0][1], '')
        relevant_statuses.append((statuses[0][0], statuses[0][1], '<='))
    
    if start_status:
        relevant_statuses.append(start_status)

    return relevant_statuses


def get_clean_version(version, is_good_version):
    '''Get clean version similar to the ones already in the database, e.g. 1:115.0.2+dfsg~ubuntu16.04 -> 115.0.2'''
    clean_version = SPLIT_VERSION.match(version)
    if clean_version:
        clean_version = clean_version.group(1)
        if ' ' in version:
            return ''
    else:
        if is_good_version:
            split_values = ['ubuntu', 'dfsg', '+', '~', 'build', 'deb']
            clean_version = version
            for value in split_values:
                clean_version = clean_version.split(value)[0]
            # 'released 0.10.3-1' -> '0.10.3-1'
            clean_version.replace('released ', '')
        else:
            return ''
    
    split_colon = clean_version.split(':')
    if len(split_colon) == 2:
        if len(split_colon[0]) > len(split_colon[1]):
            clean_version = split_colon[0]
        else:
            clean_version = split_colon[1]
    return clean_version.lower()


def get_distribution_cpe(version, version_end, distro_version, source, cpe, extra_cpe=''):
    '''Transform given cpe to cpe with distribution infos in target_sw and other'''
    cpe_parts = get_cpe_parts(cpe)
    # distribution_data in 'other' field of cpe
    cpe_parts[12] = '%s%s_%s' % (extra_cpe, source, distro_version)

    cpe = ':'.join(cpe_parts)
    return cpe


def get_cpe_infos(cpe):
    '''Return perform calculations for given cpe'''
    calculations_string = cpe+';'
    return perform_calculations([calculations_string], -1)[0]


def is_cve_rejected(cve_id, config):
    '''Return True if cve is rejected from MITRE'''
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = 'SELECT description FROM cve WHERE cve_id == ?'
    cve_description = db_cursor.execute(query, (cve_id, )).fetchone()
    try:
        cve_description = cve_description[0]
    except:
        return True
    if cve_description.startswith('Rejected'):
        return True
    else:
        return False


def get_cpe_parts(cpe):
    return re.split(r'(?<!\\):', cpe)


def add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, source, db_cursor):
    '''Add cve with new cpe to vuln_db'''
    
    version_start = '0'
    is_cpe_version_start_including = False
    version_start_nvd_lt_version_end = None

    # try to get with_cpes and version_start from matching cpe entries for the given package and cve
    for cpe_ in cpes:
        if get_versionless_cpe(cpe_[1]) == matching_cpe:
            if version_start_nvd_lt_version_end == None:
                version_start_nvd_lt_version_end = True
            cpe_version_start, is_cpe_version_start_including = cpe_[2:4]
            # version_end < version_start of nvd
            if version_start_nvd_lt_version_end and CPEVersion(cpe_version_start) < CPEVersion(version_end) and CPEVersion(get_cpe_parts(cpe_[1])[5]) < CPEVersion(version_end):
                version_start_nvd_lt_version_end = False
            if CPEVersion(cpe_[5]) == CPEVersion(version_end) or CPEVersion(get_cpe_parts(cpe_[1])[5]) == CPEVersion(version_end):
                return
            cpe_version = get_cpe_parts(cpe_[1])[5]
            if cpe_version in ('*', '-'):
                cpe_version = ''
            if is_cpe_version_start_including:
                if CPEVersion(version_end) >= CPEVersion(cpe_version_start) and CPEVersion(cpe_version_start) > CPEVersion(version_start):
                    version_start = cpe_version_start
                    is_cpe_version_start_including = True
            else:
                if CPEVersion(version_end) > CPEVersion(cpe_version_start) and CPEVersion(cpe_version_start) > CPEVersion(version_start):
                    version_start = cpe_version_start
                    is_cpe_version_start_including = False
                elif CPEVersion(version_end) > CPEVersion(cpe_version) and (CPEVersion(cpe_version) < CPEVersion(version_start) or version_start == '0'):
                    version_start = cpe_version
                    is_cpe_version_start_including = True

    # version_end < version_start of nvd -> not-affected, so use '-1' as version_end
    if version_start_nvd_lt_version_end:
        version_end = '-1'

    if version_start == '0':
        version_start = ''

    # set name_version as version_start, e.g. openssh097 -> version_start = 0.9.7
    if name_version and name_version != '-1' and not version_start:
        version_start = name_version
        is_cpe_version_start_including = True

    # remove start_version if start_version greater or equal to version_end
    if version_end != '-1' and CPEVersion(version_start) >= CPEVersion(version_end):
        version_start = ''
        is_cpe_version_start_including = False
    
    db_cursor.execute('INSERT OR IGNORE INTO cve_cpe (cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including, source) VALUES (?, ?, ?, ?, ?, ?, ?)', (cve_id, distro_cpe, version_start, is_cpe_version_start_including , version_end, False, source))
    NEW_CPES_INFOS.append(get_cpe_infos(matching_cpe))


def add_not_found_packages(not_found_cpes, distribution, db_cursor):
    '''Add all not found packages to the db with a more or less suiting cpe'''
    # iterate through all not found names
    for name, backport_cpes in not_found_cpes.items(): 
        possible_cpes = [cpe_[5] for cpe_ in backport_cpes if cpe_ == '']
        # try to find product name in cpe
        for cpe in possible_cpes:
            if name in get_cpe_parts(cpe)[4] or equal_name(name, get_cpe_parts(cpe)[4]):
                matching_cpe = get_versionless_cpe(cpe)
        else:
            # prepare search statement
            split_name = SPLIT_STRING_LETTERS_NUMBERS.match(name)
            if split_name:
                search = ' '.join(split_name.groups())
            else:
                search = name
            split_name = search.split('-')
            if len(split_name) > 1 and '.' in split_name[-1]:
                search = ' '.join(split_name[:-1])
            else:
                search = ' '.join(split_name)
            try:
                matching_cpe = NAME_CPE_DICT[name]
            except:
                try:
                    matching_cpe = next(iter(search_cpes(search, threshold=0.28, count=7, keep_data_in_memory=True).values()))[0][0]
                    matching_cpe = get_versionless_cpe(matching_cpe)
                except:
                    matching_cpe = ''
        # create an own cpe if no cpe could be found
        if not matching_cpe or matching_cpe == 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*':
            matching_cpe = 'cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*' % (name, name)

        # iterate through all not found entries for the current name and add an entry with the found cpe to the db
        for version_end, distro_version, cve_id, name_version, _, extra_cpe in backport_cpes:
            if not version_end:
                continue
            distro_in_cpe = distribution
            if distribution == 'redhat':
                distro_in_cpe = 'rhel'
            distro_cpe= get_distribution_cpe(distro_version, distro_in_cpe, matching_cpe, extra_cpe)
            add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, [], distribution, db_cursor)


def are_only_hardware_cpes(cpes):
    '''Test whether given cpes are all only hardware cpes'''
    if all([cpe[1].split(':')[2] == 'h' for cpe in cpes]):
        return True
    return False


def split_name(name):
    '''Split name in name and version, e.g.openssh097 -> openssh 097'''
    split_name = SPLIT_STRING_LETTERS_NUMBERS.match(name)
    if split_name:
        name = split_name.group(1).strip()
        name_version = split_name.groups()[-1]
    else:
        name_version = ''
    if name[-1] == '-':
        name = name[:-1]
    return name, name_version


def get_search_version_string(name, name_version, version):
    '''Return search string for cpe_search and updated name_version, e.g.: openssh 097 -> openssh 0.9.7 openssh0.9.7'''
    search = name
    if name_version:
        if name_version == version.replace('.', ''):
            name_version = version
        search = ' '.join([name, name_version, (name+name_version).split(' ')[-1]])
    search = ' '.join(search.split('-'))
    return name_version, search


def cpe_matching_score(name, cpe):
    '''Calculate matching score between given name and cpe'''
    infos_cpe = ' '.join([attr for attr in get_cpe_parts(cpe)[3:] if not attr in ['*', '-']])                    
    sim_score = fuzz.token_set_ratio(infos_cpe, name)/100.0
    return sim_score


def transform_cpe_uri_binding_to_formatted_string(cpe):
    '''Create formatted string out of uri binding'''
    cpe_parts = ['cpe', '2.3']
    # remove 'cpe:/' and get cpe_parts
    cpe_parts += [escape_string(cpe_part) for cpe_part in get_cpe_parts(cpe[5:])]
    # formatted string has 11 components
    cpe_parts += ['']*(13-len(cpe_parts))
    return ':'.join([cpe_part if cpe_part else '*' for cpe_part in cpe_parts])


def create_table_distribution_codename_version_mapping(config):
    '''Create table for mapping codename to distribution version'''
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = CREATE_SQL_STATEMENTS['TABLES']['DISTRIBUTION_VERSION_CODENAME_MAPPING'][CONFIG['DATABASE']['TYPE']]
    # necessary because SQLite can't handle more than one query a time
    for query_part in query[:-1].split(';'):
        db_cursor.execute(query_part+';')
    db_conn.commit()
    db_conn.close()