from cpe_search.cpe_search import search_cpes, perform_calculations
from thefuzz import  fuzz
import re
import sys
from cpe_version import CPEVersion
from .update_generic import *

SPLIT_VERSION = re.compile(r'^([v\d\~:]{0,2}[\d\.\-]+\w{0,2}[\d\.\-]+)(?<=\w)')
SPLIT_STRING_LETTERS_NUMBERS = re.compile(r'([a-z\-]+)([0-9]+[\.]?[0-9]*)(?:[^a-zA-Z0-9]+|$)')
ESCAPE_VERSION = re.compile(r'([\+\-\~\:])')
CPE_SEARCH_RESULT_DICT = {}
PACKAGE_CPE_MATCH_THRESHOLD = 0.42
NEW_CPES_INFOS = []
GENERAL_DISTRIBUTION_CPES = [
    'cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*', 
    'cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*', 
    'cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*', 
    'cpe:2.3:o:fedoraproject:fedora:*:*:*:*:*:*:*:*'
]
NAME_CPE_DICT = {
    'abuse-sdl': 'cpe:2.3:a:abuse:abuse-sdl:*:*:*:*:*:*:*:*',
    'aflplusplus': 'cpe:2.3:a:afl\+\+_project:afl\+\+:*:*:*:*:*:*:*:*',
    'aom': ' cpe:2.3:a:aomedia:aomedia:*:*:*:*:*:*:*:*',
    'apcupsd': 'cpe:2.3:a:apcupsd:apc_ups_daemon:*:*:*:*:*:*:*:*',
    'archvsync': 'cpe:2.3:a:debian:ftpsync:*:*:*:*:*:*:*:*',
    'adobe-flashplugin': 'cpe:2.3:a:adobe:flash_plugin:*:*:*:*:*:*:*:*', # non existent cpe
    'armagetronad': 'cpe:2.3:a:armagetron:armagetron_advanced:*:*:*:*:*:*:*:*',
    'dotnet': 'cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*',
    'libpgjava': 'cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*',
    'bzr': 'cpe:2.3:a:canonical:bazaar:*:*:*:*:*:*:*:*',
    'mc': 'cpe:2.3:a:midnight_commander:midnight_commander:*:*:*:*:*:*:*:*',
    'wv': 'cpe:2.3:a:wvware:wvware:*:*:*:*:*:*:*:*',
    'mozjs': 'cpe:2.3:a:mozilla:firefox_esr:*:*:*:*:*:*:*:*',
    'nvidia-graphics-drivers': 'cpe:2.3:a:nvidia:gpu_driver:*:-:*:*:unix:*:*:*',
    'kernel': 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*',
    'kernel-rt': 'cpe:2.3:o:linux:linux_kernel-rt:*:*:*:*:*:*:*:*'
}


def get_general_cpe(cpe):
    '''Return general cpe with no version set'''
    return ':'.join(cpe.split(':')[:5]+['*' for _ in range(8)])


def get_versionless_cpe(cpe):
    '''Return general cpe with no version set'''
    cpe_parts = cpe.split(':')
    cpe_parts[5] = '*'
    return ':'.join(cpe_parts)


def equal_name(name1, name2):
    '''Check whether two names are considered equal'''
    return name1.replace('-', ' ').replace('_', ' ') == name2.replace('-', ' ').replace('_', ' ')


def get_matching_cpe(name, name_version, version, search, cpes):
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
        count_name_matches = 0
        for cpe_ in unique_cpes:
            if name in cpe_:
                matching_cpe = cpe_
                count_name_matches += 1
        if count_name_matches > 1:
            matching_cpe = ''

    if not matching_cpe:
        # name in given cpes
        for cpe in unique_cpes:
            cpe_parts = cpe.split(':')
            if cpe_parts[4] in name or name in cpe_parts[4]:
                matching_cpe = cpe
                break
        else:
            matching_cpe = get_matching_general_cpe(name, version, cpes, unique_cpes, search)
            if not matching_cpe:
                return
            if len(unique_cpes) > 1:
                NAME_CPE_DICT[name] = get_versionless_cpe(matching_cpe)
    
    # used for subpackages of a package
    cpe_parts = matching_cpe.split(':')
    name_cpe = cpe_parts[4]
    if name_version != '-1' and name != name_cpe and name_cpe in name:
        cpe_parts[4] = name.replace(name+'-', '')
        matching_cpe = ':'.join(cpe_parts)
    matching_cpe = get_versionless_cpe(matching_cpe)
    return matching_cpe


def get_matching_general_cpe(name, version, cpes, cpe_set, search):
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

    all_cpes = []
    # cpe, cpe_version, with_cpes
    all_cpes += [(cpe[1], cpe[4].split('.')[0]) for cpe in cpes]
    if matching_cpes:
        all_cpes += [(cpe,'0', '') for cpe in matching_cpes]

    possible_cpes = ['', '', '']
    highest_value = ('', 0)
    for cpe_infos in all_cpes:
        cpe, cpe_version = cpe_infos
        vendor, product = cpe.split(':')[3:5]
        new_ratio =fuzz.token_set_ratio(cpe, search)/100.0
        if new_ratio > 0.24 and (cpe_version == version or cpe_version.split('.')[0] == version):
            new_ratio *= 1.4
        # prefer cpes with no os vendor
        if vendor in ['debian', 'ubuntu', 'redhat', 'gentoo', 'fedora']:
            new_ratio = new_ratio/4
        # prefer unix cpes
        if cpe.split(':')[9] == 'windows':
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
        if month2 < month1:
            return True
        else:
            return False
    else:
        return False


def summarize_statuses_with_version(statuses, fixed_status_names, version_field, dev_distro_name):
    '''Summarize statuses with same version to one entry'''
    relevant_statuses = []

    # filter out dev_distro_name
    if statuses[0][1] == '-1' or statuses[0][1] == dev_distro_name:
        relevant_statuses.append((statuses[0][0], dev_distro_name, ''))
        statuses = statuses[1:]

    # try to summarize entries with same version_end
    start_status = ({version_field: ''}, '', '')
    temp_statuses = []
    last_distro_version = ''
    for (status, distro_version, operator) in statuses:
        if operator or status['status'] not in  fixed_status_names \
                or distro_version == dev_distro_name \
                or (last_distro_version and not is_next_distro_version(last_distro_version, distro_version)) \
                or (start_status[0][version_field] and status[version_field]
                    and CPEVersion(get_clean_version(start_status[0][version_field], False)) != CPEVersion(get_clean_version(status[version_field], False))):
            relevant_statuses.append((status, distro_version, operator))
            start_status = ({version_field: ''},'','')
            last_distro_version = ''
            for temp_status in temp_statuses:
                relevant_statuses.append(temp_status)
            temp_statuses = []
            continue
        elif not start_status[1]:
            start_status = (status, distro_version, '>=')
        temp_statuses.append((status, distro_version, operator))
        last_distro_version = distro_version
    if start_status[1]:
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
    cpe_parts = cpe.split(':')
    if not version_end or version_end == '-1' or version_end == str(sys.maxsize):
        version = '*'
    cpe_parts[12] = re.sub(ESCAPE_VERSION, r'\\\1', version)
    # target_sw
    cpe_parts[10] = '%s%s_%s' % (extra_cpe, source, distro_version)

    cpe = ':'.join(cpe_parts)
    return cpe


def get_cpe_infos(cpe):
    '''Return perform calculations for given cpe'''
    calculations_string = cpe+';'
    return perform_calculations([calculations_string], -1)[0]


def is_cve_rejected(cve_id):
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


def get_version_end_ubuntu(version_end, status, note, software_version):
    '''Return version end, considering special ubuntu statuses'''
    version_end = get_clean_version(software_version, False)
    if (not version_end and status == 'not-affected') or status == 'DNE' :
        # no valid version found (occur with status not-affected and DNE)
        version_end = '-1'
        software_version = ''
    elif status == 'pending':
        if software_version:
            version_end = get_clean_version(software_version, True)
        else:
            version_end = str(sys.maxsize)
    elif status in ['needed, needs-triage', 'active', 'deferred']:
        version_end = str(sys.maxsize)
    elif status == 'ignored':
        if not note or any(note.startswith(string) for string in ['end of', 'code', 'superseded', 'was not-affected']):
            version_end = ''
        elif note.startswith('only'):
            version_end = '-1'
        elif not any(x in note for x in ['will not', 'intrusive', 'was', 'fix']):
            version_end = str(sys.maxsize)
        else:
            version_end = ''
    return version_end


def get_version_end(status, software_version):
    '''Return fitting version end'''
    version_end = '-1'
    if status == 'released':
        version_end = get_clean_version(software_version, True)
        if not version_end:
            version_end =  ''
    elif status == 'resolved':
        version_end = get_clean_version(software_version, True)
    # for debian
    elif status in ['open', 'undetermined']:
        version_end = str(sys.maxsize)
        software_version = ''
    else:
        # for ubuntu
        version_end = get_version_end_ubuntu(version_end=version_end, software_version=software_version, status=status, note=software_version)
    # remove all whitespaces, b/c ubuntu could return versions like ' 1.11.15. 1.12.1'
    version_end = version_end.replace(' ','')
    return version_end


def add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, source, db_cursor):
    '''Add cve with new cpe to vuln_db'''
    
    version_start = '0'
    is_cpe_version_start_including = False

    for cpe_ in cpes:
        if get_versionless_cpe(cpe_[1]) == matching_cpe:
            if CPEVersion(cpe_[4]) == CPEVersion(version_end) or CPEVersion(cpe_[1].split(':')[5]) == CPEVersion(version_end):
                return
            cpe_version_start, is_cpe_version_start_including = cpe_[2:4]
            cpe_version = cpe_[1].split(':')[5]
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
    if version_start == '0':
        version_start = ''
    if name_version and name_version != '-1' and not version_start:
        version_start = name_version
        is_cpe_version_start_including = True
    if version_end != '-1' and CPEVersion(version_start) >= CPEVersion(version_end):
        version_start = ''
        is_cpe_version_start_including = False
    
    db_cursor.execute('INSERT OR IGNORE INTO cve_cpe (cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including, source) VALUES (?, ?, ?, ?, ?, ?, ?)', (cve_id, distro_cpe, version_start, is_cpe_version_start_including , version_end, False, source))
    NEW_CPES_INFOS.append(get_cpe_infos(matching_cpe))


def add_not_found_packages(not_found_cpes, distribution, db_cursor):
    '''Add all not found packages to the db with a more or less suiting cpe'''
    for name, backport_cpes in not_found_cpes.items(): 
        possible_cpes = [cpe_[5] for cpe_ in backport_cpes if cpe_ == '']
        for cpe in possible_cpes:
            if name in cpe.split(':')[4] or equal_name(name, cpe.split(':')[4]):
                matching_cpe = get_versionless_cpe(cpe)
        else:
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
        if not matching_cpe or matching_cpe == 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*':
            matching_cpe = 'cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*' % (name, name)

        for note, distro_version, cve_id, name_version, _, status, extra_cpe in backport_cpes:
            if (status == 'released' or status == 'resolved') and not note:
                continue
            version_end = get_version_end(status, note)
            distro_in_cpe = distribution
            if distribution == 'redhat':
                distro_in_cpe = 'rhel'
            distro_cpe= get_distribution_cpe(distro_version, distro_in_cpe, matching_cpe, extra_cpe)
            if version_end:
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
    infos_cpe = ' '.join([attr for attr in cpe.split(':')[3:] if not attr in ['*', '-']])                    
    sim_score = fuzz.token_set_ratio(infos_cpe, name)/100.0
    return sim_score


def transform_cpe_uri_binding_to_formatted_string(cpe):
    '''Create formatted string out of uri binding'''
    cpe_parts = ['cpe', '2.3']
    # remove 'cpe:/' and get cpe_parts
    cpe_parts += cpe[5:].split(':')
    # formatted string has 11 components
    cpe_parts += ['']*(13-len(cpe_parts))
    return ':'.join([cpe_part if cpe_part else '*' for cpe_part in cpe_parts])


def create_table_distribution_codename_version_mapping():
    '''Create table for mapping codename to distribution version'''
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = CREATE_SQL_STATEMENTS['TABLES']['DISTRIBUTION_VERSION_CODENAME_MAPPING'][CONFIG['DATABASE']['TYPE']]
    # necessary because SQLite can't handle more than one query a time
    for query_part in query[:-1].split(';'):
        db_cursor.execute(query_part+';')
    db_conn.commit()
    db_conn.close()