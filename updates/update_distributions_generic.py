from thefuzz import  fuzz
import re
import sys
import requests
import string
from urllib.parse import unquote
from .update_generic import *
from search_vulns_modules.generic_functions import get_cpe_parts

from cpe_search.cpe_search import search_cpes
from cpe_search.cpe_search import get_all_cpes, TEXT_TO_VECTOR_RE

SPLIT_VERSION = re.compile(r'^([v\d\~:]{0,2}[\d\.\-]+\w{0,2}[\d\.\-]+)(?<=\w)')
SPLIT_STRING_LETTERS_NUMBERS = re.compile(r'([a-z\-]+)([0-9]+[\.]?[0-9]*[a-z]?)(?:[^a-zA-Z0-9]+|$)')
ESCAPE_STRING_RE = re.compile(r'((?<!\\)[^a-zA-Z0-9\-\_\\\.\s])')

MAN_MAPPING_JSON_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'man_mapping.json')
PACKAGENAME_CPE_MAPPING_URL = 'https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CPE/list'

CPE_SEARCH_RESULT_DICT = {}
PACKAGE_CPE_MATCH_THRESHOLD = 0.42
NEW_CPES_INFOS = []
ALL_CPES_NVD = []
NAME_CPE_DICT = {}


def init_manual_mapping():
    with open(MAN_MAPPING_JSON_FILE, 'r') as f:
        global NAME_CPE_DICT
        man_mappings = json.loads(f.read())
        for name, cpe in man_mappings.items():
            NAME_CPE_DICT[name] = cpe


def load_all_cpes(config):
    global ALL_CPES_NVD
    ALL_CPES_NVD = get_all_cpes(config['cpe_search'])


def escape_string(str):
    return re.sub(ESCAPE_STRING_RE, r'\\\1', str)


def get_general_cpe(cpe):
    '''Return general cpe with no field after product set'''
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


def get_matching_cpe(name, original_package_name, version, search, cpes):
    '''Get matching cpe for a given package '''
    unique_cpes = set([get_versionless_cpe(cpe[1]) for cpe in cpes])
    matching_cpe = ''
    # special handling of linux-* packages
    if name.startswith('kernel-source') or name.startswith('linux-source') or name == 'linux':
        return ('cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*', True)
    # do not add entry for every possible kernel version
    elif name.startswith('linux-'):
        return (None, True)
    # skip flatpak b/c it gets updates from software vendor and not os vendor
    elif 'flatpak' in name:
        return (None, True)
    # hardcoded java cpe
    elif 'java' in original_package_name and 'openjdk' in original_package_name:
        return ('cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*', True)
    # if only one cpe in given cpes
    perfect_match = True
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
            cpe_parts_ = get_cpe_parts(cpe_)
            if cpe_parts_[3].startswith(original_package_name) or cpe_parts_[3].endswith(original_package_name)\
                or cpe_parts_[4].startswith(original_package_name) or cpe_parts_[4].endswith(original_package_name):
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
            matching_cpe, perfect_match = get_matching_general_cpe(name, original_package_name, version, cpes, unique_cpes, search)
            if not matching_cpe:
                return (None, True)
            # add found name to mapping
            if len(unique_cpes) > 1:
                NAME_CPE_DICT[name] = get_versionless_cpe(matching_cpe)
    
    matching_cpe = get_versionless_cpe(matching_cpe)
    return (matching_cpe, perfect_match)


def get_matching_general_cpe(package_name, original_package_name, package_version, cpes, unique_cpes_set, search):
    '''Get matching cpe for a given name '''
    # First idea: return hardcoded/ already found cpe for given name
    for n in [package_name, original_package_name, package_name+package_version]:
        if n in NAME_CPE_DICT.keys():
            return (NAME_CPE_DICT[n], True)

    # stupid way of creating cpes, but it works sometimes
    custom_cpes = [f'cpe:2.3:a:{package_name}:{package_name}:*:*:*:*:*:*:*:*']
    if len(package_name.split('-')) > 1:
        custom_cpes.append(f"cpe:2.3:a:{package_name.split('-')[0]}:{'_'.join(package_name.split('-')[1:]).replace(':', '_')}:*:*:*:*:*:*:*:*")
        custom_cpes.append(f"cpe:2.3:a:{package_name.split('-')[-1]}:{package_name.split('-')[-1]}:*:*:*:*:*:*:*:*")
        custom_cpes.append(f"cpe:2.3:a:{package_name.split('-')[0]}:{package_name.split('-')[0]}:*:*:*:*:*:*:*:*")

    # Second idea: return custom cpe if in given cpes
    for custom_cpe in custom_cpes:
        if custom_cpe in unique_cpes_set:
            return (custom_cpe, True)
    # return custom cpe if already in cpe_dictionary
    for custom_cpe in custom_cpes:
        if custom_cpe in ALL_CPES_NVD:
            return (custom_cpe, True)

    # get results from cpe_search and return if matching one found
    try:
        # check whether we already queried for the given search string
        matching_cpes = CPE_SEARCH_RESULT_DICT[search]
    except:
        iter_matching_cpes = iter(search_cpes(search, threshold=0.42, count=7).values())
        matching_cpes = next(iter_matching_cpes)
        if matching_cpes and matching_cpes[0][1] > 0.85:
            return (matching_cpes[0][0], True)
        matching_cpes = [get_versionless_cpe(cpe[0]) for cpe in matching_cpes]
        CPE_SEARCH_RESULT_DICT[search] = matching_cpes

    # Third idea: return cpe from cpe_search if in cpes from nvd or name field matches the one from a nvd cpe
    for cpe in matching_cpes:
        if  cpe in unique_cpes_set:
            return (cpe, True)
        if get_cpe_parts(cpe)[4] == original_package_name:
            return (cpe, True)

    all_cpes = []
    all_cpes += [(cpe[1], cpe[4].split('.')[0]) for cpe in cpes] # (cpe, cpe_version)
    if matching_cpes:
        all_cpes += [(cpe,'0') for cpe in matching_cpes]

    possible_cpes = ['', '', '']
    highest_value = ('', 0)
    name_parts = TEXT_TO_VECTOR_RE.findall(package_name)

    # Last idea: find best suiting cpe in cpes from cpe_search and given cpes for cve and 
    for cpe_infos in all_cpes:
        cpe, cpe_version = cpe_infos
        cpe_vendor, cpe_product = get_cpe_parts(cpe)[3:5]
        new_ratio =fuzz.token_set_ratio(cpe, search)/100.0
        if new_ratio > 0.24 and (cpe_version == package_version or cpe_version.split('.')[0] == package_version):
            new_ratio *= 1.4
        # prefer cpes with no os vendor
        if cpe_vendor in ['debian', 'ubuntu', 'redhat', 'gentoo', 'fedora']:
            new_ratio = new_ratio/4
        # prefer unix cpes
        if get_cpe_parts(cpe)[9] == 'windows':
            new_ratio *= 2/3

        # same name increase the ratio
        if (package_name == cpe_product or search.split(' ')[-1] == cpe_product) and not possible_cpes[0]:
            possible_cpes[0] = cpe
            new_ratio *= 1.8
        elif equal_name(package_name, cpe_product) and not possible_cpes[1]:
            possible_cpes[1] = cpe
            new_ratio *= 1.5
        elif any(name_part == cpe_product for name_part in name_parts) and not possible_cpes[2]:
            possible_cpes[2] = cpe
            new_ratio *= 1.25

        if new_ratio > highest_value[1]:
            highest_value = (cpe, new_ratio)

    if highest_value[1] > 0.75 and not possible_cpes[0]:
        return (highest_value[0], False)
    for cpe in possible_cpes:
        if cpe:
            return (cpe, False)
    if highest_value[1] > 0.49:
        return (highest_value[0], False)

    return ('cpe:2.3:a:*:*:*:*:*:*:*:*:*:*', False)


def is_next_distro_version(version1,version2):
    '''Evaluates whether version2 is the next distro version after version1'''
    
    # get major and subversion from release version
    try:
        major1, subversion1 = version1.split('.')
    except:
        major1, subversion1 = version1, ''
    try:
        major2, subversion2 = version2.split('.')
    except:
        major2, subversion2 = version2, ''

    if major1 == major2:
        if subversion2 > subversion1:
            return True
        else:
            return False
    elif int(major1) == int(major2)-1:
        if not subversion1 and not subversion2:
            return True
        # only works because ubuntu has only two main releases per year
        if subversion2 < subversion1:
            return True
        else:
            return False
    else:
        return False


def summarize_statuses_with_version(statuses, summarize_skipping_versions, dev_distro_name):
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
        summarizable_status = summarizable_status and ((last_distro_version and is_next_distro_version(last_distro_version, distro_version)) or (version_end in ('-1', str(sys.maxsize), str(sys.maxsize-1)) and summarize_skipping_versions))
        if not summarizable_status:
            # use '<=' not only for one entry
            if possible_min:
                possible_min = False
                if i > 0:
                    relevant_statuses.append((statuses[i-1][0], statuses[i-1][1], '<='))
                else:
                    relevant_statuses.append((statuses[i-1][0], statuses[i-1][1], ''))
                temp_statuses = []
            # add <= entry
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

    if start_status:
        # overwrite entry with >= operator, so no duplicate entries are written
        if len(relevant_statuses)>0 and relevant_statuses[-1][1] == start_status[1]:
            relevant_statuses[-1] = start_status
        else:
            relevant_statuses.append(start_status)

    if possible_min and statuses:
        start_status = (statuses[0][0], statuses[0][1], '')
        relevant_statuses.append((statuses[0][0], statuses[0][1], '<='))

    return relevant_statuses


def get_clean_version(version, is_good_version):
    '''Get clean version similar to the ones already in the database, e.g. 1:115.0.2+dfsg~ubuntu16.04 -> 115.0.2'''
    clean_version = SPLIT_VERSION.match(version)
    if clean_version:
        clean_version = clean_version.group(1)
        if ' ' in version:
            return ''
    # more aggressive splitting if we now that the given version is really a version
    if is_good_version:
        split_values = ['ubuntu', 'dfsg', '+', '~', 'build', 'deb', '.el']
        clean_version = version
        for value in split_values:
            clean_version = clean_version.split(value)[0]
        # 'released 0.10.3-1' -> '0.10.3-1'
        clean_version.replace('released ', '')

    if not clean_version:
        return ''

    split_colon = clean_version.split(':')
    if len(split_colon) == 2:
        if len(split_colon[0]) > len(split_colon[1]):
            clean_version = split_colon[0]
        else:
            clean_version = split_colon[1]
    return clean_version.lower()


def get_distribution_cpe(distro_version, source, cpe, extra_cpe=''):
    '''Transform given cpe to cpe with distribution infos in it'''
    cpe_parts = get_cpe_parts(cpe)
    # distribution_data in 'other' field of cpe
    cpe_parts[12] = '%s%s_%s' % (extra_cpe, source, distro_version)

    cpe = ':'.join(cpe_parts)
    return cpe


def is_cve_rejected(cve_id, config):
    '''Return True if cve is rejected from MITRE'''
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
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


def add_basename_to_package_names(relevant_package_infos, package_names):
    relevant_packages = []
    for package_name in package_names:
        # skip all entries with flatpak b/c these packages get updates directly from the maintainer and not from the distribution
        if 'flatpak' in package_name:
            continue

        # try to get base package, e.g. openssl for compat-openssl
        split_package_name, _ = split_name(package_name)
        base_name_package = split_package_name
        for name in package_names:
            split_name_, _ = split_name(name)
            if split_package_name == split_name_:
                continue
            if split_package_name.startswith(split_name_) or split_package_name.endswith(split_name_):
                if len(base_name_package) > len(split_name_):
                    base_name_package = split_name_

        # create list of relevant packages for a certain name, list of (version_end, redhat_version, operator) with operator in ('', '<=','>=')
        relevant_package_info = []
        for package_info in relevant_package_infos:
            if package_info[2] == package_name:
                relevant_package_info.append(((package_info[0], package_info[1], '')))
        relevant_packages.append((package_name, base_name_package, relevant_package_info))
    return relevant_packages


def add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, source, db_cursor):
    '''Add cve with new cpe to vuln_db'''

    version_start = '0'
    is_cpe_version_start_including = False
    version_start_nvd_lt_version_end = None
    start_versions = []

    # remove leading wrong characters
    matching_cpe = matching_cpe[matching_cpe.find('c'):]
    distro_cpe = distro_cpe[distro_cpe.find('c'):]

    if name_version == '0':
        name_version = ''

    # version_end = -2 represent EoL
    # if eol entry is necessary, version_end should be changed earlier, so skip entry here
    if version_end == '-2':
        return

    # try to get version_start from matching cpe entries for the given package and cve
    for cpe_ in cpes:
        if get_versionless_cpe(cpe_[1]) == matching_cpe:
            if version_start_nvd_lt_version_end == None:
                version_start_nvd_lt_version_end = True
            cpe_version_start_loop, is_cpe_version_start_including_loop = cpe_[2:4]
            cpe_version_loop = get_cpe_parts(cpe_[1])[5]
            if cpe_version_loop in ('*', '-'):
                cpe_version_loop = ''
            # prefix with zero if necessary
            if cpe_version_loop and re.match(r'\.\d+[\d\.]*', cpe_version_loop):
                cpe_version_loop = '0'+cpe_version_loop
            # version_end < version_start of nvd
            if version_start_nvd_lt_version_end and CPEVersion(cpe_version_start_loop) < CPEVersion(version_end) and CPEVersion(cpe_version_loop) < CPEVersion(version_end):
                version_start_nvd_lt_version_end = False
            if CPEVersion(cpe_[4]) == CPEVersion(version_end) or CPEVersion(cpe_version_loop) == CPEVersion(version_end):
                return
            # find suiting version start entries
            if is_cpe_version_start_including_loop: 
                if CPEVersion(version_end) >= CPEVersion(cpe_version_start_loop) and CPEVersion(cpe_version_start_loop) > CPEVersion(version_start):
                    version_start = cpe_version_start_loop
                    is_cpe_version_start_including = True
            else:
                if CPEVersion(version_end) > CPEVersion(cpe_version_start_loop) and CPEVersion(cpe_version_start_loop) > CPEVersion(version_start):
                    version_start = cpe_version_start_loop
                    is_cpe_version_start_including = False
                elif CPEVersion(version_end) > CPEVersion(cpe_version_loop) and (CPEVersion(cpe_version_loop) < CPEVersion(version_start) or version_start == '0'):
                    version_start = cpe_version_loop
                    is_cpe_version_start_including = True
            start_versions.append(CPEVersion(version_start))

    # set name_version as version_start, e.g. openssh097 -> version_start = 0.9.7, try to use name_version if close enough to already found version
    if all([name_version, name_version != '-1', all([x in string.digits or x in string.ascii_lowercase or x == '.' for x in name_version]), all([x in string.digits or x == '.' for x in version_start])]):
        # version extracted from package_name should not be too far away from nvd data
        if not version_start or (all(c.isdigit() for c in name_version) and 0.7<(float('.'.join(version_start.split('.')[:2]))/float('.'.join(name_version.split('.')[:2]))<1.3)):
            # same base version but version_start from nvd is more precise -> false
            if name_version != version_start.split('.')[0]:
                # name_version not already represented in cpe
                if  all(name_version != part[-len(name_version):] for part in get_cpe_parts(matching_cpe)[3:5]):
                    version_start = re.sub(r'(\d)(?=\d)',r'\1.', name_version) if not '.' in name_version else name_version
                    is_cpe_version_start_including = True

    # version_end < version_start of nvd -> remove start_version
    if version_start_nvd_lt_version_end:
        version_start = ''
        is_cpe_version_start_including = False

    # remove start_version if start_version greater or equal to version_end
    if version_end != '-1' and CPEVersion(version_start) >= CPEVersion(version_end):
        version_start = ''
        is_cpe_version_start_including = False

    # if no similar packages with a different name_version exist and no exact version_end, set version_start to minimal start version
    if not name_version and version_end in ('-1', str(sys.maxsize-1), str(sys.maxsize)):
        version_start = str(min(start_versions, default=''))
        is_cpe_version_start_including = False

    # 0 is no valid version start
    if version_start == '0':
        version_start = ''

    # write new entry to database
    db_cursor.execute('INSERT OR IGNORE INTO cve_cpe (cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including, source) VALUES (?, ?, ?, ?, ?, ?, ?)', (cve_id, distro_cpe, version_start, is_cpe_version_start_including , version_end, False, source))
    NEW_CPES_INFOS.append(matching_cpe)


def add_not_found_packages(not_found_cpes, distribution, db_cursor):
    '''Add all not found packages to the db with a more or less suiting cpe'''
    # iterate through all not found names
    for name, entries in not_found_cpes.items(): 
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
        for version_end, distro_version, cve_id, name_version, _, extra_cpe in entries:
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
        # something like apache2 or libssh2 has its own cpe
        if len(name_version) == 1:
            search = ' '.join([name+name_version, name])
        else:
            search += ' '.join([name, name_version, (name+name_version).split(' ')[-1]])
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


def initialize_packagename_cpe_mapping():
    '''Get mapping of package name to cpe from Debian Git Repo'''
    try:
        name_cpe_mapping = requests.get(url=PACKAGENAME_CPE_MAPPING_URL, headers=REQUEST_HEADERS).text
    except:
            communicate_warning('An error occured when downloading data from %s' % (PACKAGENAME_CPE_MAPPING_URL))
            return 'An error occured when downloading data from %s' % (PACKAGENAME_CPE_MAPPING_URL)
    if DEBUG:
        print(f'[+] Successfully received data from {PACKAGENAME_CPE_MAPPING_URL}.')
    
    for mapping in name_cpe_mapping.split('\n'):
        # e.g. in case of 'shellinabox;;cpe:/a:shellinabox_project:shellinabox' with two semicolons
        if len(mapping.split(';')) != 2:
            continue
        name, cpe = mapping.split(';')
        # do not overwrite manual mapping
        if name not in NAME_CPE_DICT.keys():
            # url decode and escape cpe before transforming to cpe 2.3 formatted string
            NAME_CPE_DICT[name] = transform_cpe_uri_binding_to_formatted_string(unquote(cpe))
    return False


def create_table_distribution_codename_version_mapping(config):
    '''Create table for mapping codename to distribution version'''
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = CREATE_SQL_STATEMENTS['TABLES']['DISTRIBUTION_VERSION_CODENAME_MAPPING'][config['DATABASE']['TYPE']]
    # necessary because SQLite can't handle more than one query a time
    for query_part in query[:-1].split(';'):
        db_cursor.execute(query_part+';')
    db_conn.commit()
    db_conn.close()