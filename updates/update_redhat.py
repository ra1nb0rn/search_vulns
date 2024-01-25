#!/usr/bin/env python3

import json
import os
import re
import requests
import sys
import subprocess

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

from bs4 import BeautifulSoup
from search_vulns import get_equivalent_cpes

from .update_generic import *
from .update_distributions_generic import *

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json

REDHAT_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'redhat_data_feeds')

REDHAT_NOT_FOUND_NAME = {}
REDHAT_RELEASES = {}
DB_CURSOR = None

REDHAT_UPDATE_SUCCESS = None
MATCH_RELEVANT_RHEL_CPE = re.compile(r'cpe:\/[ao]:redhat:(?:enterprise_linux|rhel_[\w]{3}):([0-9\.]{1,3})')
MATCH_RHEL_VERSION_IN_PACKAGE = re.compile(r'\.[Ee][Ll](\d{1,2}[_\.]\d{1,2})[_\.]?\d{0,2}')
CVE_REDHAT_API_URL = 'https://access.redhat.com/hydra/rest/securitydata'
GITHUB_REDHAT_API_DATA_URL = 'https://github.com/aquasecurity/vuln-list-redhat.git'
REQUEST_HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0'}
REDHAT_MAPPING_VERSION_CODENAME_URL = 'https://docs.fedoraproject.org/en-US/quick-docs/fedora-and-red-hat-enterprise-linux/'
REDHAT_EOL_DATA_API_URL = 'https://endoflife.date/api/rhel.json' 
DEBUG = False


def rollback_redhat():
    '''Performs rollback specific for redhat'''
    rollback()
    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)


def get_redhat_api_data():
    '''Download RedHat Api data from GitHub'''

    # Thanks to aquasecurity for providing the data of 
    # the RedHat Security API in a GitHub Repository
    # https://github.com/aquasecurity/vuln-list-redhat/tree/main

    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)

    # download RedHat data from a GitHub Repo
    return_code = subprocess.call(
        'git clone --depth 1 %s \'%s\''
        % (GITHUB_REDHAT_API_DATA_URL, REDHAT_DATAFEED_DIR),
        shell=True,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception('Could not download latest resources of RedHat Api from GitHub'))


def summarize_statuses_redhat(statuses):
    '''Summarize equal statuses to one entry'''
    relevant_statuses = [] # (status, redhat_version, operators)
    temp_statuses = []
    possible_min = True
    start_status = None

    # try to summarize entries with version_end = -1
    for i, (status, distro_version, _) in enumerate(statuses):

        # skip out of support scope
        if not status['version']:
            continue
        if i == 0 and not status['version'] == '-1':
            possible_min = False
        if not status['version'] == '-1':
            if possible_min:
                possible_min = False
                relevant_statuses.append((statuses[i-1][0], statuses[i-1][1], '<='))
                relevant_statuses.append((status, distro_version, ''))
                continue
            elif start_status:
                for s in temp_statuses:
                    relevant_statuses.append(s)
                temp_statuses = []
                start_status = None
            else:
                relevant_statuses.append((status, distro_version, ''))
        else:
            if possible_min:
                continue
            if not start_status:
                start_status = (status, distro_version)
            temp_statuses.append((status, distro_version, ''))
    
    if possible_min:
        start_status = (statuses[0][0], statuses[0][1])
        relevant_statuses.append((statuses[0][0], statuses[0][1], '<='))

    # try to summarize entries with same version_end
    if relevant_statuses:
        relevant_statuses = summarize_statuses_with_version(relevant_statuses, fixed_status_names=['Fixed', 'Will not fix'], version_field='version', dev_distro_name='upstream')

    return relevant_statuses


def get_redhat_version_codename_mapping():
    global REDHAT_UPDATE_SUCCESS

    try:
        redhat_mapping_initial_response = requests.get(url=REDHAT_MAPPING_VERSION_CODENAME_URL, headers=REQUEST_HEADERS)
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning(f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}')
        rollback_redhat()
        return f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}'
    if redhat_mapping_initial_response.status_code != requests.codes.ok:
        REDHAT_UPDATE_SUCCESS = False
        rollback_redhat()
        communicate_warning(f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}; received a non-ok response code.')
        return f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}; received a non-ok response code.'

    soup = BeautifulSoup(redhat_mapping_initial_response.text, "html.parser")
    try:
        table = soup.find('table', class_='tableblock frame-all grid-all stretch')
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning(f'An error occured when trying to parse the table for redhat version-codename-mapping from {REDHAT_MAPPING_VERSION_CODENAME_URL}')
        rollback_redhat()
        return f'An error occured when trying to parse the table for redhat version-codename-mapping from {REDHAT_MAPPING_VERSION_CODENAME_URL}'
    
    global REDHAT_RELEASES
    # hardcode mapping of first release because it is easier
    REDHAT_RELEASES['2.1'] = 'panama'
    # skip table header and the first two lines of the table
    for row in table.find_all('tr')[3:]:
        release, codename = row.find_all('td')[:2]
        release, codename = release.text.split()[-1], codename.text.lower()
        REDHAT_RELEASES[release] = codename


def get_redhat_eol_data():
    global REDHAT_UPDATE_SUCCESS

    headers = {'accept': 'application/json'}
 
    try:
        redhat_eol_api_response = requests.get(url=REDHAT_EOL_DATA_API_URL, headers=headers)
    except:
            REDHAT_UPDATE_SUCCESS = False
            communicate_warning(f'An error occured when making request to {REDHAT_EOL_DATA_API_URL}')
            rollback_redhat()
            return f'An error occured when making request to {REDHAT_EOL_DATA_API_URL}'
    if redhat_eol_api_response.status_code != requests.codes.ok:
        REDHAT_UPDATE_SUCCESS = False
        rollback_redhat()
        communicate_warning(f'An error occured when making initial request to {REDHAT_EOL_DATA_API_URL}; received a non-ok response code.')
        return f'An error occured when making initial request to {REDHAT_EOL_DATA_API_URL}; received a non-ok response code.'

    return redhat_eol_api_response.json()


def initialize_redhat_release_version_codename():
    '''Download redhat release data via redhat Security API'''
    
    if not QUIET:
        print('[+] Downloading RedHat version-codename-mapping data')

    get_redhat_version_codename_mapping()
    redhat_eol_json = get_redhat_eol_data()

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = 'INSERT INTO distribution_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)'

    # extract codename and version from json
    for release in redhat_eol_json:
        main_version = release['cycle']
        codename = REDHAT_RELEASES[main_version]
        support_expires = str(release['support'])
        esm_expires = str(release['extendedSupport'])
        latest_version = str(release['latest'])
        for i in range(int(latest_version.split('.')[1])+1):
            version =  main_version+'.'+str(i)
            db_cursor.execute(query, ('redhat', version, codename, support_expires, esm_expires))

    # add versions with no eol data
    for main_version, codename in REDHAT_RELEASES.items():
        if float(main_version)>=float(redhat_eol_json[-1]['cycle']):
            break
        if main_version == '3':
            count_subversions = 10
        elif main_version == '2.1':
            count_subversions = 8
        for i in range(count_subversions):
            version = main_version+'.'+str(i)
            db_cursor.execute(query, ('redhat', version, codename, '', ''))

    db_conn.commit()
    db_conn.close()


def add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, status, redhat_version, note, extra_cpe):
    '''Add given given redhat version in a package to REDHAT_NOT_FOUND_NAME'''
    try:
        REDHAT_NOT_FOUND_NAME[name].append((note, redhat_version, cve_id, name_version, matching_cpe, status, extra_cpe))
    except:
        REDHAT_NOT_FOUND_NAME[name] = [(note, redhat_version, cve_id, name_version, matching_cpe, status, extra_cpe)]


def process_cve(cve):
    '''Get cpes for all packages in a cve and add these information to the db'''
    cve_id = cve['cve_id']
    cpes = cve['cpes']
    packages = cve['affected_release'] + cve['package_state']
    # get general given application cpes
    general_given_cpes = [get_general_cpe(cpe[1]) for cpe in cpes if cpe[1].split(':')[2] == 'a']

    # skip cve if only hardware cpes
    if cpes and are_only_hardware_cpes(cpes):
        return

    packages_cpes = []
    relevant_package_infos = process_relevant_package_infos(packages) 

    package_names = set([name[2] for name in relevant_package_infos])
    relevant_packages = {}

    for package_name in package_names:
        relevant_packages[package_name] = [(package_info[0], package_info[1], '') for package_info in relevant_package_infos if package_info[2] == package_name]

    for package_name, relevant_package_info in relevant_packages.items():

        relevant_package_info.sort(key = lambda status:float(status[1]))

        # only try to summarize if more than 2 infos are given
        if len(relevant_package_info) > 2:
            relevant_package_info = summarize_statuses_redhat(relevant_package_info)
        
            relevant_package_info.sort(key = lambda status:float(status[1]))

            # highest version needs a '>=' as operator 
            if relevant_package_info:
                relevant_package_info[-1] = (relevant_package_info[-1][0], relevant_package_info[-1][1], '>=')

        all_dne_statuses = len([True for status_info, _, _ in relevant_package_info if status_info['version'] == '-1']) == len(relevant_package_info)
            
        matching_cpe = ''
        package_name, name_version = split_name(package_name)
        add_to_vuln_db_bool = True

        for status_infos, redhat_version, extra_cpe in relevant_package_info:
            status = status_infos['status']
            version = status_infos['version']

            # package_name is cpe
            if MATCH_RELEVANT_RHEL_CPE.match(package_name):
                add_to_vuln_db(cve_id, version, package_name, distro_cpe=package_name, name_version='', cpes=[], source='redhat', db_cursor=DB_CURSOR)
                continue
            # add to not found if initial cpe search wasn't successful
            if not add_to_vuln_db_bool:
                add_package_status_to_not_found(cve_id, matching_cpe, package_name, name_version, status, redhat_version, version, extra_cpe)
                continue
            if not matching_cpe:
                # virt:av/qemu-kvm -> qemu-kvm
                package_name = package_name.replace(':', ' ')
                if '/' in package_name:
                    package_name = package_name.split('/')[1]
                name_version, search = get_search_version_string(package_name, name_version, version)
                if len(package_names) == 1 and len(general_given_cpes) == 1 and package_name in general_given_cpes[0] and package_name != 'linux':
                    matching_cpe = get_general_cpe(cpes[0][1])
                else:
                    matching_cpe = get_matching_cpe(package_name, name_version, version, search, cpes)
                
                # linux-* package
                if not matching_cpe:
                    break
            
                # check whether similarity between name and cpe is high enough
                sim_score = cpe_matching_score(package_name, matching_cpe)
                if sim_score < PACKAGE_CPE_MATCH_THRESHOLD:
                    add_package_status_to_not_found(cve_id, matching_cpe, package_name, name_version, status, redhat_version, version, extra_cpe) 
                    add_to_vuln_db_bool = False
                    matching_cpe = ''
                    continue

                # check if similiar packages are part of the given cve
                matching_cpe, add_to_vuln_db_bool = check_similar_packages(cve_id, packages_cpes, matching_cpe, name_version, status, redhat_version, version, extra_cpe)
                # add packages to found packages for cve
                if add_to_vuln_db_bool:
                    best_match = False
                    if package_name == matching_cpe.split(':')[4]:
                        best_match = True
                    packages_cpes.append((matching_cpe, package_name, best_match))
                else:
                    continue
                
                # match found cpe to all previous not found packages
                match_not_found_cpe(cpes, matching_cpe, package_name)

            # package not relevant, b/c all statuses are 'not affected' and matching cpe is not in the given ones, 
            # so redhat doesn't correct NVD data, because CVE is already not shown for the given package
            if all_dne_statuses and get_general_cpe(matching_cpe) not in general_given_cpes and len(get_equivalent_cpes(matching_cpe, CONFIG)) == 1:
                break
            version_end = get_clean_version(version, True)
            distro_cpe= get_distribution_cpe(redhat_version, 'rhel', matching_cpe, extra_cpe)
            add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'redhat', DB_CURSOR)


def process_relevant_package_infos(packages):
    relevant_package_infos = []
    for package in packages:
        redhat_cpe = package['cpe']
        if not MATCH_RELEVANT_RHEL_CPE.match(redhat_cpe):
            continue
        redhat_version = MATCH_RELEVANT_RHEL_CPE.match(redhat_cpe).group(1)
        # extend redhat version
        try:
            package_name, version = package['package'].split(':', maxsplit=1)
            # remove attached '-0' to some package names
            if package_name[-2:] == '-0':
                package_name = package_name[:-2]
            # get exact redhat version from package if something like 'RedHat Enterprise Linux 7' is given
            # add two entries to database, one general and one specific
            if len(redhat_version.split('.')) == 1 and MATCH_RHEL_VERSION_IN_PACKAGE.search(version):
                redhat_version_specific = MATCH_RHEL_VERSION_IN_PACKAGE.search(version).group(1).replace('_', '.')
                relevant_package_infos.append(({'status': 'Fixed', 'version': version}, redhat_version_specific, package_name.lower()))
            package_fix_state = 'Fixed'
        except:
            try:
                package_fix_state = package['fix_state']
            except:
                # no package or no version in 'affected_release' given 
                try:
                    # no version given, e.g. 'kpatch-patch'
                    if not any(char.isdigit() for char in package['package']):
                        continue
                    package_name, version = package['package'].split('-', maxsplit=1)
                except:
                    package_name = transform_cpe_uri_binding_to_formatted_string(redhat_cpe)
                    version = package.split(':')[5]
            else:
                package_name = package['package_name']
                if package_fix_state in ['Affected', 'Fix deferred', 'New', 'Will not fix']:
                    version = str(sys.maxsize-1)
                elif package_fix_state == 'Under investigation':
                    version = str(sys.maxsize)
                elif package_fix_state == 'Not affected':
                    version = '-1'
                else:
                    version = ''
                # Missing state: 'Out of support scope' -> a product could be fixed by Extended life cycle support (ELS, paid), but not with the standard license
            
        relevant_package_infos.append(({'status': package_fix_state, 'version': version}, redhat_version, package_name.lower()))
    return relevant_package_infos


def check_similar_packages(cve_id, packages_cpes, matching_cpe, name_version, status, redhat_version, note, extra_cpe):
    '''Check whether given package name with found cpe is close to another package with the same cpe'''
    add_to_vuln_db_bool = True
    for cpe, name, best_match in packages_cpes:
        if best_match:
            continue
        if matching_cpe == cpe:
            cpe_parts = matching_cpe.split(':')
            if cpe_parts[4] in name:
                cpe_parts[4] = name
                matching_cpe = ':'.join(cpe_parts)
            else:
                add_package_status_to_not_found(cve_id, cpe, name, name_version, status, redhat_version, note, extra_cpe)
                add_to_vuln_db_bool = False
                continue
    return matching_cpe,add_to_vuln_db_bool


def match_not_found_cpe(cpes, matching_cpe, name):
    '''Add all not found entries with the same package name to vuln_db after a matching cpe was found'''
    try:
        backport_cpes = REDHAT_NOT_FOUND_NAME[name]
        for version, redhat_version, cve_id, name_version, _, status, extra_cpe in backport_cpes:
            version_end = get_version_end(status, version)
            distro_cpe = get_distribution_cpe(redhat_version, 'rhel', matching_cpe, extra_cpe)
            if version_end:
                add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'redhat', DB_CURSOR)
        del REDHAT_NOT_FOUND_NAME[name]
    except:
        pass


def get_redhat_data_from_files():
    '''Extract the cve data from redhat api data, saved in files'''
    cves_redhat = []
    api_path = os.path.join(REDHAT_DATAFEED_DIR, 'api')

    for dir in os.listdir(api_path):
        for filename in os.listdir(os.path.join(api_path, dir)):
            with open(os.path.join(api_path, dir, filename), 'r') as f:
                res_json = json.load(f)
                if not res_json:
                    print('[!] RedHat download failed')
                    communicate_warning('RedHat download failed')
                    rollback_redhat()
                    return 'RedHat download failed'
            cves_redhat.append(res_json)
            continue
    cves_redhat.sort(key=lambda cve: cve['name'])    
    return cves_redhat


def process_data():
    '''Process RedHat api data''' 
    if not QUIET:
        print('[+] Adding RedHat data to database')

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    # get cve data from vuln_db
    query = 'SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end FROM cve_cpe WHERE source == "nvd"'
    cve_cpe_list = db_cursor.execute(query, ()).fetchall()
    cve_cpe_list.sort(key=lambda cve: cve[0])
    db_conn.close()
    
    cves_redhat = get_redhat_data_from_files()
    cve_cpe_redhat = []
 
    pointer_cves_nvd = 0
    pointer_cve_cpe_redhat = 0
    found = False   # used for cves which occur more than one time in the cve_cpe_table
    length_cve_cpe_list = len(cve_cpe_list)

    # match cve and cpe
    for cve in cves_redhat:
        cve_id = cve['name']
        # fixed packages
        affected_release = cve['affected_release']
        if not affected_release:
            affected_release = []
        
        # not fixed packages
        package_state = cve['package_state'] 
        if not package_state:
            package_state = []

        # iterate through all cves from nvd
        for i in range(pointer_cves_nvd, length_cve_cpe_list):
            nvd_cve_id = cve_cpe_list[i][0]
            if cve_id ==  nvd_cve_id:
                if not found:
                    cve_cpe_redhat.append({'cve_id': cve_id, 'cpes': [], 'affected_release': affected_release, 'package_state': package_state})
                    found = True
                cve_cpe_redhat[pointer_cve_cpe_redhat]['cpes'].append(cve_cpe_list[i])                           
            elif found:
                found = False
                pointer_cve_cpe_redhat += 1
                pointer_cves_nvd = i
                break
        # cve_id not found in cve_cpe
        else:
            if is_cve_rejected(cve_id):
                continue
            else:
                cve_cpe_redhat.append({'cve_id': cve_id, 'cpes': [], 'affected_release': affected_release, 'package_state': package_state})
                pointer_cve_cpe_redhat += 1

    cves_redhat = []
    cve_cpe_list = []
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    global DB_CURSOR
    DB_CURSOR = db_conn.cursor()

    for cve in cve_cpe_redhat:
       process_cve(cve)
    
    # add all not found packages to vuln_db
    add_not_found_packages(REDHAT_NOT_FOUND_NAME, 'redhat', DB_CURSOR) 

    db_conn.commit()
    db_conn.close()


async def update_vuln_redhat_db():
    '''Update the vulnerability database for redhat'''

    global REDHAT_UPDATE_SUCCESS
    
    if not QUIET:
        print('[+] Downloading RedHat data feeds')

    try:
        get_redhat_api_data()
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning(f'Could not download RedHat vuln data from {GITHUB_REDHAT_API_DATA_URL}.')
        rollback_redhat()
        return f'Could not download RedHat vuln data from {GITHUB_REDHAT_API_DATA_URL}.'

    # get redhat releases data
    initialize_redhat_release_version_codename()

    try:
       process_data()
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning('Could not process vuln data from the RedHat Security Api')
        rollback_redhat()
        return 'Could not process vuln data from the RedHat Security Api'
    
    shutil.rmtree(REDHAT_DATAFEED_DIR)
    return False