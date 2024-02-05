#!/usr/bin/env python3

import json
import os
import requests
import sys

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

from .update_generic import *
from .update_distributions_generic import *
from urllib.parse import unquote

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

DEBIAN_NOT_FOUND_NAME = {}
DEBIAN_RELEASES = {}
DB_CURSOR = None
CONFIG = None

REQUEST_HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0'}
DEBIAN_UPDATE_SUCCESS = None
CVE_DEBIAN_API_URL = 'https://security-tracker.debian.org/tracker/data/json'
DEBIAN_RELEASES_URL = 'https://debian.pages.debian.net/distro-info-data/debian.csv'
PACKAGENAME_CPE_MAPPING_URL = 'https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CPE/list'
DEBUG = False


def rollback_debian():
    '''Performs rollback specific for debian'''
    rollback()


def download_debian_release_version_codename_data():
    '''Download debian releases data'''

    global DEBIAN_UPDATE_SUCCESS

    if not QUIET:
        print('[+] Downloading debian releases data')
 
    try:
        debian_api_initial_response = requests.get(url=DEBIAN_RELEASES_URL)
    except:
            DEBIAN_UPDATE_SUCCESS = False
            communicate_warning('An error occured when making initial request to %s' % DEBIAN_RELEASES_URL)
            rollback_debian()
            return 'An error occured when making initial request to %s' % DEBIAN_RELEASES_URL
    if debian_api_initial_response.status_code != requests.codes.ok:
        DEBIAN_UPDATE_SUCCESS = False
        rollback_debian()
        print('An error occured when making initial request to %s; received a non-ok response code.' % DEBIAN_RELEASES_URL)
        return 'An error occured when making initial request to %s; received a non-ok response code.' % DEBIAN_RELEASES_URL

    if DEBUG:
        print(f'[+] Successfully received data from {DEBIAN_RELEASES_URL}.')

    return debian_api_initial_response.text.split('\n')


def initialize_debian_release_version_codename():
    '''Add release -> codename mapping to db and dict''' 

    releases_list = download_debian_release_version_codename_data()

    releases_dict = {}

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = 'INSERT INTO distribution_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)'

    # extract codename and version from csv
    for release in releases_list[1:]:
        split_release = release.split(',')
        # append empty string if last fields not given
        for i in range(len(split_release), 8):
            split_release.append('')
        version,_,codename,_,_,eol,eol_lts,eol_elts = split_release
        
        # sid = unstable development distribution
        if codename == 'sid':
            break
        db_cursor.execute(query, ('debian', version, codename, eol, eol_lts))
        releases_dict[codename] = {'version': version}

    db_conn.commit()
    db_conn.close()

    global DEBIAN_RELEASES
    DEBIAN_RELEASES = releases_dict
    

def add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, debian_version, version_end, extra_cpe):
    '''Add given debian version in a package to DEBIAN_NOT_FOUND_NAME'''
    try:
        DEBIAN_NOT_FOUND_NAME[name].append((version_end, debian_version, cve_id, name_version, matching_cpe, extra_cpe))
    except:
        DEBIAN_NOT_FOUND_NAME[name] = [(version_end, debian_version, cve_id, name_version, matching_cpe, extra_cpe)]


def get_debian_version_for_codename(codename):
    '''Return debian version for given codename'''
    if codename == 'sid':
        return '-1'
    return DEBIAN_RELEASES[codename]['version']


def get_version_end_debian(status_infos):
    status = status_infos['status']
    if status == 'resolved':
        version = status_infos['fixed_version']
    else:
        version = ''
    # urgency == unimportant -> version not affected (https://salsa.debian.org/security-tracker-team/security-tracker/-/blame/master/bin/tracker_data.py#L181)
    if version == '0':
        version = '-1'
    
    version_end = '-1'

    if status == 'resolved':
        version_end = get_clean_version(version, True)
    elif status == 'open':
        # sys.maxsize-1 is the highest value for us
        version_end = str(sys.maxsize-1)
    elif status == 'undetermined':
        # sys.maxsize -> could be a general info
        version_end = str(sys.maxsize)
        
    return version_end

        
def process_cve(cve):
    '''Get cpes for all packages of a cve and add these information to the db'''
    cve_id = cve['cve_id']
    cpes = cve['cpes']
    name, name_version = split_name(cve['package_name'])
    matching_cpe = cve['cpe']

    # check whether given cpe in given cpes
    if not matching_cpe in  [get_general_cpe(cpe[1]) for cpe in cpes] and name != 'linux':
        matching_cpe = ''

    # skip cve if only hardware cpes
    if cpes and are_only_hardware_cpes(cpes):
        return

    # build list of statuses with (version_end, debian_version, '') for every entry
    statuses = [(get_version_end_debian(status), get_debian_version_for_codename(codename), '') for codename, status in cve['releases'].items()]
    statuses.sort(key = lambda status:float(status[1]))
    add_to_vuln_db_bool = True

    # try to summarize statuses to decrease the size of the db
    relevant_statuses = summarize_statuses_with_version(statuses, dev_distro_name='sid')
    relevant_statuses.sort(key = lambda status:float(status[1]) if status[1].isdigit() else -1.0)

    for version_end, debian_version, extra_cpe in relevant_statuses:

        if not version_end:
            continue

        # add to not found if initial cpe search wasn't successful
        if not add_to_vuln_db_bool:
            add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, debian_version, version_end, extra_cpe)
            continue

        if not matching_cpe:
            matching_cpe = get_matching_cpe(name, cve['package_name'], name_version, version_end, search=name, cpes=cpes)
            
            # linux-* package
            if not matching_cpe:
                break
            
            # check whether similarity between name and cpe is high enough
            sim_score = cpe_matching_score(name, matching_cpe)
            if sim_score < PACKAGE_CPE_MATCH_THRESHOLD:
                add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, debian_version, version_end, extra_cpe) 
                add_to_vuln_db_bool = False
                matching_cpe = ''
                continue

            # match found cpe to all previous not found packages
            match_not_found_cpe(cpes, matching_cpe, name)
        distro_cpe= get_distribution_cpe(debian_version, 'debian', matching_cpe, extra_cpe)
        add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'debian', DB_CURSOR)


def match_not_found_cpe(cpes, matching_cpe, name):
    '''Add all entries with the same package name to vuln_db after a matching cpe was found'''
    try:
        backport_cpes = DEBIAN_NOT_FOUND_NAME[name]
        for version_end, debian_version, cve_id, name_version, _, extra_cpe in backport_cpes:
            distro_cpe = get_distribution_cpe(debian_version, 'debian', matching_cpe, extra_cpe)
            if version_end:
                add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'debian', DB_CURSOR)
        del DEBIAN_NOT_FOUND_NAME[name]
    except:
        pass


def initialize_packagename_cpe_mapping():
    '''Get mapping of package name to cpe from Debian Git Repo'''
    global DEBIAN_UPDATE_SUCCESS
    try:
        name_cpe_mapping = requests.get(url=PACKAGENAME_CPE_MAPPING_URL, headers=REQUEST_HEADERS).text
    except:
            DEBIAN_UPDATE_SUCCESS = False
            communicate_warning('An error occured when downloading data from %s' % (PACKAGENAME_CPE_MAPPING_URL))
            rollback_debian()
            return 'An error occured when downloading data from %s' % (PACKAGENAME_CPE_MAPPING_URL)
    if DEBUG:
        print(f'[+] Successfully received data from {PACKAGENAME_CPE_MAPPING_URL}.')
    
    for mapping in name_cpe_mapping.split('\n'):
        # e.g. in case of 'shellinabox;;cpe:/a:shellinabox_project:shellinabox' with two semicolons
        if len(mapping.split(';')) != 2:
            continue
        name, cpe = mapping.split(';')
        # url decode and escape cpe before transforming to cpe 2.3 formatted string
        NAME_CPE_DICT[name] = transform_cpe_uri_binding_to_formatted_string(unquote(cpe))


def merge_nvd_debian_data(cve_cpe_list, all_debian_infos):
    '''Add cpes from nvd to debian data'''
    cve_cpe_debian = []
 
    pointer_cves_nvd = 0
    pointer_cve_cpe_debian = 0
    found = False   # used for cves which occur more than one time in the cve_cpe_table
    length_cve_cpe_list = len(cve_cpe_list)
    last_cve_id = ''

    for cve in all_debian_infos:
        cve_id, package_name, cpe, releases = cve

        if cve_id == last_cve_id:
            cve_cpe_debian.append({'cve_id': cve_id, 'cpes': [], 'cpe': cpe, 'package_name': package_name, 'releases': releases})
            cve_cpe_debian[pointer_cve_cpe_debian]['cpes'] = cve_cpe_debian[pointer_cve_cpe_debian-1]['cpes']
            pointer_cve_cpe_debian += 1
            continue
        if is_cve_rejected(cve_id, CONFIG):
            continue
        # iterate through all cves from nvd
        for i in range(pointer_cves_nvd, length_cve_cpe_list):
            nvd_cve_id = cve_cpe_list[i][0]
            if cve_id ==  nvd_cve_id:
                if not found:
                    cve_cpe_debian.append({'cve_id': cve_id, 'cpes': [], 'cpe': cpe, 'package_name': package_name, 'releases': releases})
                    found = True
                cve_cpe_debian[pointer_cve_cpe_debian]['cpes'].append(cve_cpe_list[i])                           
            elif found:
                found = False
                pointer_cve_cpe_debian += 1
                pointer_cves_nvd = i
                break
        # cve_id not found in cve_cpe
        else:
            cve_cpe_debian.append({'cve_id': cve_id, 'cpes': [], 'cpe': cpe, 'package_name': package_name, 'releases': releases})
            pointer_cve_cpe_debian += 1
        last_cve_id = cve_id
    return cve_cpe_debian
    

def process_data(cves_debian):
    '''Process debian api data''' 
    
    if not QUIET:
        print('[+] Adding debian data to database')

    db_conn = get_database_connection(CONFIG['DATBASE'], CONFIG['DATABASE_FILE'])
    db_cursor = db_conn.cursor()

    # get cve data from vuln_db
    query = 'SELECT cve_id, cpe, with_cpes, cpe_version_start, is_cpe_version_start_including, cpe_version_end FROM cve_cpe'
    cve_cpe_list = db_cursor.execute(query, ()).fetchall()
    cve_cpe_list.sort(key=lambda cve: cve[0])
    db_conn.close()
    
    all_debian_infos = []

    for package_name, cves in cves_debian.items():
        try:
            cpe = NAME_CPE_DICT[package_name]
        except:
            cpe = ''
        for cve_id, cve_infos in cves.items():
            if cve_id.startswith('CVE'):
                all_debian_infos.append((cve_id, package_name, cpe, cve_infos['releases']))

    all_debian_infos.sort(key=lambda cve_id: cve_id[0])

    cve_cpe_debian = merge_nvd_debian_data(cve_cpe_list, all_debian_infos)

    cves_debian = []
    cve_cpe_list = []
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    global DB_CURSOR
    DB_CURSOR = db_conn.cursor()

    for cve in cve_cpe_debian:
        process_cve(cve)
    
    # add all not found packages to vuln_db
    add_not_found_packages(DEBIAN_NOT_FOUND_NAME, distribution='debian', db_cursor=DB_CURSOR) 
    db_conn.commit()
    db_conn.close()


async def update_vuln_debian_db(config):
    '''Update the vulnerability database for debian'''

    global DEBIAN_UPDATE_SUCCESS

    global CONFIG
    CONFIG = config

    create_table_distribution_codename_version_mapping(config)
    initialize_debian_release_version_codename()
    initialize_packagename_cpe_mapping()

    if not QUIET:
        print('[+] Downloading debian data feeds')


    try:
        cves_debian = json.loads(requests.get(url=CVE_DEBIAN_API_URL, headers=REQUEST_HEADERS).text)
    except:
            DEBIAN_UPDATE_SUCCESS = False
            communicate_warning('An error occured when downloading data from %s' % (CVE_DEBIAN_API_URL))
            rollback_debian()
            return 'An error occured when downloading data from %s' % (CVE_DEBIAN_API_URL)

    init_manual_mapping()

    try:
        process_data(cves_debian)
    except:
        DEBIAN_UPDATE_SUCCESS = False
        communicate_warning('Could not process vuln data from the Debian Security Api')
        rollback_debian()
        return 'Could not process vuln data from the Debian Security Api'

    return False