#!/usr/bin/env python3

import asyncio
import json
import os
import re
import requests
import sys

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

import aiohttp
from aiolimiter import AsyncLimiter
from search_vulns import get_equivalent_cpes

from .update_generic import *
from .update_distributions_generic import *

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json

UBUNTU_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'ubuntu_data_feeds')

UBUNTU_NOT_FOUND_NAME = {}
DB_CURSOR = None

UBUNTU_UPDATE_SUCCESS = None
CVE_UBUNTU_API_URL = 'https://ubuntu.com/security/cves.json'
DEBUG = False

def rollback_ubuntu():
    '''Performs rollback specific for ubuntu'''
    rollback()
    if os.path.isdir(UBUNTU_DATAFEED_DIR):
        shutil.rmtree(UBUNTU_DATAFEED_DIR)


async def api_request(headers, params, requestno, url):
    '''Perform request to API for one task'''

    global UBUNTU_UPDATE_SUCCESS

    if UBUNTU_UPDATE_SUCCESS is not None and not UBUNTU_UPDATE_SUCCESS:
        return None

    retry_limit = 3
    retry_interval = 6
    for _ in range(retry_limit + 1):
        async with aiohttp.ClientSession() as session:
            try:
                cve_api_data_response = await session.get(url=url, headers=headers, params=params)
                if cve_api_data_response.status == 200 and cve_api_data_response.text is not None:
                    if DEBUG:
                        print(f'[+] Successfully received data from request {requestno}.')
                    return await cve_api_data_response.json()
                else:
                    if DEBUG:
                        print(f'[-] Received status code {cve_api_data_response.status} on request {requestno} Retrying...')
                await asyncio.sleep(retry_interval)
            except Exception as e:
                if UBUNTU_UPDATE_SUCCESS is None:
                    communicate_warning('Got the following exception when downloading vuln data via API: %s' % str(e))
                UBUNTU_UPDATE_SUCCESS = False
                return None


def summarize_statuses_ubuntu(statuses):
    '''Summarize equal statuses to one entry'''
    relevant_statuses = [] # (status, ubuntu_version, operators)
    temp_statuses = []
    possible_min = True
    start_status = None

    # filter out upstream
    if statuses[0][1] == '-1':
        relevant_statuses.append((statuses[0][0], 'upstream', ''))
        statuses = statuses[1:]

    # try to summarize entries with version_end = -1
    for i, (status, distro_version) in enumerate(statuses):

        summarizable_status = status['status'] == 'DNE' or (status['status'] in ('not-affected', 'pending') and not get_clean_version(status['description'], False))
        if i == 0 and not summarizable_status:
            possible_min = False
        if not summarizable_status:
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
    
    if possible_min and statuses:
        start_status = (statuses[0][0], statuses[0][1])
        relevant_statuses.append((statuses[0][0], statuses[0][1], '<='))
    
    if start_status:
        relevant_statuses.append((start_status[0], start_status[1], '>='))

    # try to summarize entries with same version_end
    relevant_statuses = summarize_statuses_with_version(relevant_statuses, fixed_status_names=['released', 'not-affected', 'pending'], version_field='description', dev_distro_name='upstream')

    return relevant_statuses


def download_ubuntu_release_codename_mapping():
    '''Download ubuntu release data via Ubuntu Security API'''
      
    global UBUNTU_UPDATE_SUCCESS

    if not QUIET:
        print('[+] Downloading ubuntu releases data')

    # initial request to set paramters
    headers = {'accept': 'application/json'}
    api_url =  CVE_UBUNTU_API_URL.replace('cves', 'releases')
 
    try:
        ubuntu_api_initial_response = requests.get(url=api_url, headers=headers)
    except:
            UBUNTU_UPDATE_SUCCESS = False
            communicate_warning('An error occured when making initial request to https://ubuntu.com/security/releases.json')
            rollback_ubuntu()
            return 'An error occured when making initial request to https://ubuntu.com/security/releases.json'
    if ubuntu_api_initial_response.status_code != requests.codes.ok:
        UBUNTU_UPDATE_SUCCESS = False
        rollback_ubuntu()
        communicate_warning('An error occured when making initial request to https://ubuntu.com/security/releases.json; received a non-ok response code.')
        return 'An error occured when making initial request to https://ubuntu.com/security/releases.json; received a non-ok response code.'

    return ubuntu_api_initial_response.json()['releases']


def initialize_ubuntu_release_version_codename():
    '''Add release -> codename mapping to db and dict''' 
    releases_dict = {}
    releases_json = download_ubuntu_release_codename_mapping()

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = 'INSERT INTO distribution_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)'

    # extract codename and version from json
    for release in releases_json:
        codename = release['codename']
        version = release['version']
        support_expires = str(release['support_expires']).split('T')[0]
        esm_expires = str(release['esm_expires']).split('T')[0]
        
        # use upstream as upstream version
        if not version:
            version = 'upstream'

        db_cursor.execute(query, ('ubuntu', version, codename, support_expires, esm_expires))
        releases_dict[codename] = {'version': version}

    db_conn.commit()
    db_conn.close()

    global UBUNTU_RELEASES
    UBUNTU_RELEASES = releases_dict


def write_data_to_json_file(api_data, requestno):
    '''Perform creation of cve json files'''

    if DEBUG:
        print(f'[+] Writing data from request number {requestno} to file.')
    with open(os.path.join(UBUNTU_DATAFEED_DIR, f'ubuntu_cve-{requestno}.json'), 'a') as outfile:
        json.dump(api_data, outfile)


async def worker_ubuntu(headers, params, requestno, rate_limit):
    '''Handle requests within its offset space asychronously, then performs processing steps to produce final database.'''
    
    global UBUNTU_UPDATE_SUCCESS

    async with rate_limit:
        api_data_response = await api_request(headers=headers, params=params, requestno=requestno, url=CVE_UBUNTU_API_URL)

    if UBUNTU_UPDATE_SUCCESS is not None and not UBUNTU_UPDATE_SUCCESS:
        return None

    write_data_to_json_file(api_data=api_data_response, requestno=requestno)
    

def add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, status, ubuntu_version, note, extra_cpe):
    '''Add given given ubuntu version in a package to UBUNTU_NOT_FOUND_NAME'''
    try:
        UBUNTU_NOT_FOUND_NAME[name].append((note, ubuntu_version, cve_id, name_version, matching_cpe, status, extra_cpe))
    except:
        UBUNTU_NOT_FOUND_NAME[name] = [(note, ubuntu_version, cve_id, name_version, matching_cpe, status, extra_cpe)]


def get_ubuntu_version_for_codename(codename):
    if codename == 'upstream':
        return '-1'
    else:    
        return UBUNTU_RELEASES[codename]['version']

        
def process_cve(cve):
    '''Get cpes for all packages of a cve and add these information to the db'''
    cve_id = cve['cve_id']
    cpes = cve['cpes']
    general_given_cpes = [get_general_cpe(cpe[1]) for cpe in cpes]

    # skip cve if only hardware cpes
    if cpes and are_only_hardware_cpes(cpes):
        return

    packages_cpes = []

    for package in cve['packages']:
        statuses = [(status, get_ubuntu_version_for_codename(status['release_codename'])) for status in package['statuses']]
        statuses.sort(key = lambda status:float(status[1]))
        
        matching_cpe = ''
        name, name_version = split_name(package['name'])
        add_to_vuln_db_bool = True

        relevant_statuses = summarize_statuses_ubuntu(statuses)

        # highest version needs '>=' as operator
        if relevant_statuses[-1][1] != 'upstream':
            relevant_statuses[-1] = (relevant_statuses[-1][0], relevant_statuses[-1][1], '>=')
        elif len(relevant_statuses) > 1:
            relevant_statuses[-2] = (relevant_statuses[-2][0], relevant_statuses[-2][1], '>=')

        all_dne_statuses = len([True for status_info, _, _ in relevant_statuses if status_info['status'] == 'DNE']) == len(relevant_statuses)

        for status_infos, ubuntu_version, extra_cpe in relevant_statuses:
            status = status_infos['status']
            note = status_infos['description']
            version = note
            name_version, search = get_search_version_string(name, name_version, version)

            # add to not found if initial cpe search wasn't successful
            if not add_to_vuln_db_bool:
                add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, status, ubuntu_version, note, extra_cpe)
                continue

            if not matching_cpe:
                if len(cve['packages']) == 1 and len(general_given_cpes) == 1 and name in general_given_cpes[0] and name != 'linux':
                    matching_cpe = get_general_cpe(cpes[0][1])
                else:
                    matching_cpe = get_matching_cpe(name, name_version, version, search, cpes)
                
                # linux-* package
                if not matching_cpe:
                    break
                
                # check whether similarity between name and cpe is high enough
                sim_score = cpe_matching_score(name, matching_cpe)
                if sim_score < PACKAGE_CPE_MATCH_THRESHOLD:
                    add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, status, ubuntu_version, note, extra_cpe) 
                    add_to_vuln_db_bool = False
                    matching_cpe = ''
                    continue

                # check if similiar packages are part of the given cve
                matching_cpe, add_to_vuln_db_bool = check_similar_packages(cve_id, packages_cpes, matching_cpe, name_version, status, ubuntu_version, note, extra_cpe)
                # add packages to found packages for cve
                if add_to_vuln_db_bool:
                    best_match = False
                    if name == matching_cpe.split(':')[4]:
                        best_match = True
                    packages_cpes.append((matching_cpe, name, best_match))
                else:
                    continue
                
                # match found cpe to all previous not found packages
                match_not_found_cpe(cpes, matching_cpe, name)

            # package not relevant, b/c all statuses are does not exist and matching cpe is not in the given ones, 
            # so ubuntu doesn't correct NVD data, because CVE is already not shown for the given package
            if all_dne_statuses and get_general_cpe(matching_cpe) not in general_given_cpes and len(get_equivalent_cpes(matching_cpe)) == 1:
                break
            if status == 'released':
                # no version given with status released, could happen with 'upstream' as codename
                if not note:
                    continue
            version_end = get_version_end(status, note)
            distro_cpe= get_distribution_cpe(ubuntu_version, 'ubuntu', matching_cpe, extra_cpe)
            if version_end:
                add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'ubuntu', DB_CURSOR)


def check_similar_packages(cve_id, packages_cpes, matching_cpe, name_version, status, ubuntu_version, note, extra_cpe):
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
                add_package_status_to_not_found(cve_id, cpe, name, name_version, status, ubuntu_version, note, extra_cpe)
                add_to_vuln_db_bool = False
                continue
    return matching_cpe,add_to_vuln_db_bool


def match_not_found_cpe(cpes, matching_cpe, name):
    '''Add all not found entries with the same package name to vuln_db after a matching cpe was found'''
    try:
        backport_cpes = UBUNTU_NOT_FOUND_NAME[name]
        for note, ubuntu_version, cve_id, name_version, _, status, extra_cpe in backport_cpes:
            if status == 'released':
                clean_version = get_clean_version(note, True)
            else:
                clean_version = get_clean_version(note, False)
            if not clean_version or status == 'DNE':
                clean_version = '-1'
                note = ''
            version_end = get_version_end(status, note)
            distro_cpe = get_distribution_cpe(ubuntu_version, 'ubuntu', matching_cpe, extra_cpe)
            if version_end:
                add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'ubuntu', DB_CURSOR)
        del UBUNTU_NOT_FOUND_NAME[name]
    except:
        pass


def get_ubuntu_data_from_files():
    '''Extract the cve data from ubuntu api data, saved in files'''
    cves_ubuntu = []
    for filename in os.listdir(UBUNTU_DATAFEED_DIR):
        with open(os.path.join(UBUNTU_DATAFEED_DIR, filename), 'r') as f:
            res_json = json.load(f)
            if not res_json:
                print('[!] Ubuntu download failed')
                communicate_warning('Ubuntu download failed')
                rollback_ubuntu()
                return 'Ubuntu download failed'
            cves = res_json['cves']
            cves_ubuntu += cves
            continue
    cves_ubuntu.sort(key=lambda id: id['id'])    
    return cves_ubuntu


def process_data():
    '''Process ubuntu api data''' 
    if not QUIET:
        print('[+] Adding ubuntu data to database')

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    # get cve data from vuln_db
    query = 'SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end FROM cve_cpe WHERE source == "nvd"'
    cve_cpe_list = db_cursor.execute(query, ()).fetchall()
    cve_cpe_list.sort(key=lambda cve: cve[0])
    db_conn.close()
    
    cves_ubuntu = get_ubuntu_data_from_files()
    cve_cpe_ubuntu = []
 
    pointer_cves_nvd = 0
    pointer_cve_cpe_ubuntu = 0
    found = False   # used for cves which occur more than one time in the cve_cpe_table
    length_cve_cpe_list = len(cve_cpe_list)

    # match cve and cpe
    for cve in cves_ubuntu:
        cve_id = cve['id']

        # iterate through all cves from nvd
        for i in range(pointer_cves_nvd, length_cve_cpe_list):
            nvd_cve_id = cve_cpe_list[i][0]
            if cve_id ==  nvd_cve_id:
                if not found:
                    cve_cpe_ubuntu.append({'cve_id': cve_id, 'cpes': [], 'packages': cve['packages']})#'infos_ubuntu': cve, 'infos_nvd': cve_cpe_list[i]})
                    found = True
                cve_cpe_ubuntu[pointer_cve_cpe_ubuntu]['cpes'].append(cve_cpe_list[i])                           
            elif found:
                found = False
                pointer_cve_cpe_ubuntu += 1
                pointer_cves_nvd = i
                break
        # cve_id not found in cve_cpe
        else:
            if is_cve_rejected(cve_id):
                continue
            else:
                cve_cpe_ubuntu.append({'cve_id': cve_id, 'cpes': [], 'packages': cve['packages']})#'infos_ubuntu': cve, 'infos_nvd': cve_cpe_list[i]})
                pointer_cve_cpe_ubuntu += 1

    cves_ubuntu = []
    cve_cpe_list = []
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    global DB_CURSOR
    DB_CURSOR = db_conn.cursor()

    for cve in cve_cpe_ubuntu:
        process_cve(cve)
    
    # add all not found packages to vuln_db
    add_not_found_packages(UBUNTU_NOT_FOUND_NAME, 'ubuntu', DB_CURSOR) 

    db_conn.commit()
    db_conn.close()



async def update_vuln_ubuntu_db():
    '''Update the vulnerability database for ubuntu'''

    global UBUNTU_UPDATE_SUCCESS

    rate_limit = AsyncLimiter(5.0, 1.0)
    # download vulnerability data via Ubuntu Security API
    if os.path.exists(UBUNTU_DATAFEED_DIR):
        shutil.rmtree(UBUNTU_DATAFEED_DIR)
    os.makedirs(UBUNTU_DATAFEED_DIR)

    if not QUIET:
        print('[+] Downloading ubuntu data feeds')

    offset = 0

    # initial request to set paramters
    params = {'offset': 0, 'limit': 1, 'order': 'descending', 'sort_by': 'published', 'show_hidden': 'false', 'cve_status': 'active'}
    headers = {'accept': 'application/json'}
    api_results_per_page = 100

    try:
        cve_api_initial_response = requests.get(url=CVE_UBUNTU_API_URL, headers=headers, params=params)
    except:
            UBUNTU_UPDATE_SUCCESS = False
            communicate_warning('An error occured when making initial request for parameter setting to https://ubuntu.com/security/cves.json')
            rollback_ubuntu()
            return 'An error occured when making initial request for parameter setting to https://ubuntu.com/security/cves.json'
    if cve_api_initial_response.status_code != requests.codes.ok:
        UBUNTU_UPDATE_SUCCESS = False
        rollback_ubuntu()
        communicate_warning('An error occured when making initial request for parameter setting to https://ubuntu.com/security/cves.json; received a non-ok response code.')
        return 'An error occured when making initial request for parameter setting to https://ubuntu.com/security/cves.json; received a non-ok response code.'

    numTotalResults = cve_api_initial_response.json().get('total_results')

    # make necessary amount of requests
    requestno = 0
    tasks = []
    while(offset <= numTotalResults):
        requestno += 1
        params = {'offset': offset, 'limit': api_results_per_page, 'order': 'descending', 'sort_by': 'published', 'show_hidden': 'false', 'cve_status': 'active'}
        task = asyncio.create_task(worker_ubuntu(headers=headers, params=params, requestno = requestno, rate_limit=rate_limit))
        tasks.append(task)
        offset += api_results_per_page

    while True:
        _, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED, timeout=2)
        if len(pending) < 1 or (UBUNTU_UPDATE_SUCCESS is not None and not UBUNTU_UPDATE_SUCCESS):
            break
    if (not len(os.listdir(UBUNTU_DATAFEED_DIR))) or (UBUNTU_UPDATE_SUCCESS is not None and not UBUNTU_UPDATE_SUCCESS):
        UBUNTU_UPDATE_SUCCESS = False
        communicate_warning('Could not download vuln data from https://ubuntu.com/security/cves.json')
        rollback_ubuntu()
        return 'Could not download vuln data from https://ubuntu.com/security/cves.json'
        
    # get ubuntu releases data
    initialize_ubuntu_release_version_codename()

    try:
        process_data()
    except:
        UBUNTU_UPDATE_SUCCESS = False
        communicate_warning('Could not process vuln data from the Ubuntu Security Api')
        rollback_ubuntu()
        return 'Could not process vuln data from the Ubuntu Security Api'

    shutil.rmtree(UBUNTU_DATAFEED_DIR)
    return False