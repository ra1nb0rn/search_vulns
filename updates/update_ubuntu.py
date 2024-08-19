#!/usr/bin/env python3

import aiohttp
from aiolimiter import AsyncLimiter

from .update_generic import *
from .update_distributions_generic import *

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

UBUNTU_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'ubuntu_data_feeds')
CVE_UBUNTU_API_URL = 'https://ubuntu.com/security/cves.json'

UBUNTU_NOT_FOUND_NAME = {}
UBUNTU_RELEASES = {}
UBUNTU_UPDATE_SUCCESS = None
UBUNTU_API_REQUESTS_PER_SECOND = 1.0

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


def get_version_end_ubuntu(version, status):
    '''Return a version_end matching the format from the database and reflecting the status'''
    version_end = '-1'

    if status == 'released':
        # released only returns a version, not any describing words, so returning a good version is easier
        version_end = get_clean_version(version, is_good_version=True)
        if not version_end:
            version_end =  ''
    else:
        version_end = get_clean_version(version, is_good_version=False)

    # if distro is not affected or package does-not-exists(dne). use version_end = -1 to describe it
    if (not version_end and status == 'not-affected') or status == 'DNE' :
        version_end = '-1'
    elif status == 'pending':
        # update is ready, but not enrolled
        if version:
            version_end = get_clean_version(version, True)
        # distro is vulnerable, but no update ready. use MAX_INT-1 to describe it
        else:
            version_end = str(sys.maxsize-1)
    # distro is vulnerable, but no update ready. use MAX_INT-1 to describe it
    elif status in ['needed', 'active', 'deferred']:
        version_end = str(sys.maxsize-1)
    # distro could be vulnerable, but needs further investigation. use MAX_INT to describe it
    elif status == 'needs-triage':
        version_end = str(sys.maxsize)
    # status ignored can have many reasons, try to find a suiting version for the most popular cases
    elif status == 'ignored':
        if not version or any(version.startswith(string) for string in ['end of', 'code', 'superseded', 'was not-affected']):
            version_end = ''
        elif version.startswith('only'):
            version_end = '-1'
        elif not any(x in version for x in ['will not', 'intrusive', 'was', 'fix']):
            version_end = str(sys.maxsize-1)
        else:
            version_end = ''

    # remove all whitespaces, b/c ubuntu could return versions like ' 1.11.15. 1.12.1'
    version_end = version_end.replace(' ','')
    return version_end


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


def initialize_ubuntu_release_version_codename(config):
    '''Add release -> codename mapping to db and dict''' 
    releases_dict = {}
    releases_json = download_ubuntu_release_codename_mapping()

    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = 'INSERT INTO distribution_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)'

    # extract codename and version from json
    for release in releases_json:
        codename = release['codename']
        version = release['version']
        support_expires = str(release['support_expires']).split('T')[0]
        esm_expires = str(release['esm_expires']).split('T')[0]
        
        # use upstream as upstream version name
        if not version:
            version = 'upstream'

        # add information to database
        db_cursor.execute(query, ('ubuntu', version, codename, support_expires, esm_expires))
        # fill a dictionary used during the update
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
    

def add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, ubuntu_version, version_end, extra_cpe):
    '''Add given given ubuntu version in a package to UBUNTU_NOT_FOUND_NAME'''
    global UBUNTU_NOT_FOUND_NAME
    try:
        UBUNTU_NOT_FOUND_NAME[name].append((version_end, ubuntu_version, cve_id, name_version, matching_cpe, extra_cpe))
    except:
        UBUNTU_NOT_FOUND_NAME[name] = [(version_end, ubuntu_version, cve_id, name_version, matching_cpe, extra_cpe)]


def get_ubuntu_version_for_codename(codename):
    '''Return the matching version for a given codename'''
    if codename == 'upstream':
        return '-1'
    else:    
        return UBUNTU_RELEASES[codename]['version']

        
def process_cve(cve, db_cursor):
    '''Get cpes for all packages of a cve and add these information to the db'''
    cve_id = cve['cve_id']
    cpes = cve['cpes']
    general_given_cpes = list(set([get_general_cpe(cpe[1]) for cpe in cpes]))

    # skip cve if only hardware cpes from the nvd given
    if cpes and are_only_hardware_cpes(cpes):
        return

    packages_cpes = []

    # iterate through every package mentioned in the given cve entry
    for package in cve['packages']:
        matching_cpe = ''
        # split something like openssl098 to openssl 098, so 098 can be considered as version_start = 0.9.8
        name, name_version = split_name(package['name'])
        add_to_vuln_db_bool = True

        # list of (version_end, status, ubuntu_version)
        statuses = [(get_version_end_ubuntu(status['description'], status['status']), get_ubuntu_version_for_codename(status['release_codename']), '') for status in package['statuses']]
        statuses.sort(key = lambda status:float(status[1]))
        # try to summarize statuses with the same version_end to minimize the amount of entries in the db
        relevant_statuses = summarize_statuses_with_version(statuses, 'upstream')
        
        #  force to use '>=' as operator in the entry with the highest distribution version
        if relevant_statuses[-1][1] == statuses[-1][1] and not relevant_statuses[-1][2] and len(cpes) == 0:
            relevant_statuses[-1] = (relevant_statuses[-1][0], relevant_statuses[-1][1], '>=')

        # iterate through every relevant entry for a given package in a given cve
        for version_end, ubuntu_version, extra_cpe in relevant_statuses:
            # skip entries with no version_end, could happen with status ignored
            # use the nvd data in this case, b/c distribution will not fix it, but user could manually update
            if not version_end:
                continue

            # create a search string with all relevant information (package name, found version in package name and version end) 
            name_version, search = get_search_version_string(name, name_version, version_end)

            # add to not found if initial cpe search wasn't successful
            if not add_to_vuln_db_bool:
                add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, ubuntu_version, version_end, extra_cpe)
                continue

            # no matching cpe for the given package found in a previous loop run
            if not matching_cpe:
                # if only one cpe given from nvd and only one package affected, the given cpe is the one we're searching for
                if len(cve['packages']) == 1 and len(general_given_cpes) == 1 and name in general_given_cpes[0] and name != 'linux':
                    matching_cpe = get_general_cpe(general_given_cpes[0])
                # else try to find a matching cpe
                else:
                    matching_cpe = get_matching_cpe(name, package['name'], name_version, version_end, search, cpes)
                
                # linux-* package
                if not matching_cpe:
                    break
                
                # check whether similarity between name and cpe is high enough
                sim_score = cpe_matching_score(name, matching_cpe)
                if sim_score < PACKAGE_CPE_MATCH_THRESHOLD:
                    add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, ubuntu_version, version_end, extra_cpe) 
                    add_to_vuln_db_bool = False
                    matching_cpe = ''
                    continue

                # check if cve has similar packages which we need to consider
                matching_cpe, add_to_vuln_db_bool = check_similar_packages(cve_id, packages_cpes, matching_cpe, name_version, ubuntu_version, version_end, extra_cpe)
                # add packages to found packages for cve
                if add_to_vuln_db_bool:
                    best_match = False
                    if name == matching_cpe.split(':')[4]:
                        best_match = True
                    packages_cpes.append((matching_cpe, name, best_match))
                else:
                    continue
                
                # match found cpe to all previous not found packages
                match_not_found_cpe(cpes, matching_cpe, name, db_cursor)

            # add distribution information to cpe and add to database
            distro_cpe= get_distribution_cpe(ubuntu_version, 'ubuntu', matching_cpe, extra_cpe)
            add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'ubuntu', db_cursor)


def check_similar_packages(cve_id, packages_cpes, matching_cpe, name_version, ubuntu_version, note, extra_cpe):
    '''Check whether given package name with found cpe is close to another package with the same cpe'''
    add_to_vuln_db_bool = True
    # use found cpe of a similar package from the same cve entry
    for cpe, name, best_match in packages_cpes:
        if best_match:
            continue
        if matching_cpe == cpe:
            cpe_parts = matching_cpe.split(':')
            if cpe_parts[4] in name:
                cpe_parts[4] = name
                matching_cpe = ':'.join(cpe_parts)
            else:
                add_package_status_to_not_found(cve_id, cpe, name, name_version, ubuntu_version, note, extra_cpe)
                add_to_vuln_db_bool = False
                continue
    return matching_cpe,add_to_vuln_db_bool


def match_not_found_cpe(cpes, matching_cpe, name, db_cursor):
    '''Add all not found entries with the same package name to vuln_db after a matching cpe was found'''
    global UBUNTU_NOT_FOUND_NAME
    try:
        backport_cpes = UBUNTU_NOT_FOUND_NAME[name]
        for version_end, ubuntu_version, cve_id, name_version, _, extra_cpe in backport_cpes:
            distro_cpe = get_distribution_cpe(ubuntu_version, 'ubuntu', matching_cpe, extra_cpe)
            if version_end:
                add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'ubuntu', db_cursor)
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
                global UBUNTU_UPDATE_SUCCESS
                UBUNTU_UPDATE_SUCCESS = False
                return 'Ubuntu download failed'
            cves = res_json['cves']
            cves_ubuntu += cves
            continue
    cves_ubuntu.sort(key=lambda id: id['id'])    
    return cves_ubuntu


def process_data(config):
    '''Process ubuntu api data''' 
    if not QUIET:
        print('[+] Adding ubuntu data to database')

    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
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

    # download failed
    if type(cves_ubuntu) == string:
        return cves_ubuntu

    # match cve and cpes from nvd
    for cve in cves_ubuntu:
        cve_id = cve['id']

        # iterate through all cves from nvd
        for i in range(pointer_cves_nvd, length_cve_cpe_list):
            nvd_cve_id = cve_cpe_list[i][0]
            # use information from nvd for the cves from ubuntu
            if cve_id ==  nvd_cve_id:
                if not found:
                    cve_cpe_ubuntu.append({'cve_id': cve_id, 'cpes': [], 'packages': cve['packages']})
                    found = True
                cve_cpe_ubuntu[pointer_cve_cpe_ubuntu]['cpes'].append(cve_cpe_list[i])                           
            # a cve can have more than one matching cpe
            elif found:
                found = False
                pointer_cve_cpe_ubuntu += 1
                pointer_cves_nvd = i
                break
        # cve_id not found in cve_cpe
        else:
            if is_cve_rejected(cve_id, config):
                continue
            else:
                cve_cpe_ubuntu.append({'cve_id': cve_id, 'cpes': [], 'packages': cve['packages']})
                pointer_cve_cpe_ubuntu += 1

    cves_ubuntu = []
    cve_cpe_list = []
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    for cve in cve_cpe_ubuntu:
        process_cve(cve, db_cursor)

    # add all not found packages to vuln_db
    add_not_found_packages(UBUNTU_NOT_FOUND_NAME, 'ubuntu', db_cursor) 

    db_conn.commit()
    db_conn.close()


async def download_ubuntu_data():
    global UBUNTU_UPDATE_SUCCESS

    rate_limit = AsyncLimiter(UBUNTU_API_REQUESTS_PER_SECOND, 1.0)

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
        cve_api_initial_response = requests.get(url=CVE_UBUNTU_API_URL, headers=headers)
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



async def update_vuln_ubuntu_db(config):
    '''Update the vulnerability database for ubuntu'''

    global UBUNTU_UPDATE_SUCCESS

    # download the data from the api
    error = await download_ubuntu_data()
    if error:
        return error
    # get releases information from api
    initialize_ubuntu_release_version_codename(config)

    try:
        process_data(config)
    except:
        UBUNTU_UPDATE_SUCCESS = False
        communicate_warning('Could not process vuln data from the Ubuntu Security Api')
        rollback_ubuntu()
        return 'Could not process vuln data from the Ubuntu Security Api'

    if UBUNTU_UPDATE_SUCCESS != False:
        shutil.rmtree(UBUNTU_DATAFEED_DIR)
    return False