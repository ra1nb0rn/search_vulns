#!/usr/bin/env python3

import re
import requests
import threading
import time

import aiohttp
from aiolimiter import AsyncLimiter
from .update_generic import *

CONFIG = None


def rollback_nvd():
    rollback()
    if os.path.isdir(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)


async def api_request(headers, params, requestno):
    '''Perform request to API for one task'''

    global NVD_UPDATE_SUCCESS

    if NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS:
        return None

    retry_limit = 3
    retry_interval = 6
    for _ in range(retry_limit + 1):
        async with aiohttp.ClientSession() as session:
            try:
                cve_api_data_response = await session.get(url=CVE_API_URL, headers=headers, params=params)
                if cve_api_data_response.status == 200 and cve_api_data_response.text is not None:
                    if DEBUG:
                        print(f'[+] Successfully received data from request {requestno}.')
                    return await cve_api_data_response.json()
                else:
                    if DEBUG:
                        print(f'[-] Received status code {cve_api_data_response.status} on request {requestno} Retrying...')
                await asyncio.sleep(retry_interval)
            except Exception as e:
                if NVD_UPDATE_SUCCESS is None:
                    communicate_warning('Got the following exception when downloading vuln data via API: %s' % str(e))
                NVD_UPDATE_SUCCESS = False
                return None


def write_data_to_json_file(api_data, requestno):
    '''Perform creation of cve json files'''

    if DEBUG:
        print(f'[+] Writing data from request number {requestno} to file.')
    with open(os.path.join(NVD_DATAFEED_DIR, f'nvdcve-2.0-{requestno}.json'), 'a') as outfile:
        json.dump(api_data, outfile)


async def worker(headers, params, requestno, rate_limit):
    '''Handle requests within its offset space asychronously, then performs processing steps to produce final database.'''

    global NVD_UPDATE_SUCCESS

    async with rate_limit:
        api_data_response = await api_request(headers=headers, params=params, requestno=requestno)

    if NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS:
        return None

    write_data_to_json_file(api_data=api_data_response, requestno=requestno)


async def update_vuln_db(nvd_api_key=None, config_file=''):
    '''Update the vulnerability database'''

    global NVD_UPDATE_SUCCESS
    
    if nvd_api_key:
        if not QUIET:
            print('[+] API Key found - Requests will be sent at a rate of 25 per 30s.')
        rate_limit = AsyncLimiter(25.0, 30.0)
    else:
        print('[-] No API Key found - Requests will be sent at a rate of 5 per 30s. To lower build time, consider getting an NVD API Key.')
        rate_limit = AsyncLimiter(5.0, 30.0)

    # start CVE ID <--> EDB ID mapping creation in background thread
    cve_edb_map_thread = threading.Thread(target=create_cveid_edbid_mapping)
    cve_edb_map_thread.start()

    # download vulnerability data via NVD's API
    if os.path.exists(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    os.makedirs(NVD_DATAFEED_DIR)

    if not QUIET:
        print('[+] Downloading NVD data feeds and EDB information')

    offset = 0

    # initial request to set paramters
    params = {'resultsPerPage': API_RESULTS_PER_PAGE, 'startIndex': offset}
    if nvd_api_key:
        headers = {'apiKey': nvd_api_key}
    else:
        headers = {}

    try:
        cve_api_initial_response = requests.get(url=CVE_API_URL, headers=headers, params=params)
    except:
            NVD_UPDATE_SUCCESS = False
            communicate_warning('An error occured when making initial request for parameter setting to https://services.nvd.nist.gov/rest/json/cves/2.0')
            rollback_nvd()
            cve_edb_map_thread.join()
            return 'An error occured when making initial request for parameter setting to https://services.nvd.nist.gov/rest/json/cves/2.0'
    if cve_api_initial_response.status_code != requests.codes.ok:
        NVD_UPDATE_SUCCESS = False
        rollback_nvd()
        cve_edb_map_thread.join()
        return 'An error occured when making initial request for parameter setting to https://services.nvd.nist.gov/rest/json/cves/2.0; received a non-ok response code.'

    numTotalResults = cve_api_initial_response.json().get('totalResults')

    # make necessary amount of requests
    requestno = 0
    tasks = []
    while(offset <= numTotalResults):
        requestno += 1
        params = {'resultsPerPage': API_RESULTS_PER_PAGE, 'startIndex': offset}
        task = asyncio.create_task(worker(headers=headers, params=params, requestno = requestno, rate_limit=rate_limit))
        tasks.append(task)
        offset += API_RESULTS_PER_PAGE

    while True:
        _, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED, timeout=2)
        if len(pending) < 1 or (NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS):
            break

    if (not len(os.listdir(NVD_DATAFEED_DIR))) or (NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS):
        NVD_UPDATE_SUCCESS = False
        communicate_warning('Could not download vuln data from https://services.nvd.nist.gov/rest/json/cves/2.0')
        rollback_nvd()
        cve_edb_map_thread.join()
        return 'Could not download vuln data from https://services.nvd.nist.gov/rest/json/cves/2.0'

    # build local NVD copy with downloaded data feeds
    print('[+] Building vulnerability database')
    create_db_call = ["./create_db", NVD_DATAFEED_DIR, config_file, CONFIG['DATABASE_NAME'], CREATE_SQL_STATEMENTS_FILE]
    with open(os.devnull, "w") as outfile:
        return_code = subprocess.call(create_db_call, stdout=outfile, stderr=subprocess.STDOUT)

    if return_code != 0:
        NVD_UPDATE_SUCCESS = False
        communicate_warning('Building NVD database failed')
        rollback_nvd()
        cve_edb_map_thread.join()
        return f'Building NVD database failed with status code {return_code}.'

    shutil.rmtree(NVD_DATAFEED_DIR)
    NVD_UPDATE_SUCCESS = True
    cve_edb_map_thread.join()

    # build and add table of PoC-in-GitHub
    print('[+] Adding PoC-in-GitHub information')
    try:
        create_poc_in_github_table()
    except:
        communicate_warning('Building PoCs in GitHub table failed')
        rollback_nvd()
        return 'Building PoCs in GitHub table failed'


def get_all_edbids():
    ''' Return a list of all existing EDB IDs '''
    files_exploits_resp = requests.get('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', headers=REQUEST_HEADERS)
    files_exploits = files_exploits_resp.text
    return re.findall(r'^(\d+),.*$', files_exploits, re.MULTILINE)


def create_cveid_edbid_mapping():
    ''' Create a CVE ID --> EDB ID mapping and store in local vuln DB '''

    # get all unknown EDB IDs
    all_edbids, edbids_no_cveid = set(get_all_edbids()), set()
    if os.path.isfile(CONFIG['CVE_EDB_MAP_FILE']):
        with open(CONFIG['CVE_EDB_MAP_FILE']) as f:
            cve_edb_map = json.load(f)
        mapped_edbids = set()
        edbids_no_cveid = set(cve_edb_map['N/A'])
        for ebdids in cve_edb_map.values():
            mapped_edbids |= set(ebdids)
        remaining_edbids = all_edbids - mapped_edbids
    elif os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
        # if the DB is updated and previously built map is not available, build
        # incremental CVE ID --> EDB ID mapping based on previous version of DB
        cve_edb_map = recover_map_data_from_db()
        mapped_edbids = set()
        for edbids in cve_edb_map.values():
            mapped_edbids |= set(edbids)
        gh_map_edb_cve_resp = requests.get('https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping.json', headers=REQUEST_HEADERS)
        edb_cve_map = json.loads(gh_map_edb_cve_resp.text)
        edbids_no_cveid = set()
        for edbid, cveids in edb_cve_map.items():
            if not cveids:
                edbids_no_cveid.add(edbid)
        remaining_edbids = all_edbids - mapped_edbids - edbids_no_cveid
    else:
        # if a full DB installation is done, build CVE ID --> EDB ID mapping from scratch
        # use the mapping data from andreafioraldi's cve_searchsploit as base
        gh_map_cve_edb_resp = requests.get('https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping_cve.json', headers=REQUEST_HEADERS)
        cve_edb_map = json.loads(gh_map_cve_edb_resp.text)
        gh_map_edb_cve_resp = requests.get('https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping.json', headers=REQUEST_HEADERS)
        edb_cve_map = json.loads(gh_map_edb_cve_resp.text)
        edbids_no_cveid = set()
        for edbid, cveids in edb_cve_map.items():
            if not cveids:
                edbids_no_cveid.add(edbid)
        gh_captured_edbids = set(edb_cve_map.keys())
        remaining_edbids = all_edbids - gh_captured_edbids

    # manually crawl the mappings not yet created
    cveid_expr = re.compile(r'https://nvd.nist.gov/vuln/detail/(CVE-\d\d\d\d-\d+)')
    pause_time, last_time, printed_wait = 0.51, time.time(), False
    for i, edbid in enumerate(remaining_edbids):
        # wait at least pause_time seconds before making another request to not put heavy load on servers
        time_diff = time.time() - last_time
        if time_diff < pause_time:
            time.sleep(pause_time - time_diff)
        last_time = time.time()

        if not QUIET and NVD_UPDATE_SUCCESS and not printed_wait:
            print('Waiting for CVE ID <--> EDB ID map creation to finish ...')
            printed_wait = True
        elif (NVD_UPDATE_SUCCESS is not None) and (not NVD_UPDATE_SUCCESS):
            return

        exploit_page_resp = requests.get('https://www.exploit-db.com/exploits/%s' % edbid, headers=REQUEST_HEADERS, timeout=30)
        cveids = cveid_expr.findall(exploit_page_resp.text)

        if not cveids:
            edbids_no_cveid.add(edbid)

        for cveid in cveids:
            if cveid not in cve_edb_map:
                cve_edb_map[cveid] = []
            cve_edb_map[cveid].append(edbid)

    cve_edb_map['N/A'] = list(edbids_no_cveid)  # store all EDBIDs without CVE
    with open(CONFIG['CVE_EDB_MAP_FILE'], 'w') as f:
        f.write(json.dumps(cve_edb_map))

    while NVD_UPDATE_SUCCESS is None:
        time.sleep(1)

    if NVD_UPDATE_SUCCESS:
        fill_database_with_mapinfo(cve_edb_map)


def fill_database_with_mapinfo(cve_edb_map):
    ''' Put the given mapping data into the database specified by the given cursor '''

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    update_statement = 'UPDATE cve SET edb_ids=? WHERE cve_id=?'
    for cveid, edbids in cve_edb_map.items():
        if cveid == 'N/A':  # skip the fake item holding EDBIDs without CVEID
            continue

        edbids = sorted(set(edbids), key=lambda eid: int(eid))
        db_cursor.execute(update_statement, (','.join(edbids), cveid))

    db_conn.commit()
    db_conn.close()


def recover_map_data_from_db():
    ''' Return stored CVE ID <--> EDB ID mapping from DB backup file '''

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_BACKUP_FILE'])
    db_cursor = db_conn.cursor()

    # recover CVE ID --> EDB ID data
    db_cursor.execute('SELECT cve_id, edb_ids FROM cve')
    map_data = db_cursor.fetchall()
    cve_edb_map = {}
    for cve_id, edb_ids in map_data:
        if edb_ids:
            cve_edb_map[cve_id] = edb_ids.split(',')

    db_conn.close()
    return cve_edb_map


def create_poc_in_github_table():
    '''Create CVE ID <--> GitHub PoC URL mapping'''

    if os.path.isdir(POC_IN_GITHUB_DIR):
        shutil.rmtree(POC_IN_GITHUB_DIR)

    # download PoC in GitHub Repo
    return_code = subprocess.call(
        'git clone --depth 1 %s \'%s\''
        % (POC_IN_GITHUB_REPO, POC_IN_GITHUB_DIR),
        shell=True,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception('Could not download latest resources of PoC-in-GitHub'))

    # add PoC / exploit information to DB
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    create_poc_in_github_table = CREATE_SQL_STATEMENTS['TABLES']['CVE_POC_IN_GITHUB_MAP'][CONFIG['DATABASE']['TYPE']]
    # necessary because SQLite can't handle more than one query a time
    for query in create_poc_in_github_table[:-1].split(';'):
        db_cursor.execute(query+';')
    db_conn.commit()

    for file in os.listdir(POC_IN_GITHUB_DIR):
        yearpath = os.path.join(POC_IN_GITHUB_DIR, file)
        if not os.path.isdir(yearpath):
            continue
        try:
            int(file)
        except:
            continue

        for cve_file in os.listdir(yearpath):
            cve_filepath = os.path.join(yearpath, cve_file)
            cve_id = os.path.splitext(cve_file)[0]
            with open(cve_filepath) as cve_fh:
                cve_json = json.loads(cve_fh.read())
                for poc_item in cve_json:
                    db_cursor.execute('INSERT INTO cve_poc_in_github_map VALUES (?, ?)', (cve_id, poc_item['html_url']))

    db_conn.commit()
    db_conn.close()

    if os.path.isdir(POC_IN_GITHUB_DIR):
        shutil.rmtree(POC_IN_GITHUB_DIR)
