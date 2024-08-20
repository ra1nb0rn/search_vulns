#!/usr/bin/env python3

import asyncio
from collections import Counter
import csv
import json
import math
import os
import re
import requests
import shutil
import shlex
import subprocess
import sys
import threading
import time

import aiohttp
from aiolimiter import AsyncLimiter
from cvss import CVSS2, CVSS3, CVSS4
from cpe_search.cpe_search import update as update_cpe
from cpe_search.cpe_search import search_cpes, add_cpes_to_db
from cpe_search.database_wrapper_functions import get_database_connection
from search_vulns import _load_config

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json


NVD_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("resources", "nvd_data_feeds"))
VULNDB_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/vulndb.db3"
CPE_DICT_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/cpe-search-dictionary.db3"
CPE_DEPRECATIONS_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/deprecated-cpes.json"
CVE_EDB_MAP_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/cveid_to_edbid.json"
POC_IN_GITHUB_REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"
POC_IN_GITHUB_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("resources", "PoC-in-GitHub"))
EOLD_GITHUB_REPO = "https://github.com/endoflife-date/endoflife.date"
EOLD_GITHUB_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("resources", "endoflife.date"))
EOLD_HARDCODED_MATCHES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("resources", "eold_hardcoded_matches.json"))
GHSA_GITHUB_REPO = "https://github.com/github/advisory-database"
GHSA_GITHUB_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("resources", "ghsa-database"))
GHSA_HARDCODED_MATCHES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("resources", "ghsa_hardcoded_matches.json"))
REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0"}
NVD_UPDATE_SUCCESS = None
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MARIADB_BACKUP_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join('resources', 'mariadb_dump.sql'))
CREATE_SQL_STATEMENTS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join('resources', 'create_sql_statements.json'))
QUIET = False
DEBUG = False
API_RESULTS_PER_PAGE = 2000


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
                        print(f"[+] Successfully received data from request {requestno}.")
                    return await cve_api_data_response.json()
                else:
                    if DEBUG:
                        print(f"[-] Received status code {cve_api_data_response.status} on request {requestno} Retrying...")
                await asyncio.sleep(retry_interval)
            except Exception as e:
                if NVD_UPDATE_SUCCESS is None:
                    communicate_warning('Got the following exception when downloading vuln data via API: %s' % str(e))
                NVD_UPDATE_SUCCESS = False
                return None


def write_data_to_json_file(api_data, requestno):
    '''Perform creation of cve json files'''

    if DEBUG:
        print(f"[+] Writing data from request number {requestno} to file.")
    with open(os.path.join(NVD_DATAFEED_DIR, f"nvdcve-2.0-{requestno}.json"), 'a') as outfile:
        json.dump(api_data, outfile)


async def worker(headers, params, requestno, rate_limit):
    '''Handle requests within its offset space asychronously, then performs processing steps to produce final database.'''

    global NVD_UPDATE_SUCCESS

    async with rate_limit:
        api_data_response = await api_request(headers=headers, params=params, requestno=requestno)

    if NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS:
        return None

    write_data_to_json_file(api_data=api_data_response, requestno=requestno)


def backup_mariadb_database(database):
    try:
        # check whether database exists
        get_database_connection(CONFIG['DATABASE'], database)
    except:
        pass
    else:
        # backup MariaDB
        backup_call = ['mariadb-dump',
                       '-u', CONFIG['DATABASE']['USER'],
                        '-h', CONFIG['DATABASE']['HOST'],
                        '-P', str(CONFIG['DATABASE']['PORT']),
                        '--add-drop-database', '--add-locks',
                        '-B', database, '-r', MARIADB_BACKUP_FILE]
        if CONFIG['DATABASE']['PASSWORD']:
            backup_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")

        return_code = subprocess.call(backup_call)
        if return_code != 0:
            print(f'[-] MariaDB backup of {database} failed')


async def update_vuln_db(nvd_api_key=None):
    """Update the vulnerability database"""

    global NVD_UPDATE_SUCCESS

    # backup MariaDB
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
        backup_mariadb_database(CONFIG['DATABASE_NAME']) 
    elif os.path.isfile(CONFIG['DATABASE_NAME']):
        shutil.move(CONFIG['DATABASE_NAME'], CONFIG['DATABASE_BACKUP_FILE'])

    if nvd_api_key:
        if not QUIET:
            print('[+] API Key found - Requests will be sent at a rate of 25 per 30s.')
        rate_limit = AsyncLimiter(25.0, 30.0)
    else:
        print('[-] No API Key found - Requests will be sent at a rate of 5 per 30s. To lower build time, consider getting an NVD API Key.')
        rate_limit = AsyncLimiter(5.0, 30.0)

    # start endoflife.date integration in background thread
    build_eold_data_thread = threading.Thread(target=create_endoflife_date_table)
    build_eold_data_thread.start()

    # download vulnerability data via NVD's API
    if os.path.exists(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    os.makedirs(NVD_DATAFEED_DIR)

    if not QUIET:
        print('[+] Downloading NVD data and EDB information and creating end of life data')

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
            rollback()
            build_eold_data_thread.join()
            return 'An error occured when making initial request for parameter setting to https://services.nvd.nist.gov/rest/json/cves/2.0'
    if cve_api_initial_response.status_code != requests.codes.ok:
        NVD_UPDATE_SUCCESS = False
        rollback()
        build_eold_data_thread.join()
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
        rollback()
        build_eold_data_thread.join()
        return 'Could not download vuln data from https://services.nvd.nist.gov/rest/json/cves/2.0'

    # build local NVD copy with downloaded data feeds
    print('[+] Building vulnerability database')
    create_db_call = ["./create_db", NVD_DATAFEED_DIR, CONFIG_FILE, CONFIG['DATABASE_NAME'], CREATE_SQL_STATEMENTS_FILE]
    with open(os.devnull, "w") as outfile:
        return_code = subprocess.call(create_db_call, stdout=outfile, stderr=subprocess.STDOUT)

    if return_code != 0:
        NVD_UPDATE_SUCCESS = False
        communicate_warning('Building NVD database failed')
        rollback()
        build_eold_data_thread.join()
        return f"Building NVD database failed with status code {return_code}."

    shutil.rmtree(NVD_DATAFEED_DIR)
    NVD_UPDATE_SUCCESS = True
    build_eold_data_thread.join()

    # start GHSA integration in background thread
    build_ghsa_data_thread = threading.Thread(target=add_ghsa_data_to_db)
    build_ghsa_data_thread.start()

    # add CPE infos from vulnerability data to CPE DB
    print('[+] Adding software/CPE information from vulns to CPE-DB')
    add_vuln_cpes_to_cpe_search()

    # add CVE ID <--> EDB ID mapping data
    print('[+] Adding Exploit-DB information')
    try:
        create_cveid_edbid_mapping()
    except:
        communicate_warning('Building of CVE-ID -> EDB-ID mapping failed')
        rollback()
        return 'Building of CVE-ID -> EDB-ID mapping failed'

    # build and add table of PoC-in-GitHub
    print('[+] Adding PoC-in-GitHub information')
    try:
        create_poc_in_github_table()
    except:
        communicate_warning('Building PoCs in GitHub table failed')
        rollback()
        return 'Building PoCs in GitHub table failed'

    # print this in the end, because it might take the most time / runs in background
    print('[+] Adding vuln data from GitHub Security Advisories Vuln Data')
    build_ghsa_data_thread.join()

    # remove backup file on success
    if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
        os.remove(CONFIG['DATABASE_BACKUP_FILE'])


async def handle_cpes_update(nvd_api_key=None):
    if os.path.isfile(CONFIG['cpe_search']['DATABASE_NAME']):
        shutil.move(CONFIG['cpe_search']['DATABASE_NAME'], CONFIG['CPE_DATABASE_BACKUP_FILE'])
    if os.path.isfile(CONFIG['cpe_search']['DEPRECATED_CPES_FILE']):
        shutil.move(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'], CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
       backup_mariadb_database(CONFIG['cpe_search']['DATABASE_NAME']) 

    success = await update_cpe(nvd_api_key, CONFIG['cpe_search'])
    if not success:
        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            shutil.move(CONFIG['CPE_DATABASE_BACKUP_FILE'], CONFIG['cpe_search']['DATABASE_NAME'])
        if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
            shutil.move(CONFIG['DEPRECATED_CPES_BACKUP_FILE'], CONFIG['cpe_search']['DEPRECATED_CPES_FILE'])
        if os.path.isfile(MARIADB_BACKUP_FILE) and CONFIG['DATABASE']['TYPE'] == 'mariadb':
            with open(MARIADB_BACKUP_FILE, 'rb') as f:
                mariadb_backup_data = f.read()
            restore_call = ['mariadb', '-u', CONFIG['DATABASE']['USER'],
                            '-h', CONFIG['DATABASE']['HOST'],
                            '-P', str(CONFIG['DATABASE']['PORT'])]
            if CONFIG['DATABASE']['PASSWORD']:
                restore_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")
            restore_call_run = subprocess.run(restore_call, input=mariadb_backup_data)
            if restore_call_run.returncode != 0:
                print('[-] Failed to restore MariaDB')
            else:
                print('[+] Restored MariaDB from backup')

            # Restore failed b/c database is down -> not delete backup file
            # check whether database is up by trying to get a connection
            try:
                get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
            except:
                print('[!] MariaDB seems to be down. The backup file wasn\'t deleted. To restore manually from the file, run the following command:')
                print(' '.join(restore_call+['<', MARIADB_BACKUP_FILE, '&&', 'rm', MARIADB_BACKUP_FILE]))
            else:
                os.remove(MARIADB_BACKUP_FILE)
    else:
        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            os.remove(CONFIG['CPE_DATABASE_BACKUP_FILE'])
        if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
            os.remove(CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
        if os.path.isfile(MARIADB_BACKUP_FILE):
            os.remove(MARIADB_BACKUP_FILE)

    return not success


def rollback():
    """Rollback the DB / module update"""

    communicate_warning('An error occured, rolling back database update')
    if CONFIG['DATABASE']['TYPE'] == 'sqlite':
        if os.path.isfile(CONFIG['DATABASE_NAME']):
            os.remove(CONFIG['DATABASE_NAME'])
    if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
        shutil.move(CONFIG['DATABASE_BACKUP_FILE'], CONFIG['DATABASE_NAME'])
    if os.path.isdir(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    if os.path.isfile(MARIADB_BACKUP_FILE):
        with open(MARIADB_BACKUP_FILE, 'rb') as f:
            mariadb_backup_data = f.read()
        restore_call = ['mariadb', '-u', CONFIG['DATABASE']['USER'],
                        '-h', CONFIG['DATABASE']['HOST'],
                        '-P', str(CONFIG['DATABASE']['PORT'])]
        if CONFIG['DATABASE']['PASSWORD']:
            restore_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")
        restore_call_run = subprocess.run(restore_call, input=mariadb_backup_data)
        if restore_call_run.returncode != 0:
            print('[-] Failed to restore MariaDB')
        else:
            print('[+] Restored MariaDB from backup')

        # Restore failed b/c database is down -> not delete backup file
        # check whether database is up by trying to get a connection
        try:
            get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
        except:
            print('[!] MariaDB seems to be down. The backup file wasn\'t deleted. To restore manually from the file, run the following command:')
            print(' '.join(restore_call+['<', MARIADB_BACKUP_FILE, '&&', 'rm', MARIADB_BACKUP_FILE]))
        else:
            os.remove(MARIADB_BACKUP_FILE)


def communicate_warning(msg: str):
    """Communicate warning via logger or stdout"""

    if not QUIET:
        print("Warning: " + msg)


def fill_database_with_mapinfo(cve_edb_map):
    """ Put the given mapping data into the database specified by the given cursor """

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    update_statement = "UPDATE cve SET edb_ids=? WHERE cve_id=?"
    for cveid, edbids in cve_edb_map.items():
        if cveid == "N/A":  # skip the fake item holding EDBIDs without CVEID
            continue

        edbids = sorted(set(edbids), key=lambda eid: int(eid))
        db_cursor.execute(update_statement, (",".join(edbids), cveid))

    db_conn.commit()
    db_conn.close()


def create_cveid_edbid_mapping():
    """ Create a CVE ID --> EDB ID mapping and store in local vuln DB """

    # download exploit index file from GitLab
    cve_edb_map = {}
    cve_re = re.compile(r'((cve|CVE)-[0-9]{4}-[0-9]{4,})')
    exploits_csv = requests.get('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv')
    exploits_csv = exploits_csv.content.decode()
    exploits_csv = csv.reader(exploits_csv.splitlines(), delimiter=',')
    cve_info_column = None
    for row in exploits_csv:
        # get index of "codes" column, which contains info about CVE, OSVDB and other IDs
        if not cve_info_column:
            for i, col in enumerate(row):
                if col.strip().lower() == 'codes':
                    cve_info_column = i
                    break
            continue

        # extract CVEs from "codes" column and store in map
        codes = row[cve_info_column].strip()
        if codes:
            edbid = row[0]
            codes = codes.replace('–', '-')  # replace EN Dash with Hyphen
            for code in cve_re.findall(codes):
                cve_id = code[0]
                if cve_id not in cve_edb_map:
                    cve_edb_map[cve_id] = []
                if edbid not in cve_edb_map[cve_id]:
                    cve_edb_map[cve_id].append(edbid)

    # save map separately as byproduct and in vuln DB for usage
    with open(CONFIG['CVE_EDB_MAP_FILE'], "w") as f:
        f.write(json.dumps(cve_edb_map))
    fill_database_with_mapinfo(cve_edb_map)


def create_poc_in_github_table():
    """ Create CVE ID <--> GitHub PoC URL mapping"""

    if os.path.isdir(POC_IN_GITHUB_DIR):
        shutil.rmtree(POC_IN_GITHUB_DIR)

    # download PoC in GitHub Repo
    return_code = subprocess.call(
        "git clone --depth 1 %s '%s'"
        % (POC_IN_GITHUB_REPO, POC_IN_GITHUB_DIR),
        shell=True,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception("Could not download latest resources of PoC-in-GitHub"))

    # add PoC / exploit information to DB
    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    create_poc_in_github_table = CREATE_SQL_STATEMENTS['TABLES']['CVE_POC_IN_GITHUB_MAP'][CONFIG['DATABASE']['TYPE']]
    # necessary because SQLite can't handle more than one query a time
    for query in create_poc_in_github_table.split(';'):
        if query:
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


def parse_eold_product_releases(release_info_raw):
    # parse manually instead of using a third-party YAML parser
    releases = []

    for release_raw in re.split(r'- *releaseCycle', release_info_raw):
        release_raw = release_raw.strip()
        release_raw = release_raw.strip()
        if not release_raw:
            continue

        release = {}
        added_back_cycle_key = False
        for line in release_raw.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            elif '#' in line:
                line = line[:line.find('#')]
            if not added_back_cycle_key:
                line = '-   releaseCycle' + line
                added_back_cycle_key = True

            if line.startswith('-'):
                line = line[1:]
                line = line.strip()

            key, val = line.split(':', maxsplit=1)
            key, val = key.strip(), val.strip()
            if len(key) > 1 and key.startswith('"') and key.endswith('"'):
                key = key[1:-1].strip()
            if len(val) > 1 and val.startswith('"') and val.endswith('"'):
                val = val[1:-1].strip()
            if len(key) > 1 and key.startswith("'") and key.endswith("'"):
                key = key[1:-1].strip()
            if len(val) > 1 and val.startswith("'") and val.endswith("'"):
                val = val[1:-1].strip()
            release[key] = val
        if release:
            releases.append(release)

    return releases


def create_endoflife_date_table():
    """ Create table containing product release data from endoflife.date """

    if os.path.isdir(EOLD_GITHUB_DIR):
        shutil.rmtree(EOLD_GITHUB_DIR)

    # download endoflife.date repo
    return_code = subprocess.call(
        "git clone --depth 1 %s '%s'"
        % (EOLD_GITHUB_REPO, EOLD_GITHUB_DIR),
        shell=True,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception("Could not download latest resources of endoflife.date"))

    # load hardcoded EOLD product --> CPE matches
    hardcoded_matches = {}
    with open(EOLD_HARDCODED_MATCHES_FILE) as f:
        hardcoded_matches = json.loads(f.read())

    eold_products_dir = os.path.join(EOLD_GITHUB_DIR, 'products')
    product_title_re = re.compile(r'---\s*[tT]itle: ([^\n]+)')
    product_eold_id_re = re.compile(r'permalink: /([^\n]+)')
    product_releases_re = re.compile(r'^[Rr]eleases:(.*?)---', re.MULTILINE | re.DOTALL)

    # create endoflife.date data
    eold_data, printed_wait = {}, False
    for filename in os.listdir(eold_products_dir):

        if not QUIET and NVD_UPDATE_SUCCESS and not printed_wait:
            print("Waiting for end of life data creation to finish ...")
            printed_wait = True
        elif (NVD_UPDATE_SUCCESS is not None) and (not NVD_UPDATE_SUCCESS):
            if os.path.isdir(EOLD_GITHUB_DIR):
                shutil.rmtree(EOLD_GITHUB_DIR)
            return

        with open(os.path.join(eold_products_dir, filename)) as f:
            product_content = f.read()

        # work around (temporary) EoLD data bug, see https://github.com/endoflife-date/endoflife.date/commit/2c23c3f7e58a19cbefed814d3125403b61a7b035#diff-788cea2420ea468fc502aabb8477fb4063f25db4091d95004e0ca31bc6b52227R22
        product_content = product_content.replace('releases:\nreleases:', 'releases:')

        eold_product_title = product_title_re.search(product_content)
        if not eold_product_title:
            continue
        eold_product_title = eold_product_title.group(1)

        eold_product_id = product_eold_id_re.search(product_content)
        if not eold_product_id:
            eold_product_id = os.path.basename(filename)
        else:
            eold_product_id = eold_product_id.group(1)

        product_releases = product_releases_re.search(product_content)
        if not product_releases:
            continue

        product_releases = parse_eold_product_releases(product_releases.group(1))
        cpes = []
        if eold_product_id in hardcoded_matches or eold_product_id.lower() in hardcoded_matches:
            cpes = hardcoded_matches[eold_product_id]
            cpes = [':'.join(cpe.split(':')[:5]) + ':' for cpe in cpes]
        else:
            cpe_results = search_cpes(eold_product_title, config=CONFIG['cpe_search'])
            cpe = ''
            if cpe_results and cpe_results['cpes']:
                cpe = cpe_results['cpes'][0][0]
            elif cpe_results['pot_cpes']:
                cpe = cpe_results['pot_cpes'][0][0]
            if cpe:
                cpe = ':'.join(cpe.split(':')[:5]) + ':'
                cpes = [cpe]

        eold_entry = {'eold-id': eold_product_id, 'eold-title': eold_product_title, 'releases': product_releases}
        for cpe in cpes:
            eold_data[cpe] = eold_entry

    while NVD_UPDATE_SUCCESS is None:
        time.sleep(1)

    if NVD_UPDATE_SUCCESS:
        # put endoflife.data data into DB
        db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
        db_cursor = db_conn.cursor()
        create_eol_date_table = CREATE_SQL_STATEMENTS['TABLES']['EOL_DATE'][CONFIG['DATABASE']['TYPE']]
        # necessary because SQLite can't handle more than one query a time
        for query in create_eol_date_table.split(';'):
            if query:
                db_cursor.execute(query+';')

        for cpe, eold_entry in eold_data.items():
            # iterate over releases in reversed order, s.t. oldest release always has unique ID 0
            for i, release in enumerate(reversed(eold_entry['releases'])):
                version_start = release['releaseCycle']
                version_latest = release.get('latest', '')  # e.g. slackware
                eol_info = release.get('eol', 'false')
                db_data = (cpe, i, eold_entry['eold-id'], eold_entry['eold-title'],
                            version_start, version_latest, eol_info)
                db_cursor.execute('INSERT INTO eol_date_data VALUES (?, ?, ?, ?, ?, ?, ?)', db_data)

        db_conn.commit()
        db_conn.close()

    if os.path.isdir(EOLD_GITHUB_DIR):
        shutil.rmtree(EOLD_GITHUB_DIR)


def compute_cosine_similarity(text_1: str, text_2: str, text_vector_regex=r"[a-zA-Z0-9\.]+"):
    """
    Compute the cosine similarity of two text strings.
    :param text_1: the first text
    :param text_2: the second text
    :return: the cosine similarity of the two text strings
    """

    def text_to_vector(text: str):
        """
        Get the vector representation of a text. It stores the word frequency
        of every word contained in the given text.
        :return: a Counter object that stores the word frequencies in a dict
                 with the respective word as key
        """
        word = re.compile(text_vector_regex)
        words = word.findall(text)
        return Counter(words)

    text_vector_1, text_vector_2 = text_to_vector(text_1), text_to_vector(text_2)

    intersecting_words = set(text_vector_1.keys()) & set(text_vector_2.keys())
    inner_product = sum([text_vector_1[w] * text_vector_2[w] for w in intersecting_words])

    abs_1 = math.sqrt(sum([cnt**2 for cnt in text_vector_1.values()]))
    abs_2 = math.sqrt(sum([cnt**2 for cnt in text_vector_2.values()]))
    normalization_factor = abs_1 * abs_2

    if not normalization_factor:  # avoid divison by 0
        return 0.0
    return float(inner_product)/float(normalization_factor)


def add_ghsa_data_to_db():
    """Add GitHub Security Advisory DB data to vuln DB"""

    if os.path.isdir(GHSA_GITHUB_DIR):
        shutil.rmtree(GHSA_GITHUB_DIR)

    # download GitHub reviewed advisories from GHSA repo
    return_code = subprocess.call(
        "git clone -n --depth=1 --filter=tree:0 %s '%s' && " % (GHSA_GITHUB_REPO, GHSA_GITHUB_DIR) +
        "cd %s && " % GHSA_GITHUB_DIR +
        "git sparse-checkout set --no-cone advisories/github-reviewed/ && " +
        "git checkout",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception("Could not download latest resources of the GHSA"))

    # set up DB connection and tables
    vulndb_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    vulndb_cursor = vulndb_conn.cursor()
    create_ghsa_table_stmt = CREATE_SQL_STATEMENTS['TABLES']['GHSA'][CONFIG['DATABASE']['TYPE']]
    create_ghsa_cpe_table_stmt = CREATE_SQL_STATEMENTS['TABLES']['GHSA_CPE'][CONFIG['DATABASE']['TYPE']]
    for stmt in create_ghsa_table_stmt.split(';'):
        if stmt:
            vulndb_cursor.execute(stmt+';')
    for stmt in create_ghsa_cpe_table_stmt.split(';'):
        if stmt:
            vulndb_cursor.execute(stmt+';')
    if CONFIG['DATABASE']['TYPE'] == 'sqlite':
        import sqlite3
        sql_integrity_error = sqlite3.IntegrityError
    elif CONFIG['DATABASE']['TYPE'] == 'mariadb':
        import mariadb
        sql_integrity_error = mariadb.IntegrityError

    # variables to manage data across steps
    sim_score_thres_good_cpe = 0.35
    pname_cpe_map = {}
    ghsa_no_cpe_yet = []
    ghsa_affects_map = {}
    description_meta_info_re = re.compile(r'^([\*\:]*[A-Z ]+[\*\:]+)')
    cpe_creation_github_ref_re = re.compile(r"^(https://)?github.com/([\w.\-]+)\/([\w.\-]+)/?[^/]*$")
    cpe_creation_slash_re = re.compile(r"^([\w.\-]+)\/([\w.\-]+)/?[^/]*$")
    cpe_creation_single_word_re = re.compile(r"^\w+$")
    difficult_package_prefixes = ['github.com/go', 'github.com/microsoft/go', 'microsoft/microsoft']
    ghsa_hardcoded_matches = {}

    with open(GHSA_HARDCODED_MATCHES_FILE) as f:
        ghsa_hardcoded_matches = json.loads(f.read())

    # only traverse reviewed advisories, since only those have information about affected software
    for dirpath, _, files in os.walk(os.path.join(GHSA_GITHUB_DIR, 'advisories/github-reviewed')):
        for file in files:
            with open(os.path.join(dirpath, file)) as af:
                advisory = json.load(af)

            if advisory.get('withdrawn', ''):  # skip withdrawn entries
                continue

            # extract affects statements and map them to the same structure as the cve_cpe table
            ghsa_id = advisory['id']
            ghsa_affects_map[ghsa_id] = []
            advisory_affected_pnames = set()
            for pkg in advisory['affected']:
                pname = pkg['package']['name'].lower()
                ecosystem = pkg['package']['ecosystem'].lower()
                single_version_affected = False
                affected_ranges = []
                advisory_affected_pnames.add(pname)

                # extract affected version ranges
                for pkg_range in pkg.get('ranges', []):  # usually just one entry
                    introduced, fixed, is_version_end_incl = '', '', False
                    for event in pkg_range.get('events'):
                        if 'introduced' in event and not introduced:
                            introduced = event['introduced']
                        if 'fixed' in event and not fixed:
                            fixed = event['fixed']
                        if 'last_affected' in event and not fixed:
                            fixed = event['last_affected']
                            is_version_end_incl = True
                    affected_ranges.append((pname, ecosystem, introduced, fixed, is_version_end_incl))
                for version in pkg.get('versions', []):  # usually just one entry or omitted
                    if version == introduced:  # just a single version is affected
                        single_version_affected = True
                    ghsa_affects_map[ghsa_id].append((pname, ecosystem, version))
                if not single_version_affected:  # only add range(s) if more than one version is affected
                    for affected_range in affected_ranges:
                        ghsa_affects_map[ghsa_id].append(affected_range)

            # get list of all CVE aliasses, retrieve all their affected CPEs
            # and try to match every product name to one of these CPEs
            all_cves = []
            for alias in advisory['aliases']:
                if alias.startswith('CVE-'):
                    all_cves.append(alias)

            all_cve_cpes = set()
            for cve_id in all_cves:
                vulndb_cursor.execute('SELECT cpe FROM cve_cpe WHERE cve_id = ?', (cve_id, ))
                cve_cpes = vulndb_cursor.fetchall()
                if cve_cpes:  # MariaDB returns None and SQLite an empty list
                    for cpe in cve_cpes:
                        cpe_split = cpe[0].split(':')
                        cpe_version_wildcarded = ':'.join(cpe_split[:5]) + ':*:*:' + ':'.join(cpe_split[7:])
                        all_cve_cpes.add(cpe_version_wildcarded)

            for pname in advisory_affected_pnames:
                if pname in pname_cpe_map:
                    continue

                if pname in ghsa_hardcoded_matches:
                    pname_cpe_map[pname] = (ghsa_hardcoded_matches[pname], 1)
                elif len(advisory_affected_pnames) == 1 and len(all_cve_cpes) == 1:
                    pname_cpe_map[pname] = (next(iter(all_cve_cpes)), 1)
                else:
                    # try to retrieve a CPE for the product name by comparing it with the NVD's affected CPEs
                    most_similar = None
                    for cpe in all_cve_cpes:
                        sim = compute_cosine_similarity(cpe[10:], pname, r"[a-zA-Z0-9]+")
                        if not most_similar or sim > most_similar[1]:
                            most_similar = (cpe, sim)

                    if most_similar and most_similar[1] > sim_score_thres_good_cpe:
                        if pname not in pname_cpe_map or most_similar[1] > pname_cpe_map[pname][1]:
                            pname_cpe_map[pname] = most_similar
                    else:
                        ghsa_no_cpe_yet.append((pname, ghsa_id))

            # retrieve CVSS version, vector, score and GHSA severity
            if advisory['severity']:
                cvss_vector = advisory['severity'][0]['score']
                cvss_version = cvss_vector[cvss_vector.find(':')+1:cvss_vector.find('/')]
                cvss_score = 0.0
                if cvss_version[0] == '2':
                    cvss_score = CVSS2(cvss_vector).scores()[0]
                if cvss_version[0] == '3':
                    cvss_score = CVSS3(cvss_vector).scores()[0]
                if cvss_version[0] == '4':
                    cvss_score = CVSS4(cvss_vector).scores()[0]
            else:
                cvss_score, cvss_vector, cvss_version = '0.0', '', '0.0'
            severity = advisory['database_specific'].get('severity', 'N/A')

            # retrieve description and dates
            # take care to keep meta information from vuln details / summary
            description, other_description = advisory.get('details', ''), ''
            if description and len(description) > 600:  # use summary instead of long text
                other_description = description
                description = advisory.get('summary', '')
            else:
                other_description = advisory.get('summary', '')
            meta_info_match = description_meta_info_re.match(other_description)
            if meta_info_match:
                if not description.startswith(meta_info_match.group(0)):
                    description = meta_info_match.group(0) + ' ' + description

            published = advisory['published'].replace('T', ' ').replace('Z', '')
            last_modified = advisory['modified'].replace('T', ' ').replace('Z', '')

            # put new GHSA entry into DB
            vulndb_cursor.execute('INSERT INTO ghsa VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);',
                                  (ghsa_id, ','.join(advisory['aliases']), description, published,
                                  last_modified, cvss_version, cvss_score, cvss_vector, severity))
    vulndb_conn.commit()

    # if a CPE couldn't be found by comparing a product name with the NVD's
    # CPEs for the same vulnerbility, use cpe_search to attempt finding a CPE.
    for (pname, ghsa_id) in ghsa_no_cpe_yet:
        product_cpe = pname_cpe_map.get(pname, None)
        if not product_cpe:
            # skip assigning CPEs to cerrtain packages for now, because it's too
            # difficult, e.g., GHSA-78hx-gp6g-7mj6 or https://github.com/advisories/GHSA-7mc6-x925-7qvx
            if any(pname.startswith(prefix) for prefix in difficult_package_prefixes):
                pname_cpe_map[pname] = (pname, None)
                continue

            cpe_search_results = search_cpes(pname)
            cpe_search_cpes = cpe_search_results.get('cpes', [])
            if not cpe_search_cpes:
                cpe_search_cpes = cpe_search_results.get('pot_cpes', [])
            if cpe_search_cpes:
                cpe_parts = cpe_search_cpes[0][0].split(':')
                product_cpe = ':'.join(cpe_parts[:5] + ['*'] * 8)
                pname_cpe_map[pname] = (product_cpe, 0)
            else:
                pname_cpe_map[pname] = (pname, None)

    # Add affects statements of every GHSA vulnerability to DB and create CPEs if necessary
    newly_created_cpes = set()
    for ghsa_id, affects in ghsa_affects_map.items():
        cpe_affected_version_map = {}
        cpe_number_version_ranges_map = {}

        for product in affects:
            if not product:
                continue

            pname = product[0]
            if any(pname.startswith(prefix) for prefix in difficult_package_prefixes):
                continue  # again, skip difficult packages for now

            cpe_entry = pname_cpe_map.get(pname, (pname, ''))
            cpe = pname  # fall back to pname if no CPE could be found (without much use for now)
            if cpe_entry[1] is not None:
                cpe = cpe_entry[0]

            # create custom CPE if vendor and product name are somewhat clear
            # to achieve this, try to match the GHSA product name to a vendor:product structure
            if not cpe.startswith('cpe:2.3:'):
                cpe_vendor, cpe_product = '', ''
                cpe_creation_match = cpe_creation_github_ref_re.match(cpe)
                if cpe_creation_match:
                    cpe_vendor, cpe_product = cpe_creation_match.group(2), cpe_creation_match.group(3)
                if not cpe_vendor:
                    cpe_creation_match = cpe_creation_slash_re.match(cpe)
                    if cpe_creation_match:
                        cpe_vendor, cpe_product = cpe_creation_match.group(1), cpe_creation_match.group(2)
                if not cpe_vendor:
                    cpe_creation_match = cpe_creation_single_word_re.match(cpe)
                    if cpe_creation_match:
                        cpe_vendor, cpe_product = cpe_creation_match.group(0), cpe_creation_match.group(0)

                if cpe_vendor:
                    cpe = 'cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*' % (cpe_vendor, cpe_product)
                    cpe_entry = (cpe, 0)
                    newly_created_cpes.add(cpe)
                    pname_cpe_map[pname] = cpe_entry

            # collect plain information about affects statements and how many different version ranges are listed
            product_ver_str = json.dumps(product[2:])
            if cpe not in cpe_affected_version_map:
                cpe_affected_version_map[cpe] = {}
            if product_ver_str not in cpe_affected_version_map[cpe]:
                cpe_affected_version_map[cpe][product_ver_str] = 0
            cpe_affected_version_map[cpe][product_ver_str] += 1

            pname = product[1] + ':' + pname  # prefix with ecosystem to create unique identifier
            if cpe not in cpe_number_version_ranges_map:
                cpe_number_version_ranges_map[cpe] = {}
            if pname not in cpe_number_version_ranges_map[cpe]:
                cpe_number_version_ranges_map[cpe][pname] = 0
            cpe_number_version_ranges_map[cpe][pname] += 1

        # convert plain version range information to CPE affects statements and put into vuln DB
        # also try to solve problem: different GHSA product names are matched to same CPE, where the
        # match is bad sometimes. To not pollute the vuln data too much, do not put outliers into DB,
        # when every other affects statement of the vulnerability speaks against it.
        for cpe, version_ranges in cpe_number_version_ranges_map.items():
            number_version_ranges = max(list(version_ranges.values()))
            cpe_affected_version_map[cpe] = [ver_range_count for ver_range_count in cpe_affected_version_map[cpe].items()]
            cpe_affected_version_map[cpe] = sorted(cpe_affected_version_map[cpe], key=lambda ver_range: ver_range[1], reverse=True)
            for ver_range in cpe_affected_version_map[cpe][:number_version_ranges]:
                ver_range = json.loads(ver_range[0])

                # try to detect and fix defective version ranges by comparing with other affected products
                if number_version_ranges == 1 and ver_range[0] == "0" and not ver_range[1]:
                    if all(len(cpe_affected_version_map[other_cpe]) == 1 for other_cpe in cpe_affected_version_map):
                        for other_cpe in cpe_affected_version_map:
                            if len(cpe_affected_version_map[other_cpe]) == 1:
                                ver_range = json.loads(cpe_affected_version_map[other_cpe][0][0])
                                break

                cpe_split = cpe.split(':')
                if cpe.startswith('cpe:2.3:'):  # skip products without CPE
                    if len(ver_range) == 1:
                        cpe = ':'.join(cpe_split[:5]) + ':' + ver_range[0] + ':' + ':'.join(cpe_split[6:])
                        try:
                            vulndb_cursor.execute('INSERT INTO ghsa_cpe VALUES(?, ?, ?, ?, ?, ?)', (ghsa_id,
                                                cpe, '', False, '', False))
                        except sql_integrity_error:
                            # probably UniqueConstraint, which can happen if a different
                            # product name is matched to the same CPE
                            pass
                    elif len(ver_range) == 3:
                        cpe_split[5] = '*'
                        cpe = ':'.join(cpe_split)
                        try:
                            vulndb_cursor.execute('INSERT INTO ghsa_cpe VALUES(?, ?, ?, ?, ?, ?)', (ghsa_id,
                                                cpe, ver_range[0], True, ver_range[1], ver_range[2]))
                        except sql_integrity_error:
                            # probably UniqueConstraint, which can happen if a different
                            # product name is matched to the same CPE
                            pass

    vulndb_conn.commit()
    vulndb_cursor.close()
    vulndb_conn.close()

    # add newly_created_cpes to CPE dict
    add_cpes_to_db(newly_created_cpes, CONFIG['cpe_search'], check_duplicates=False)

    if os.path.isdir(GHSA_GITHUB_DIR):
        shutil.rmtree(GHSA_GITHUB_DIR)


def add_vuln_cpes_to_cpe_search():
    '''Add CPEs only present in NVD vulnerability data to cpe_search DB'''

    # get distinct official NVD CPEs
    db_conn_cpes = get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
    db_cursor_cpes = db_conn_cpes.cursor()
    db_cursor_cpes.execute('SELECT DISTINCT cpe FROM cpe_entries')
    nvd_official_cpes = db_cursor_cpes.fetchall()
    nvd_official_cpes = set([cpe[0] for cpe in nvd_official_cpes])
    db_cursor_cpes.close()
    db_conn_cpes.close()

    # get distinct CPEs from vulns
    db_conn_vulndb = get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
    db_cursor_vulndb = db_conn_vulndb.cursor()
    db_cursor_vulndb.execute('SELECT DISTINCT cpe FROM cve_cpe')
    vuln_cpes = db_cursor_vulndb.fetchall()
    vuln_cpes = set([cpe[0] for cpe in vuln_cpes])
    db_cursor_vulndb.close()
    db_conn_vulndb.close()

    not_contained_cpes = vuln_cpes - nvd_official_cpes
    add_cpes_to_db(not_contained_cpes, CONFIG['cpe_search'], check_duplicates=False)


def run(full=False, nvd_api_key=None, config_file=''):
    global CONFIG
    global CONFIG_FILE
    global CREATE_SQL_STATEMENTS
    CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(config_file)), config_file)

    # load config
    if config_file:
        CONFIG = _load_config(config_file)
    else:
        CONFIG = _load_config()
    CONFIG['DATABASE_BACKUP_FILE'] = CONFIG['DATABASE_NAME'] + '.bak'
    CONFIG['CPE_DATABASE_BACKUP_FILE'] = CONFIG['cpe_search']['DATABASE_NAME'] + '.bak'
    CONFIG['DEPRECATED_CPES_BACKUP_FILE'] = CONFIG['cpe_search']['DEPRECATED_CPES_FILE'] + '.bak'

    with open(CREATE_SQL_STATEMENTS_FILE) as f:
        CREATE_SQL_STATEMENTS = json.loads(f.read())

    # create file dirs as needed
    update_files = [CONFIG['CVE_EDB_MAP_FILE'], CONFIG['cpe_search']['DEPRECATED_CPES_FILE']]
    if CONFIG['DATABASE']['TYPE'] == 'sqlite':
        update_files += [CONFIG['DATABASE_NAME'], CONFIG['cpe_search']['DATABASE_NAME']]
    for file in update_files:
        os.makedirs(os.path.dirname(file), exist_ok=True)

    if full:
        if not nvd_api_key:
            nvd_api_key = os.getenv('NVD_API_KEY')
            if (not nvd_api_key) and CONFIG:
                nvd_api_key = CONFIG.get('NVD_API_KEY', None)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print("[+] Updating stored software information")
        error = loop.run_until_complete(handle_cpes_update(nvd_api_key))
        if error:
            print("[-] Error updating stored software information")
            sys.exit(1)
        print("[+] Updating vulnerability database")
        error = loop.run_until_complete(update_vuln_db(nvd_api_key))
        if error:
            print(error)
            sys.exit(1)
    else:
        print("[+] Downloading latest versions of resources ...")

        if os.path.isfile(CONFIG['cpe_search']['DATABASE_NAME']):
            shutil.move(CONFIG['cpe_search']['DATABASE_NAME'], CONFIG['CPE_DATABASE_BACKUP_FILE'])
        if os.path.isfile(CONFIG['cpe_search']['DEPRECATED_CPES_FILE']):
            shutil.move(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'], CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
        if os.path.isfile(CONFIG['DATABASE_NAME']):
            shutil.move(CONFIG['DATABASE_NAME'], CONFIG['DATABASE_BACKUP_FILE'])
        # backup MariaDB
        if CONFIG['DATABASE']['TYPE'] == 'mariadb':
            try:
                # check whether database exists
                get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
                get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
            except:
                pass
            else:
                # backup MariaDB
                backup_call = ['mariadb-dump',
                                '-u', CONFIG['DATABASE']['USER'],
                                '-h', CONFIG['DATABASE']['HOST'],
                                '-P', str(CONFIG['DATABASE']['PORT']),
                                '--add-drop-database', '--add-locks',
                                '-B', CONFIG['DATABASE_NAME'],
                                '-B', CONFIG['cpe_search']['DATABASE_NAME'],
                                '-r', MARIADB_BACKUP_FILE]
                if CONFIG['DATABASE']['PASSWORD']:
                    backup_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")
                return_code = subprocess.call(backup_call, stderr=subprocess.DEVNULL)
                if return_code != 0:
                    print(f'[-] MariaDB backup failed')
            # expand paths
            CONFIG['DATABASE_NAME'] = os.path.join(os.path.dirname(os.path.abspath(config_file)), CONFIG['DATABASE_NAME'])
            CONFIG['cpe_search']['DATABASE_NAME'] = os.path.join(os.path.dirname(os.path.abspath(config_file)), CONFIG['cpe_search']['DATABASE_NAME'])

        try:
            quiet_flag = ""
            if QUIET:
                quiet_flag = "-q"
            else:
                quiet_flag = "-q --show-progress"
            return_code = subprocess.call("wget %s %s -O %s" % (quiet_flag, shlex.quote(CPE_DICT_ARTIFACT_URL),
                                          shlex.quote(CONFIG['cpe_search']['DATABASE_NAME'])), shell=True)
            if return_code != 0:
                raise(Exception("Could not download latest resource files"))

            return_code = subprocess.call("wget %s %s -O %s" % (quiet_flag, shlex.quote(CPE_DEPRECATIONS_ARTIFACT_URL),
                                          shlex.quote(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'])), shell=True)
            if return_code != 0:
                raise(Exception("Could not download latest resource files"))

            return_code = subprocess.call("wget %s %s -O %s" % (quiet_flag, shlex.quote(VULNDB_ARTIFACT_URL),
                                          shlex.quote(CONFIG['DATABASE_NAME'])), shell=True)
            if return_code != 0:
                raise(Exception("Could not download latest resource files"))

            if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
                os.remove(CONFIG['CPE_DATABASE_BACKUP_FILE'])
            if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
                os.remove(CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
            if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
                os.remove(CONFIG['DATABASE_BACKUP_FILE'])

            # migrate SQLite to MariaDB if specified database type is mariadb
            if CONFIG['DATABASE']['TYPE'] == 'mariadb':
                print('[+] Migrating from SQLite to MariaDB (takes around 2 minutes)...')
                return_code = subprocess.call('./resources/migrate_sqlite_to_mariadb.sh %s %s %s' % (shlex.quote(CONFIG['DATABASE_NAME']), shlex.quote(CONFIG['cpe_search']['DATABASE_NAME']), CONFIG_FILE), shell=True, stderr=subprocess.DEVNULL)
                if return_code != 0:
                    raise(Exception('Migration of database failed'))
                os.remove(MARIADB_BACKUP_FILE)
                os.remove(CONFIG['DATABASE_NAME'])
                os.remove(CONFIG['cpe_search']['DATABASE_NAME'])
        except Exception as e:
            print("[!] Encountered an error: %s" % str(e))
            if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
                shutil.move(CONFIG['CPE_DATABASE_BACKUP_FILE'], CONFIG['cpe_search']['DATABASE_NAME'])
                print("[+] Restored software infos from backup")
            if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
                shutil.move(CONFIG['DEPRECATED_CPES_BACKUP_FILE'], CONFIG['cpe_search']['DEPRECATED_CPES_FILE'])
                print("[+] Restored software deprecation infos from backup")
            if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
                shutil.move(CONFIG['DATABASE_BACKUP_FILE'], CONFIG['DATABASE_NAME'])
                print("[+] Restored vulnerability infos from backup")
            if os.path.isfile(MARIADB_BACKUP_FILE) and CONFIG['DATABASE']['TYPE'] == 'mariadb':
                with open(MARIADB_BACKUP_FILE, 'rb') as f:
                    mariadb_backup_data = f.read()
                restore_call = ['mariadb', '-u', CONFIG['DATABASE']['USER'],
                                '-h', CONFIG['DATABASE']['HOST'],
                                '-P', str(CONFIG['DATABASE']['PORT'])]
                if CONFIG['DATABASE']['PASSWORD']:
                    restore_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")
                restore_call_run = subprocess.run(restore_call, input=mariadb_backup_data)
                if restore_call_run.returncode != 0:
                    print('[-] Failed to restore MariaDB')
                else:
                    print('[+] Restored MariaDB from backup')

                # Restore failed b/c database is down -> not delete backup file
                # check whether database is up by trying to get a connection
                try:
                    get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
                except:
                    print('[!] MariaDB seems to be down. The backup file wasn\'t deleted. To restore manually from the file, run the following command:')
                    print(' '.join(restore_call+['<', MARIADB_BACKUP_FILE, '&&', 'rm', MARIADB_BACKUP_FILE]))
                else:
                    os.remove(MARIADB_BACKUP_FILE)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--full":
        run(True)
    else:
        run(False)
