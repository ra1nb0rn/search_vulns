#!/usr/bin/env python3

import os
import asyncio
import shutil
import re
from cpe_search.database_wrapper_functions import get_database_connection
import subprocess
from search_vulns_modules.config import get_config
from cpe_version import CPEVersion
from search_vulns_modules.generic_functions import get_cpe_parts

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json

VULNDB_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/vulndb.db3"
NVD_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "nvd_data_feeds")
CPE_DICT_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/cpe-search-dictionary.db3"
CPE_DEPRECATIONS_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/deprecated-cpes.json"
CVE_EDB_MAP_ARTIFACT_URL = "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/cveid_to_edbid.json"

POC_IN_GITHUB_REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"
POC_IN_GITHUB_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "PoC-in-GitHub")

EOLD_GITHUB_REPO = "https://github.com/endoflife-date/endoflife.date"
EOLD_GITHUB_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "endoflife.date")
EOLD_HARDCODED_MATCHES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join('..', 'resources', 'eold_hardcoded_matches.json'))

REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0"}
NVD_UPDATE_SUCCESS = None
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MARIADB_BACKUP_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mariadb_dump.sql')
CREATE_SQL_STATEMENTS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join('..', 'resources', 'create_sql_statements.json'))
QUIET = False
DEBUG = False
API_RESULTS_PER_PAGE = 2000

with open(CREATE_SQL_STATEMENTS_FILE) as f:
    CREATE_SQL_STATEMENTS = json.loads(f.read())

def rollback():
    '''Rollback the DB / module update'''

    config = get_config()

    communicate_warning('An error occured, rolling back database update')
    if config['DATABASE']['TYPE'] == 'sqlite':
        if os.path.isfile(config['DATABASE_NAME']):
            os.remove(config['DATABASE_NAME'])
    if os.path.isfile(config['DATABASE_BACKUP_FILE']):
        shutil.move(config['DATABASE_BACKUP_FILE'], config['DATABASE_NAME'])
    if os.path.isdir(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    if os.path.isfile(MARIADB_BACKUP_FILE):
        with open(MARIADB_BACKUP_FILE, 'rb') as f:
            mariadb_backup_data = f.read()
        restore_call = ['mariadb', '-u', config['DATABASE']['USER'],
                        '-h', config['DATABASE']['HOST'],
                        '-P', str(config['DATABASE']['PORT'])]
        if config['DATABASE']['PASSWORD']:
            restore_call.append(f"-p{config['DATABASE']['PASSWORD']}")
        restore_call_run = subprocess.run(restore_call, input=mariadb_backup_data)
        if restore_call_run.returncode != 0:
            print('[-] Failed to restore MariaDB')
        else:
            print('[+] Restored MariaDB from backup')

        # Restore failed b/c database is down -> not delete backup file
        # check whether database is up by trying to get a connection
        try:
            get_database_connection(config['DATABASE'], config['cpe_search']['DATABASE_NAME'])
        except:
            print('[!] MariaDB seems to be down. The backup file wasn\'t deleted. To restore manually from the file, run the following command:')
            print(' '.join(restore_call+['<', MARIADB_BACKUP_FILE, '&&', 'rm', MARIADB_BACKUP_FILE]))
        else:
            os.remove(MARIADB_BACKUP_FILE)


def communicate_warning(msg: str):
    '''Communicate warning via logger or stdout'''

    if not QUIET:
        print('Warning: ' + msg)


def backup_mariadb_database(database, config):
    try:
        # check whether database exists
        get_database_connection(config['DATABASE'], database)
    except:
        pass
    else:
        # backup MariaDB
        backup_call = ['mariadb-dump',
                       '-u', config['DATABASE']['USER'],
                        '-h', config['DATABASE']['HOST'],
                        '-P', str(config['DATABASE']['PORT']),
                        '--add-drop-database', '--add-locks',
                        '-B', database, '-r', MARIADB_BACKUP_FILE]
        if config['DATABASE']['PASSWORD']:
            backup_call.append(f"-p{config['DATABASE']['PASSWORD']}")

        return_code = subprocess.call(backup_call)
        if return_code != 0:
            print(f'[-] MariaDB backup of {database} failed')