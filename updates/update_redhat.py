#!/usr/bin/env python3

import os
import requests
import sqlite3
import sys

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

from bs4 import BeautifulSoup
from search_vulns import VULNDB_FILE

from .update_generic import *
from .update_distributions_generic import *

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json

REDHAT_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'redhat_data_feeds')

REDHAT_NOT_FOUND_NAME = {}
REDHAT_RELEASES = {}

REDHAT_UPDATE_SUCCESS = None
CVE_REDHAT_API_URL = 'https://access.redhat.com/hydra/rest/securitydata'
REQUEST_HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0'}
REDHAT_MAPPING_VERSION_CODENAME_URL = 'https://docs.fedoraproject.org/en-US/quick-docs/fedora-and-red-hat-enterprise-linux/'
REDHAT_EOL_DATA_API_URL = 'https://endoflife.date/api/rhel.json' 


def rollback_redhat():
    '''Performs rollback specific for redhat'''
    rollback()
    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)


def get_redhat_version_codename_mapping():
    global REDHAT_UPDATE_SUCCESS

    if not QUIET:
        print('[+] Downloading redhat version-codename-mapping data')

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

    if not QUIET:
        print('[+] Downloading redhat version-codename-mapping data')

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

    get_redhat_version_codename_mapping()
    redhat_eol_json = get_redhat_eol_data()

    db_conn = sqlite3.connect(VULNDB_FILE)
    db_cursor = db_conn.cursor()
    query = 'INSERT INTO distribution_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)'

    # extract codename and version from json
    for release in redhat_eol_json:
        version = release['cycle']
        codename = REDHAT_RELEASES[version]
        support_expires = str(release['support'])
        esm_expires = str(release['extendedSupport'])
        
        db_cursor.execute(query, ('redhat', version, codename, support_expires, esm_expires))

    db_conn.commit()
    db_conn.close()


async def update_vuln_redhat_db():
    '''Update the vulnerability database for redhat'''

    # get redhat releases data
    initialize_redhat_release_version_codename()