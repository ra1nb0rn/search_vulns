#!/usr/bin/env python3

import json
import os
import re
import requests
import shutil
import sqlite3
import shlex
import subprocess
import sys
import threading
import time
import zipfile

from cpe_search.cpe_search import update as update_cpe

NVD_DATAFEED_DIR = "nvd_data_feeds"
VULNDB_FILE = "vulndb.db3"
VULNDB_BACKUP_FILE = "vulndb_bak.db3"
REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0"}
NVD_UPDATE_SUCCESS = None
QUIET = False

def update_vuln_db():
    """Update the vulnerability database"""

    global NVD_UPDATE_SUCCESS

    full_edbid_update = True
    if os.path.isfile(VULNDB_FILE):
        shutil.move(VULNDB_FILE, VULNDB_BACKUP_FILE)
        full_edbid_update = False

    # start CVE ID <--> EDB ID mapping creation in background thread
    cve_edb_map_thread = threading.Thread(target=create_cveid_edbid_mapping, args=(full_edbid_update, ))
    cve_edb_map_thread.start()

    # download NVD datafeeds from https://nvd.nist.gov/vuln/data-feeds
    if os.path.exists(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    os.makedirs(NVD_DATAFEED_DIR)

    if not QUIET:
        print('[+] Downloading NVD data feeds and EDB information')

    # first download the data feed overview to retrieve URLs to all data feeds
    try:
        nvd_response = requests.get("https://nvd.nist.gov/vuln/data-feeds", timeout=20)
    except:
        NVD_UPDATE_SUCCESS = False
        communicate_warning('An error occured when trying to download webpage: https://nvd.nist.gov/vuln/data-feeds')
        rollback()
        cve_edb_map_thread.join()
        return 'An error occured when trying to download webpage: https://nvd.nist.gov/vuln/data-feeds'
    if nvd_response.status_code != requests.codes.ok:
        NVD_UPDATE_SUCCESS = False
        rollback()
        cve_edb_map_thread.join()
        return 'An error occured when trying to download webpage: https://nvd.nist.gov/vuln/data-feeds'

    # match the data feed URLs
    nvd_nist_datafeed_html = nvd_response.text
    jfeed_expr = re.compile(r"/feeds/json/cve/1\.1/nvdcve-1\.1-\d\d\d\d.json\.zip")
    nvd_feed_urls = re.findall(jfeed_expr, nvd_nist_datafeed_html)

    if not nvd_feed_urls:
        NVD_UPDATE_SUCCESS = False
        communicate_warning('No data feed links available on https://nvd.nist.gov/vuln/data-feeds')
        rollback()
        cve_edb_map_thread.join()
        return 'No data feed links available on https://nvd.nist.gov/vuln/data-feeds'

    # download all data feeds
    with open(os.devnull, "w") as outfile:
        zipfiles = []
        for nvd_feed_url in nvd_feed_urls:
            nvd_feed_url = "https://nvd.nist.gov" + nvd_feed_url
            outname = os.path.join(NVD_DATAFEED_DIR, nvd_feed_url.split("/")[-1])
            return_code = subprocess.call("wget %s -O %s" % (shlex.quote(nvd_feed_url), shlex.quote(outname)),
                                          stdout=outfile, stderr=subprocess.STDOUT, shell=True)
            if return_code != 0:
                NVD_UPDATE_SUCCESS = False
                communicate_warning('Retrieving NVD data feed %s failed' %  nvd_feed_url)
                rollback()
                cve_edb_map_thread.join()
                return 'Retrieving NVD data feed %s failed' %  nvd_feed_url
            zipfiles.append(outname)

    if os.path.isfile("wget-log"):
        os.remove("wget-log")

    # unzip data feeds
    if not QUIET:
        print("[+] Unzipping data feeds")

    for file in zipfiles:
        try:
            zip_ref = zipfile.ZipFile(file, "r")
            zip_ref.extractall(NVD_DATAFEED_DIR)
            zip_ref.close()
            os.remove(file)
        except:
            NVD_UPDATE_SUCCESS = False
            communicate_warning('Unzipping data feed %s failed' % file)
            rollback()
            cve_edb_map_thread.join()
            return 'Unzipping data feed %s failed' % file

    # build local NVD copy with downloaded data feeds
    print('[+] Building vulnerability database')
    create_db_call = ["./create_db", NVD_DATAFEED_DIR, VULNDB_FILE]
    with open(os.devnull, "w") as outfile:
        return_code = subprocess.call(create_db_call, stdout=outfile, stderr=subprocess.STDOUT)

    if return_code != 0:
        NVD_UPDATE_SUCCESS = False
        communicate_warning('Building NVD database failed')
        rollback()
        cve_edb_map_thread.join()
        return 'Building NVD database failed'

    shutil.rmtree(NVD_DATAFEED_DIR)
    if os.path.isfile(VULNDB_BACKUP_FILE):
        os.remove(VULNDB_BACKUP_FILE)
    NVD_UPDATE_SUCCESS = True
    cve_edb_map_thread.join()


def rollback():
    """Rollback the DB / module update"""

    communicate_warning('An error occured, rolling back database update')
    if os.path.isfile(VULNDB_FILE):
        os.remove(VULNDB_FILE)
    if os.path.isfile(VULNDB_BACKUP_FILE):
        shutil.move(VULNDB_BACKUP_FILE, VULNDB_FILE)
    if os.path.isdir(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)


def communicate_warning(msg: str):
    """Communicate warning via logger or stdout"""

    if not QUIET:
        print("Warning: " + msg)


def get_all_edbids():
    """ Return a list of all existing EDB IDs """
    files_exploits_resp = requests.get("https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv", headers=REQUEST_HEADERS)
    files_exploits = files_exploits_resp.text
    return re.findall(r"^(\d+),.*$", files_exploits, re.MULTILINE)


def create_cveid_edbid_mapping(full=True):
    """ Create a CVE ID <--> EDB ID mapping and store in local vuln DB """

    # get all existing EDB IDs
    all_edbids = set(get_all_edbids())
    if full:
        # if a full DB installation is done, build CVE ID <--> EDB ID mapping from scratch
        # use as base the mapping data from andreafioraldi's cve_searchsploit as base
        gh_map_cve_edb_resp = requests.get("https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping_cve.json", headers=REQUEST_HEADERS)
        cve_edb_map = json.loads(gh_map_cve_edb_resp.text)
        gh_map_edb_cve_resp = requests.get("https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping.json", headers=REQUEST_HEADERS)
        edb_cve_map = json.loads(gh_map_edb_cve_resp.text)
        gh_captured_edbids = set(edb_cve_map.keys())
        remaining_edbids = all_edbids - gh_captured_edbids
    else:
        # if the DB is only updated, build incremental
        # CVE ID <--> EDB ID mapping based on previous one
        cve_edb_map, edb_cve_map = recover_map_data_from_db()
        remaining_edbids = all_edbids - set(edb_cve_map.keys())

    # manually crawl the mappings not yet created
    cveid_expr = re.compile(r"https://nvd.nist.gov/vuln/detail/(CVE-\d\d\d\d-\d+)")
    pause_time, last_time, printed_wait = 0.51, time.time(), False
    for i, edbid in enumerate(remaining_edbids):
        # wait at least pause_time seconds before making another request to not put heavy load on servers
        time_diff = time.time() - last_time
        if time_diff < pause_time:
            time.sleep(pause_time - time_diff)
        last_time = time.time()

        if not QUIET and NVD_UPDATE_SUCCESS and not printed_wait:
            print("Waiting for CVE ID <--> EDB ID map creation to finish ...")
            printed_wait = True
        elif (NVD_UPDATE_SUCCESS is not None) and (not NVD_UPDATE_SUCCESS):
            return

        exploit_page_resp = requests.get("https://www.exploit-db.com/exploits/%s" % edbid, headers=REQUEST_HEADERS, timeout=10)
        cveids = cveid_expr.findall(exploit_page_resp.text)

        if edbid not in edb_cve_map:
            edb_cve_map[edbid] = cveids
        else:
            edb_cve_map[edbid] += cveids

        for cveid in cveids:
            if cveid not in cve_edb_map:
                cve_edb_map[cveid] = []
            cve_edb_map[cveid].append(edbid)

    while NVD_UPDATE_SUCCESS is None:
        time.sleep(1)

    if NVD_UPDATE_SUCCESS:
        fill_database_with_mapinfo(cve_edb_map, edb_cve_map)


def fill_database_with_mapinfo(cve_edb_map, edb_cve_map):
    """ Put the given mapping data into the database specified by the given cursor """

    db_conn = sqlite3.connect(VULNDB_FILE)
    db_cursor = db_conn.cursor()

    # 1. put cve_id --> edb_ids mapping info into database
    update_statement = "UPDATE cve SET edb_ids=? WHERE cve_id=?"
    for cveid, edbids in cve_edb_map.items():
        edbids = sorted(set(edbids), key=lambda eid: int(eid))
        db_cursor.execute(update_statement, (",".join(edbids), cveid))

    # 2. put edb_id --> cve_ids mapping info into database
    db_cursor.execute("CREATE TABLE edbid_cveid_map (edb_id TEXT PRIMARY KEY," +
                      "cve_ids TEXT DEFAULT \"\");")
    for edb_id in edb_cve_map.keys():
        db_cursor.execute("INSERT INTO edbid_cveid_map VALUES (?, ?)", (edb_id, ""))

    update_statement = "UPDATE edbid_cveid_map SET cve_ids=? WHERE edb_id=?"
    for edbid, cveids in edb_cve_map.items():
        cveids = set(cveids)
        db_cursor.execute(update_statement, (",".join(cveids), edbid))

    db_conn.commit()
    db_conn.close()


def recover_map_data_from_db():
    """ Return stored CVE ID <--> EDB ID mapping from DB backup file """

    db_conn = sqlite3.connect(VULNDB_BACKUP_FILE)
    db_cursor = db_conn.cursor()

    # recover CVE ID --> EDB ID data
    db_cursor.execute("SELECT cve_id, edb_ids FROM cve")
    map_data = db_cursor.fetchall()
    cve_edb_map = {}
    for cve_id, edb_ids in map_data:
        if edb_ids:
            cve_edb_map[cve_id] = edb_ids.split(",")

    # recover EDB ID --> CVE ID data
    db_cursor.execute("SELECT edb_id, cve_ids FROM edbid_cveid_map")
    map_data = db_cursor.fetchall()
    edb_cve_map = {}
    for edb_id, cve_ids in map_data:
        if cve_ids:
            edb_cve_map[edb_id] = cve_ids.split(",")
        else:
            edb_cve_map[edb_id] = ""

    db_conn.close()
    return cve_edb_map, edb_cve_map


def run():
    update_cpe("2.3")
    error = update_vuln_db()
    if error:
        print(error)
        sys.exit(1)


if __name__ == "__main__":
    run()
