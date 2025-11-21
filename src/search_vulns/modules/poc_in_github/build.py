import csv
import logging
import os
import shutil
import subprocess

import ujson

from search_vulns.modules.utils import SQLITE_TIMEOUT, get_database_connection

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
POC_IN_GITHUB_REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"
POC_IN_GITHUB_DIR = os.path.join(SCRIPT_DIR, "PoC-in-GitHub")
LOGGER = logging.getLogger()


def cleanup():
    if os.path.isdir(POC_IN_GITHUB_DIR):
        shutil.rmtree(POC_IN_GITHUB_DIR)


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # download PoC in GitHub Repo
    cleanup()
    return_code = subprocess.call(
        "git clone --depth 1 %s '%s'" % (POC_IN_GITHUB_REPO, POC_IN_GITHUB_DIR),
        shell=True,
        stderr=subprocess.DEVNULL,
    )
    if return_code != 0:
        LOGGER.error("Could not download latest resources of PoC-in-GitHub")
        cleanup()
        return False, []

    # get DB connection and create table
    db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor = db_conn.cursor()

    if vulndb_config["TYPE"] == "sqlite":
        create_poc_in_github_table = "DROP TABLE IF EXISTS poc_in_github; CREATE TABLE poc_in_github (cve_id VARCHAR(25), reference VARCHAR(255), PRIMARY KEY (cve_id, reference));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_poc_in_github_table = "CREATE OR REPLACE TABLE poc_in_github (cve_id VARCHAR(25) CHARACTER SET ascii, reference VARCHAR(255), PRIMARY KEY (cve_id, reference));"

    # necessary because SQLite can't handle more than one query a time
    for query in create_poc_in_github_table.split(";"):
        if query:
            db_cursor.execute(query + ";")
    db_conn.commit()

    # add PoC / exploit information to DB
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
                cve_json = ujson.loads(cve_fh.read())
                for poc_item in cve_json:
                    db_cursor.execute(
                        "INSERT INTO poc_in_github VALUES (?, ?)",
                        (cve_id, poc_item["html_url"]),
                    )

    db_conn.commit()
    db_conn.close()
    cleanup()

    return True, []
