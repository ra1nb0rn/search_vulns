import gzip
import logging
import os
import shutil
import zipfile
from pathlib import Path

import requests
import ujson

from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    download_file,
    get_database_connection,
)

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search", "nvd.search_vulns_nvd"]
LOGGER = logging.getLogger()
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


def download_nvdpp_data(vulncheck_api_key):
    """Download Vulncheck NVD++ data via backup API"""

    headers = {"Authorization": "Bearer %s" % vulncheck_api_key}
    resp = requests.get("https://api.vulncheck.com/v3/backup/nist-nvd2", headers=headers)
    resp.raise_for_status()
    resp = resp.json()
    dl_url = resp["data"][0]["url"]
    dl_filename = resp["data"][0]["filename"]
    dl_filepath = os.path.join(SCRIPT_DIR, dl_filename)
    vuln_data_dir = os.path.join(SCRIPT_DIR, os.path.splitext(dl_filename)[0])
    download_file(dl_url, dl_filepath)
    with zipfile.ZipFile(dl_filepath, "r") as zf:
        zf.extractall(vuln_data_dir)
    os.remove(dl_filepath)
    return vuln_data_dir


def retrieve_vulncheck_cves(vulndb_config):
    """Determine CVEs for which Vulncheck data should be retrieved"""

    db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor = db_conn.cursor()

    # retrieve CVEs without vulnerable CPE
    db_cursor.execute(
        "SELECT cve_id from nvd where cve_id not in (SELECT DISTINCT cve_id FROM nvd_cpe);"
    )
    cves_no_cpe = [result[0] for result in db_cursor.fetchall()]

    # retrieve CVEs with only one general CPE affected
    db_cursor.execute(
        'SELECT DISTINCT cve_id FROM nvd_cpe WHERE cpe LIKE "%:*:*:*:*:*:*:*:*" AND cpe_version_start = "" AND cpe_version_end = "" AND cve_id IN (SELECT cve_id FROM nvd_cpe GROUP BY cve_id HAVING COUNT(*) = 1);'
    )
    cves_one_general_cpe = [result[0] for result in db_cursor.fetchall()]
    vulncheck_cves = cves_no_cpe + cves_one_general_cpe

    db_cursor.close()
    db_conn.close()
    return vulncheck_cves


def extract_affects_statements(vuln_data_dir, vulndb_config):
    """Extract vuln affects statements as needed from NVD++ data"""

    # retrieve CVEs that require more vuln data from NVD++
    vulncheck_cves = set(retrieve_vulncheck_cves(vulndb_config))

    # parse NVD++ data and retrieve affects statements
    affects_statements = []
    vuln_data_dir = Path(vuln_data_dir)
    for gz_file in vuln_data_dir.glob("*.json.gz"):
        with gzip.open(gz_file, "rt", encoding="utf-8") as f:
            vuln_data = ujson.load(f)
            for vuln in vuln_data["vulnerabilities"]:
                # first check if more data for current vuln is needed
                cve = vuln.get("cve", {})
                if not cve:
                    continue

                cve_id = cve["id"]
                if cve_id in vulncheck_cves:
                    vulncheck_cves.remove(cve_id)
                else:
                    continue

                # then generate affects statements from vuln data
                for vc_configs_entry in cve.get("vcConfigurations", []):
                    for vc_configs_node in vc_configs_entry.get("nodes", []):
                        for cpe_entry in vc_configs_node.get("cpeMatch", []):
                            if not cpe_entry["vulnerable"]:
                                continue
                            cpe = cpe_entry["criteria"]
                            cpe_version_start, cpe_version_end = "", ""
                            is_cpe_version_start_incl, is_cpe_version_end_incl = False, False
                            if "versionStartIncluding" in cpe_entry:
                                cpe_version_start = cpe_entry["versionStartIncluding"]
                                is_cpe_version_start_incl = True
                            elif "versionStartExcluding" in cpe_entry:
                                cpe_version_start = cpe_entry["versionStartExcluding"]
                                is_cpe_version_start_incl = False

                            if "versionEndIncluding" in cpe_entry:
                                cpe_version_end = cpe_entry["versionEndIncluding"]
                                is_cpe_version_end_incl = True
                            elif "versionEndExcluding" in cpe_entry:
                                cpe_version_end = cpe_entry["versionEndExcluding"]
                                is_cpe_version_end_incl = False

                            affects_statements.append(
                                (
                                    cve_id,
                                    cpe,
                                    cpe_version_start,
                                    is_cpe_version_start_incl,
                                    cpe_version_end,
                                    is_cpe_version_end_incl,
                                )
                            )
    return affects_statements


def store_affects_statements(vulndb_config, affects_statements):
    """Store the provided vuln affects statements in the DB"""

    # create Vulncheck NVD++ tables
    db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor = db_conn.cursor()
    if vulndb_config["TYPE"] == "sqlite":
        import sqlite3

        sql_integrity_error = sqlite3.IntegrityError
        db_cursor.execute("DROP TABLE IF EXISTS vulncheck_nvd_cpe;")
        db_cursor.execute(
            "CREATE TABLE vulncheck_nvd_cpe (cve_id VARCHAR(25), cpe VARCHAR(255), cpe_version_start VARCHAR(100), is_cpe_version_start_including BOOL, cpe_version_end VARCHAR(100), is_cpe_version_end_including BOOL, PRIMARY KEY(cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including));"
        )
    elif vulndb_config["TYPE"] == "mariadb":
        import mariadb

        sql_integrity_error = mariadb.IntegrityError
        db_cursor.execute(
            "CREATE OR REPLACE TABLE vulncheck_nvd_cpe (cve_id VARCHAR(25) CHARACTER SET ascii, cpe VARCHAR(255) CHARACTER SET utf8, cpe_version_start VARCHAR(100)  CHARACTER SET utf8, is_cpe_version_start_including BOOL, cpe_version_end VARCHAR(100)  CHARACTER SET utf8, is_cpe_version_end_including BOOL, PRIMARY KEY(cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including), INDEX(cpe) USING BTREE);"
        )

    # insert all NVD++ affects statements into DB
    insert_nvd_cpe_query = "INSERT INTO vulncheck_nvd_cpe VALUES(?, ?, ?, ?, ?, ?);"
    for stmt in affects_statements:
        if not stmt:
            continue
        try:
            db_cursor.execute(insert_nvd_cpe_query, stmt)
        except sql_integrity_error:
            pass
    db_conn.commit()
    db_cursor.close()
    db_conn.close()


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    """Perform full update"""

    vulncheck_api_key = os.getenv("VULNCHECK_API_KEY")
    if not vulncheck_api_key:
        vulncheck_api_key = module_config.get("VULNCHECK_API_KEY", "")

    if vulncheck_api_key:
        LOGGER.info("[+] Adding CVE (NVD) <-> CPE information from VulnCheck")

        vuln_data_dir = download_nvdpp_data(vulncheck_api_key)
        affects_statements = extract_affects_statements(vuln_data_dir, vulndb_config)
        store_affects_statements(vulndb_config, affects_statements)

        shutil.rmtree(str(vuln_data_dir))
