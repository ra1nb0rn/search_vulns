import logging
from typing import Dict

import requests
import ujson

from search_vulns.models.Vulnerability import Vulnerability
from search_vulns.modules.utils import SQLITE_TIMEOUT, get_database_connection

VULN_TRACK_BASE_URL = "https://euvd.enisa.europa.eu/vulnerability/"
LOGGER = logging.getLogger()


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # download and parse KEV data
    resp = requests.get("https://euvdservices.enisa.europa.eu/api/kev/dump")
    if resp.status_code != 200:
        LOGGER.error("Could not retrieve EUVD KEV data")
        return False, []
    euvd_kev = set()
    for kev_item in ujson.loads(resp.text):
        if "eukev_kev" in kev_item["sources"]:
            euvd_kev.add(kev_item["euvdId"])

    # download EUVD <-> CVE mapping
    resp = requests.get("https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping")
    if resp.status_code != 200:
        LOGGER.error("Could not retrieve EUVD <-> CVE mapping")
        return False, []

    # set up connection to vuln DB
    db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor = db_conn.cursor()
    if vulndb_config["TYPE"] == "sqlite":
        create_cve_edbids_table = "DROP TABLE IF EXISTS euvd; CREATE TABLE euvd (euvd_id VARCHAR(25), cve_id VARCHAR(25), euvd_kev BOOL, PRIMARY KEY (euvd_id));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_cve_edbids_table = "CREATE OR REPLACE TABLE euvd (euvd_id VARCHAR(25) CHARACTER SET ascii, cve_id VARCHAR(25) CHARACTER SET ascii, euvd_kev BOOL, PRIMARY KEY (euvd_id));"
    # necessary because SQLite can't handle more than one query a time
    for query in create_cve_edbids_table.split(";"):
        if query:
            db_cursor.execute(query + ";")
    db_conn.commit()

    # simple processing, skip header line
    insert_statement = "INSERT INTO euvd VALUES(?, ?, ?)"
    for line in resp.text.splitlines()[1:]:
        euvd, cve = line.split(",")
        if not cve or not euvd:
            continue
        if euvd in euvd_kev:
            db_cursor.execute(insert_statement, (euvd, cve, True))
        else:
            db_cursor.execute(insert_statement, (euvd, cve, False))

    db_conn.commit()
    db_conn.close()


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # Add EUVD aliases to vulnerabilities having CVE identifiers

    # gather all cve_ids
    all_cve_ids = set()
    for vuln_id, vuln in vulns.items():
        if vuln_id.startswith("CVE-"):
            all_cve_ids.add(vuln_id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                all_cve_ids.add(alias)

    # make one joint SQL query with all involved cve_ids
    placeholders = ",".join(["?"] * len(all_cve_ids))  # → "?,?,?,..."
    if all_cve_ids:
        vuln_db_cursor.execute(
            f"SELECT cve_id, euvd_id FROM euvd WHERE cve_id IN ({placeholders})",
            list(all_cve_ids),
        )
        cve_euvd = vuln_db_cursor.fetchall()
    else:
        cve_euvd = []

    # create cve_id --> euvd_id map
    cve_euvd_map = {}
    for cve_id, euvd_id in cve_euvd:
        if cve_id not in cve_euvd_map:
            cve_euvd_map[cve_id] = set()
        cve_euvd_map[cve_id].add(euvd_id)

    # finally, add EUVD aliases
    for vuln_id, vuln in vulns.items():
        for alias in vuln.aliases | {vuln.id: ""}:
            if alias.startswith("CVE-"):
                for euvd_id in cve_euvd_map.get(alias, []):
                    if euvd_id not in vuln.aliases:
                        href = VULN_TRACK_BASE_URL + alias
                        vuln.add_alias(euvd_id, href)

                        # no actual tracking of vulns yet
                        # if alias not in vuln.aliases:
                        #     vuln.add_tracked_by_with_alias(DataSource.GHSA, href, alias)

    # TODO: EUVD KEV
