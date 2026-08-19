import logging
from typing import Dict

import requests

from search_vulns.models.Vulnerability import Vulnerability
from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    extract_all_cve_ids_from_vulns,
    extract_all_ghsa_ids_from_vulns,
    get_database_connection,
    select_from_where_in_to_map,
)

KEVINTEL_FEED_BASE_URL = "https://kevintel.com/api/v2/kevs?per_page=100"
KEVINTEL_REFERENCE_BASE_URL = "https://kevintel.com/"
LOGGER = logging.getLogger()


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # CREATE TABLE
    if vulndb_config["TYPE"] == "sqlite":
        create_table_query = "DROP TABLE IF EXISTS kevintel; CREATE TABLE kevintel (vuln_id VARCHAR(45), PRIMARY KEY (vuln_id));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_table_query = "CREATE OR REPLACE TABLE kevintel (vuln_id VARCHAR(45) CHARACTER SET ascii, PRIMARY KEY (vuln_id));"

    # get DB connection and create table
    db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor = db_conn.cursor()

    # necessary because SQLite can't handle more than one query a time
    for query in create_table_query.split(";"):
        if query:
            db_cursor.execute(query + ";")
    db_conn.commit()

    # check for API key and skip if not present
    api_key = module_config.get("KEVINTEL_API_KEY")
    if not api_key:
        LOGGER.warning("No KEVIntel API key configured - skipping setup")
        return

    insert_query = "INSERT INTO kevintel VALUES(?)"
    headers = {"X-API-Token": api_key}
    page = 1
    while True:
        resp = requests.get(KEVINTEL_FEED_BASE_URL + f"&page={page}", headers=headers)
        if not resp.ok:
            LOGGER.warning("Got HTTP error when trying to retrieve KEVIntel data")
            return False, []
        kev_data = resp.json()
        for kev in kev_data["kevs"]:
            vuln_id = kev["vulnerability_id"]
            if not vuln_id:
                continue
            if vuln_id.split("-", maxsplit=1)[0] not in ("CVE", "GHSA", "EUVD"):
                continue
            db_cursor.execute(insert_query, (vuln_id,))

        if page >= int(kev_data["pagination"]["total_pages"]):
            break
        page += 1

    db_conn.commit()
    db_cursor.close()
    db_conn.close()


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # Add KEV info from KEVIntel if configured
    all_cve_ids = extract_all_cve_ids_from_vulns(vulns)
    all_ghsa_ids = extract_all_ghsa_ids_from_vulns(vulns)
    all_vuln_ids = all_cve_ids | all_ghsa_ids

    try:
        vuln_id_kev_map = select_from_where_in_to_map(
            vuln_db_cursor, "vuln_id", "vuln_id", "kevintel", "vuln_id", all_vuln_ids
        )
        for vuln in vulns.values():
            is_kev = False
            for cve_id in vuln.get_all_cve_ids():
                if cve_id in vuln_id_kev_map:
                    vuln.add_kev(KEVINTEL_REFERENCE_BASE_URL + f"{cve_id}#overview")
                    is_kev = True
            if is_kev:
                continue

            for ghsa_id in vuln.get_all_ghsa_ids():
                if ghsa_id in vuln_id_kev_map:
                    vuln.add_kev(KEVINTEL_REFERENCE_BASE_URL + f"{ghsa_id}#overview")
    except:
        # skip if KEVIntel is not set up
        pass
