import logging
from typing import Dict

import requests

from search_vulns.models.Vulnerability import Vulnerability
from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    extract_all_cve_ids_from_vulns,
    get_database_connection,
    select_from_where_in_to_map,
)

KEVINTEL_FEED_BASE_URL = "https://kevintel.com/api/v2/kevs?per_page=100"
KEVINTEL_REFERENCE_BASE_URL = "https://kevintel.com/"
LOGGER = logging.getLogger()


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # CREATE TABLE
    if vulndb_config["TYPE"] == "sqlite":
        create_table_query = "DROP TABLE IF EXISTS kevintel; CREATE TABLE kevintel (cve_id VARCHAR(25), PRIMARY KEY (cve_id));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_table_query = "CREATE OR REPLACE TABLE kevintel (cve_id VARCHAR(25) CHARACTER SET ascii, PRIMARY KEY (cve_id));"

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
            db_cursor.execute(insert_query, (kev["cve_id"],))

        if page >= int(kev_data["pagination"]["total_pages"]):
            break
        page += 1

    db_conn.commit()
    db_cursor.close()
    db_conn.close()


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # Add KEV info from KEVIntel if configured
    all_cve_ids = extract_all_cve_ids_from_vulns(vulns)

    try:
        cve_kev_map = select_from_where_in_to_map(
            vuln_db_cursor, "cve_id", "cve_id", "kevintel", "cve_id", all_cve_ids
        )
        for vuln in vulns.values():
            for cve_id in vuln.get_all_cve_ids():
                if cve_id in cve_kev_map:
                    vuln.add_kev(KEVINTEL_REFERENCE_BASE_URL + f"{cve_id}#overview")
    except:
        # skip if KEVIntel is not set up
        pass
