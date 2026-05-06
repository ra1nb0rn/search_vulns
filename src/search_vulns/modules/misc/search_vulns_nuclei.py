from typing import Dict

import requests
import ujson

from search_vulns.models.Vulnerability import Vulnerability
from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    extract_all_cve_ids_from_vulns,
    get_database_connection,
    select_from_where_in_to_map,
)

NUCLEI_CVE_TEMPLATE_MAP_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json"
NUCLEI_FILES_BASE_URL = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # download available Nuclei CVE data
    resp = requests.get(NUCLEI_CVE_TEMPLATE_MAP_URL)
    resp.raise_for_status()
    nuclei_data_raw = resp.text
    cve_nuclei_map = {}
    for line in nuclei_data_raw.splitlines():
        nuclei_data = ujson.loads(line)
        cve_id = nuclei_data["ID"]
        filepath = nuclei_data["file_path"]
        if cve_id not in cve_nuclei_map:
            cve_nuclei_map[cve_id] = []
        cve_nuclei_map[cve_id].append(filepath)

    # get DB connection and create table
    db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor = db_conn.cursor()

    if vulndb_config["TYPE"] == "sqlite":
        create_table_query = "DROP TABLE IF EXISTS nuclei_cve_templates; CREATE TABLE nuclei_cve_templates (cve_id VARCHAR(25), filepath VARCHAR(255), PRIMARY KEY (cve_id, filepath));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_table_query = "CREATE OR REPLACE TABLE nuclei_cve_templates (cve_id VARCHAR(25) CHARACTER SET ascii, filepath VARCHAR(255), PRIMARY KEY (cve_id, filepath));"

    # necessary because SQLite can't handle more than one query a time
    for query in create_table_query.split(";"):
        if query:
            db_cursor.execute(query + ";")
    db_conn.commit()

    # put data into DB
    insert_query = "INSERT INTO nuclei_cve_templates VALUES(?, ?);"
    for cve_id, filepaths in cve_nuclei_map.items():
        for filepath in filepaths:
            db_cursor.execute(insert_query, (cve_id, filepath))
    db_conn.commit()
    db_cursor.close()
    db_conn.close()


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # Add info about Nuclei templates to vulns
    all_cve_ids = extract_all_cve_ids_from_vulns(vulns)
    cve_nuclei_paths_map = select_from_where_in_to_map(
        vuln_db_cursor, "cve_id", "filepath", "nuclei_cve_templates", "cve_id", all_cve_ids
    )

    for vuln in vulns.values():
        exploits = set()
        for cve_id in vuln.get_all_cve_ids():
            nuclei_paths = cve_nuclei_paths_map.get(cve_id, None)
            if nuclei_paths:
                urls = [NUCLEI_FILES_BASE_URL + path for path in nuclei_paths]
                exploits |= set(urls)
        vuln.add_exploits(exploits)
