import gzip
import logging

import requests

from search_vulns.modules.utils import get_database_connection

LOGGER = logging.getLogger()

EPSS_DATA_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    db_conn, db_cursor = None, None

    try:
        resp = requests.get(EPSS_DATA_URL)
        if resp.status_code != 200:
            LOGGER.error(
                f"Got response code {resp.status_code} when trying to retrieve EPSS data"
            )
            return False, []
        epss_csv = str(gzip.decompress(resp.content), "utf-8")

        db_conn = get_database_connection(vulndb_config)
        db_cursor = db_conn.cursor()

        # create EPSS table in vulndb
        if vulndb_config["TYPE"] == "sqlite":
            db_cursor.execute("DROP TABLE IF EXISTS cve_epss;")
            create_cve_epps_table = "CREATE TABLE cve_epss (cve_id VARCHAR(25), epss REAL, percentile REAL, PRIMARY KEY (cve_id));"
        elif vulndb_config["TYPE"] == "mariadb":
            create_cve_epps_table = "CREATE OR REPLACE TABLE cve_epss (cve_id VARCHAR(25) CHARACTER SET ascii, epss DOUBLE, percentile DOUBLE, PRIMARY KEY (cve_id));"
        db_cursor.execute(create_cve_epps_table)

        # parse EPSS CSV and insert values into vulndb table
        for line in epss_csv.splitlines()[2:]:
            cve, epss, percentile = line.split(",")
            db_cursor.execute("INSERT INTO cve_epss VALUES(?, ?, ?)", (cve, epss, percentile))

        db_conn.commit()
    except Exception as e:
        LOGGER.error(f"Ran into an error {resp.status_code} when trying to process EPSS data")
        raise e
    finally:
        if db_cursor:
            db_cursor.close()
        if db_conn:
            db_conn.close()

    return True, []


def add_extra_vuln_info(vulns, vuln_db_cursor, config, extra_params):
    for vuln_id, vuln in vulns.items():
        vuln_cve_ids = set()
        if vuln_id.startswith("CVE-"):
            vuln_cve_ids.add(vuln_id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                vuln_cve_ids.add(alias)

        # in case of multiple CVEs being mapped to one vuln, use highest EPSS
        epss = -1
        for cve_id in vuln_cve_ids:
            vuln_db_cursor.execute("SELECT epss FROM cve_epss WHERE cve_id = ?", (cve_id,))
            cur_epss = vuln_db_cursor.fetchone()
            if cur_epss:
                cur_epss = cur_epss[0]
                if cur_epss > epss:
                    epss = cur_epss

        if epss != -1:
            vuln.set_epss(epss)
