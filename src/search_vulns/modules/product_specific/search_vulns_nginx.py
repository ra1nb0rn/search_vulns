import html
import logging
import re
from typing import Dict

import requests

from search_vulns.models.CPEVersion import CPEVersion
from search_vulns.models.SearchVulnsResult import ProductIDsResult
from search_vulns.models.Vulnerability import DataSource, MatchReason, Vulnerability
from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    get_database_connection,
    split_cpe,
)

LOGGER = logging.getLogger()
NGINX_ADVISORIES_URL = "https://nginx.org/en/security_advisories.html"


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    db_conn, db_cursor = None, None

    try:
        resp = requests.get(NGINX_ADVISORIES_URL)
        if resp.status_code != 200:
            LOGGER.error(
                f"Got response code {resp.status_code} when trying to retrieve EPSS data"
            )
            return False, []

        # create vuln table in vulndb
        db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        db_cursor = db_conn.cursor()
        if vulndb_config["TYPE"] == "sqlite":
            db_cursor.execute("DROP TABLE IF EXISTS nginx_vulns;")
            create_vuln_table = "CREATE TABLE nginx_vulns (cve_id VARCHAR(25), version_start VARCHAR(13), version_end VARCHAR(13), version_end_incl BOOL, PRIMARY KEY (cve_id, version_start, version_end));"
        elif vulndb_config["TYPE"] == "mariadb":
            create_vuln_table = "CREATE OR REPLACE TABLE nginx_vulns (cve_id VARCHAR(25) CHARACTER SET ascii, version_start VARCHAR(13) CHARACTER SET ascii, version_end VARCHAR(13) CHARACTER SET ascii, version_end_incl BOOL, PRIMARY KEY (cve_id, version_start, version_end));"
        db_cursor.execute(create_vuln_table)

        # parse advisory data and insert into DB
        html_content = resp.text
        html_content = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html_content)
        text = re.sub(r"(?s)<[^>]+>", "\n", html_content)
        text = html.unescape(text)
        text = re.sub(r"\n{2,}", "\n", text)

        # extract advisories
        pattern = re.compile(
            r"(CVE-\d{4}-\d+)\s*" r"Not vulnerable:\s*([^\n]+)\s*" r"Vulnerable:\s*([^\n]+)",
            re.MULTILINE | re.IGNORECASE,
        )

        # parse advisories and create vuln data
        insert_query = "INSERT INTO nginx_vulns VALUES (?, ?, ?, ?)"
        last_not_vuln_version = "0"
        for cve, not_vuln, vuln in pattern.findall(text):
            cve, not_vuln, vuln = cve.strip(), not_vuln.strip(), vuln.strip()

            # not vulnerable
            not_vuln_entries_raw = [x.strip() for x in not_vuln.split(",") if x.strip()]
            not_vuln_ranges = []
            for version in not_vuln_entries_raw:
                version_parts = version.split(".")
                version_start = ".".join(version_parts[:2] + ["0"])
                if version.endswith("+"):
                    version_end = version[:-1]
                    version_parts[2] = version_parts[2][:-1]
                else:
                    version_end = version_start

                not_vuln_ranges.append((CPEVersion(version_start), CPEVersion(version_end)))
            not_vuln_ranges.sort(key=lambda entry: entry[0])

            # vulnerable
            vuln_entries = [x.strip() for x in vuln.split(",") if x.strip()]
            vuln_data = []
            for version in vuln_entries:
                inserted_data = False
                if version.lower() != "all":
                    # remove non-version information like "nginx/Windows"
                    version = "".join([c for c in version if c in "0123456789.-"])
                    if "-" in version:
                        version_start, version_end = version.split("-")
                    else:
                        version_start, version_end = version, version
                    version_start, version_end = version_start.strip(), version_end.strip()
                else:
                    # only affects CVE-2009-4487 , which has no clear resolution but is too old to matter
                    version_start, version_end = "0", last_not_vuln_version
                    vuln_data.append((version_start, version_end, True))
                    inserted_data = True

                if not inserted_data:
                    version_start, version_end = CPEVersion(version_start), CPEVersion(
                        version_end
                    )
                    for fixed_start, fixed_end in not_vuln_ranges:
                        if "".join(str(version_start).split(".")[:2]) == "".join(
                            str(fixed_start).split(".")[:2]
                        ):
                            fixed_start = version_start
                        if inserted_data:
                            version_start = fixed_start

                        if version_start <= fixed_start <= version_end:
                            if version_start <= fixed_end <= version_end:
                                vuln_data.append((str(version_start), str(fixed_end), False))
                            elif not inserted_data:
                                vuln_data.append((str(version_start), str(version_end), True))
                            else:
                                vuln_data.append((str(fixed_start), str(version_end), True))
                            inserted_data = True
                    if not inserted_data:
                        vuln_data.append((str(version_start), str(version_end), True))

            for start, end, end_incl in vuln_data:
                db_cursor.execute(insert_query, (cve, start, end, end_incl))
            if vuln_data:
                last_not_vuln_version = vuln_data[0][1]

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


def search_vulns(
    query, product_ids: ProductIDsResult, vuln_db_cursor, config, extra_params
) -> Dict[str, Vulnerability]:

    vuln_cves = set()
    vuln_data = None
    processed_versions = set()
    for cpe in product_ids.cpe:
        cpe_split = split_cpe(cpe)
        if cpe_split[4] in ("nginx", "nginx_open_source"):
            version = cpe_split[5]
            if version in processed_versions:
                continue
            processed_versions.add(version)
            version = CPEVersion(version)

            if vuln_data is None:
                vuln_db_cursor.execute(
                    "SELECT cve_id, version_start, version_end, version_end_incl from nginx_vulns;"
                )
                vuln_data = vuln_db_cursor.fetchall()
            if vuln_data:
                for cve_id, version_start, version_end, version_end_incl in vuln_data:
                    if cve_id in vuln_cves:
                        continue
                    version_start, version_end = CPEVersion(version_start), CPEVersion(
                        version_end
                    )
                    if version_start <= version:
                        if version < version_end:
                            vuln_cves.add(cve_id)
                        elif version == version_end and version_end_incl == 1:
                            vuln_cves.add(cve_id)

    vulns = {}
    for cve_id in vuln_cves:
        vulns[cve_id] = Vulnerability.from_vuln_match(
            cve_id,
            MatchReason.VERSION_IN_RANGE,
            DataSource.PRODUCT_SPECIFIC,
            NGINX_ADVISORIES_URL,
        )

    return vulns
