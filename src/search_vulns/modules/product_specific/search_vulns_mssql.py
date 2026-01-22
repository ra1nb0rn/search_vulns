import csv
import io
import logging
import re
from datetime import datetime
from typing import Dict, Tuple

import requests

from search_vulns.models.CPEVersion import CPEVersion
from search_vulns.models.SearchVulnsResult import ProductIDsResult, SearchVulnsResult
from search_vulns.models.Vulnerability import DataSource, MatchReason, Vulnerability
from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    get_database_connection,
    split_cpe,
)

LOGGER = logging.getLogger()
SQL_SERVER_BUILDS_VULN_DATA_URL = "https://docs.google.com/spreadsheets/d/16Ymdz80xlCzb6CwRFVokwo0onkofVYFoSkc7mYe6pgw/export?gid=0&format=csv"
SQL_SERVER_BUILDS_RELEASES_URL = "https://docs.google.com/spreadsheets/d/16Ymdz80xlCzb6CwRFVokwo0onkofVYFoSkc7mYe6pgw/export?gid=1648964847&format=csv"
SQL_SERVER_BUILDS_OVERVIEW_URL = "https://sqlserverbuilds.blogspot.com/"
MICROSOFT_ADVISORY_BASE_URL = "https://msrc.microsoft.com/update-guide/en-US/vulnerability/"
MSSQL_QUERY_RE = re.compile(
    r"(mssql|((microsoft)?\s*sql\s*server))\s*((\d+\.\d+).\d+\.\d+)", re.IGNORECASE
)


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    db_conn, db_cursor = None, None

    try:
        # retrieve vuln and release data by SQL Server Builds (https://sqlserverbuilds.blogspot.com/)
        resp = requests.get(SQL_SERVER_BUILDS_VULN_DATA_URL)
        if resp.status_code != 200:
            LOGGER.error(
                f"Got response code {resp.status_code} when trying to retrieve MSSQL vuln data"
            )
            return False, []

        # parse release CVE data
        reader = csv.DictReader(io.StringIO(resp.text))
        db_data = []
        max_cve_len = -1
        for row in reader:
            if len(row["CVEs"]) > max_cve_len:
                max_cve_len = len(row["CVEs"])
            db_data.append((row["SQLServer"], row["Build"], row["ReleaseDate"], row["CVEs"]))

        # create vuln table in vulndb
        db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        db_cursor = db_conn.cursor()
        if vulndb_config["TYPE"] == "sqlite":
            db_cursor.execute("DROP TABLE IF EXISTS mssql_vulns;")
            create_vuln_table = f"CREATE TABLE mssql_vulns (mssql_release VARCHAR(20), build VARCHAR(25), release_date VARCHAR(20), cves VARCHAR({max_cve_len+1}), PRIMARY KEY (build));"
            import sqlite3

            sql_integrity_error = sqlite3.IntegrityError
        elif vulndb_config["TYPE"] == "mariadb":
            import mariadb

            create_vuln_table = f"CREATE OR REPLACE TABLE mssql_vulns (mssql_release VARCHAR(20) CHARACTER SET ascii, build VARCHAR(25) CHARACTER SET ascii, release_date VARCHAR(20) CHARACTER SET ascii, cves VARCHAR({max_cve_len+1}) CHARACTER SET ascii, PRIMARY KEY (build));"
            sql_integrity_error = mariadb.IntegrityError
        db_cursor.execute(create_vuln_table)

        # put release data into DB
        insert_query = "INSERT INTO mssql_vulns VALUES(?, ?, ?, ?)"
        for row in db_data:
            try:
                db_cursor.execute(insert_query, row)
            except sql_integrity_error:
                # old releases sometimes have duplicate build number, e.g. 9.0.3186
                # ignore and only put latest release in DB
                pass
        db_conn.commit()
        db_cursor.close()
        db_conn.close()

        # retrieve release EoL data
        resp = requests.get(SQL_SERVER_BUILDS_RELEASES_URL)
        if resp.status_code != 200:
            LOGGER.error(
                f"Got response code {resp.status_code} when trying to retrieve MSSQL releases data"
            )
            return False, []

        db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        db_cursor = db_conn.cursor()
        if vulndb_config["TYPE"] == "sqlite":
            db_cursor.execute("DROP TABLE IF EXISTS mssql_releases;")
            create_vuln_table = "CREATE TABLE mssql_releases (mssql_release VARCHAR(20), version VARCHAR(10), eol_date VARCHAR(13), PRIMARY KEY (mssql_release));"
        elif vulndb_config["TYPE"] == "mariadb":
            create_vuln_table = "CREATE OR REPLACE TABLE mssql_releases (mssql_release VARCHAR(20) CHARACTER SET ascii, version VARCHAR(10) CHARACTER SET ascii, eol_date VARCHAR(13) CHARACTER SET ascii, PRIMARY KEY (mssql_release));"
        db_cursor.execute(create_vuln_table)

        reader = csv.DictReader(io.StringIO(resp.text))
        insert_query = "INSERT INTO mssql_releases VALUES(?, ?, ?)"
        for row in reader:
            if row["ExtendedSupportEnds"]:
                db_cursor.execute(
                    insert_query, (row["Release"], row["Version"], row["ExtendedSupportEnds"])
                )
            else:
                db_cursor.execute(
                    insert_query, (row["Release"], row["Version"], row["MainstreamSupportEnds"])
                )
        db_conn.commit()
    except Exception as e:
        LOGGER.error(f"Ran into an error {resp.status_code} when trying to process MSSQL data")
        raise e
    finally:
        if db_cursor:
            db_cursor.close()
        if db_conn:
            db_conn.close()

    return True, []


def preprocess_query(
    query, product_ids: ProductIDsResult, vuln_db_cursor, product_db_cursor, config
) -> Tuple[str, Dict]:

    # hijack query to match to proper CPE
    matches = MSSQL_QUERY_RE.findall(query)
    if matches:
        release_version = matches[0][-1]
        build = matches[0][-2]
        # strip double zero
        if release_version.endswith("00"):
            release_version = release_version[:-1]
        vuln_db_cursor.execute(
            "SELECT mssql_release FROM mssql_releases WHERE version = ?", (release_version,)
        )
        release = vuln_db_cursor.fetchall()
        cpes = []
        if release:
            release = release[0][0]

            # the NVD uses several valid CPEs ...
            cpes.append(f"cpe:2.3:a:microsoft:sql_server:{build}:*:*:*:*:*:*:*")
            if " " in release:
                a, b = release.split(" ")
                cpes.append(f"cpe:2.3:a:microsoft:sql_server_{a}:{b}:*:*:*:*:*:*:*")
            else:
                cpes.append(f"cpe:2.3:a:microsoft:sql_server_{release}:{build}:*:*:*:*:*:*:*")

        return query.replace(matches[0][0], ""), {"mssql_cpes": cpes, "mssql_build": build}


def search_product_ids(
    query: str,
    product_db_cursor,
    current_product_ids: ProductIDsResult,
    is_product_id_query,
    config,
    extra_params,
) -> Tuple[ProductIDsResult, ProductIDsResult]:

    # provide the previously determined CPE as product ID
    if "mssql_cpes" in extra_params:
        product_ids = ProductIDsResult.from_cpes(extra_params["mssql_cpes"])
        return product_ids, None


def search_vulns(
    query, product_ids: ProductIDsResult, vuln_db_cursor, config, extra_params
) -> Dict[str, Vulnerability]:

    # check if module should run and retrieve extra params
    queried_build = None
    if "mssql_build" in extra_params:
        queried_build = extra_params["mssql_build"]
    else:
        for cpe in product_ids.cpe:
            cpe_split = split_cpe(cpe)
            if cpe_split[3] == "microsoft" and cpe_split[4].startswith("sql_server"):
                queried_build = cpe_split[5]
    if not queried_build:
        return

    # check if queried release is EoL
    queried_release_nr = ".".join(queried_build.split(".")[:2])
    queried_build_is_eol = False
    vuln_db_cursor.execute(
        "SELECT mssql_release, eol_date FROM mssql_releases WHERE version = ?",
        (queried_release_nr,),
    )
    queried_release_data = vuln_db_cursor.fetchall()
    if queried_release_data:
        queried_release = CPEVersion(queried_release_data[0][0])
        if queried_release_data[0][1]:
            eol_date = datetime.strptime(queried_release_data[0][1], "%Y-%m-%d")
            if datetime.now() >= eol_date:
                queried_build_is_eol = True

    # retrieve MSSQL vuln data sorted by build number
    vuln_db_cursor.execute("SELECT * FROM mssql_vulns;")
    vuln_data = vuln_db_cursor.fetchall()
    vuln_data = sorted(vuln_data, key=lambda release: CPEVersion(release[1]), reverse=True)

    # iterate over release vuln data with sliding window to
    # differentiate between CU/SP and GDR patches
    queried_build = CPEVersion(queried_build)
    cur_cves, all_seen_cves, cur_release_str = [], [], ""
    last_release_date, cur_release_date = "", ""
    last_fixed_cves_str = ""
    cur_fixed_cves = []
    for row in vuln_data:
        # parse data of current build
        release, build, release_date, cves_str = row
        if release_date:
            cur_release_date = datetime.strptime(release_date, "%Y-%m-%d")
        if not cur_release_str:
            cur_release_str = release

        # discover break point if queried build was found
        # keep going if queried release is EoL to gather fixed vulns for release
        if queried_build > CPEVersion(build):
            if not queried_build_is_eol:
                break
            elif queried_release > CPEVersion(release):
                break
            cur_fixed_cves += last_fixed_cves_str.split(",")

        # append vulns fixed by previous release
        if last_fixed_cves_str:
            all_seen_cves += cur_cves
            if not cur_fixed_cves:
                cur_cves += last_fixed_cves_str.split(",")

        # enter a new window if a release with later date was found
        last_fixed_cves_str = cves_str
        if not last_release_date:
            last_release_date = cur_release_date
        elif cur_release_date > last_release_date:
            cur_cves, cur_release_str = [], ""
            last_release_date, cur_release_date = "", ""
            continue

        cur_release_str = release
        last_fixed_cves_str = cves_str
        last_release_date = cur_release_date

    # determine vulns affecting queried build
    cur_cves = set(cur_cves)
    cur_fixed_cves = set(cur_fixed_cves)
    all_seen_cves = set(all_seen_cves)
    if not queried_build_is_eol:
        affected_by_cves = cur_cves
    else:
        affected_by_cves = all_seen_cves - cur_fixed_cves

    # return vulns to search_vulns core
    vulns = {}
    for cve_id in affected_by_cves:
        vulns[cve_id] = Vulnerability.from_vuln_match_with_vuln_reference(
            cve_id,
            MatchReason.VERSION_IN_RANGE,
            DataSource.PRODUCT_SPECIFIC,
            SQL_SERVER_BUILDS_OVERVIEW_URL,
            MICROSOFT_ADVISORY_BASE_URL + cve_id,
        )

    return vulns
