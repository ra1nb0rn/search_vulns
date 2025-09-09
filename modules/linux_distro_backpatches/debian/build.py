import logging
import os
import re

import requests

try:
    import ujson as json
except ImportError:
    import json

from modules.cpe_search.cpe_search.cpe_search import search_cpes
from modules.linux_distro_backpatches.utils import get_clean_version
from modules.utils import (
    SQLITE_TIMEOUT,
    compute_cosine_similarity,
    get_database_connection,
    get_versionless_cpes_of_nvd_cves,
)

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search", "nvd.search_vulns_nvd"]
LOGGER = logging.getLogger()

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"
}
CVE_DEBIAN_API_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_RELEASES_URL = "https://debian.pages.debian.net/distro-info-data/debian.csv"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DEBIAN_HARDCODED_MATCHES_FILE = os.path.join(SCRIPT_DIR, "debian_hardcoded_matches.json")

DEBIAN_NOT_FOUND_NAME = {}
DEBIAN_RELEASES = {}
SIM_SCORE_THRES_NVD_CPE_RETRIEVAL = 0.35
VERSION_IN_NAME_RE = re.compile(r"([a-zA-Z\-_])+(\d[\d\.]*)$")


############################################################################################
### Created with help of original connector to Debian API by https://github.com/MRuppDev ###
############################################################################################


def download_debian_release_version_codename_data(vulndb_config):
    global DEBIAN_RELEASES

    try:
        resp = requests.get(url=DEBIAN_RELEASES_URL)
        if resp.status_code != 200:
            LOGGER.error(
                f"Got response code {resp.status_code} when trying to retrieve Debian releases"
            )
            return False

        db_conn = get_database_connection(vulndb_config)
        db_cursor = db_conn.cursor()

        # create codename-version table in vulndb
        if vulndb_config["TYPE"] == "sqlite":
            db_cursor.execute("DROP TABLE IF EXISTS debian_codename_version_mapping;")
            create_mapping_table = "CREATE TABLE debian_codename_version_mapping (source CHAR(6), version VARCHAR(23), codename VARCHAR(25), support_expires DATETIME, esm_lts_expires DATETIME, PRIMARY KEY(source, version, codename));"
        elif vulndb_config["TYPE"] == "mariadb":
            create_mapping_table = "CREATE OR REPLACE TABLE debian_codename_version_mapping (source CHAR(6) CHARACTER SET ascii, version VARCHAR(15) CHARACTER SET ascii, codename VARCHAR(25) CHARACTER SET ascii, support_expires DATETIME, esm_lts_expires DATETIME, PRIMARY KEY(source, version, codename));"
        db_cursor.execute(create_mapping_table)

        insert_release_query = "INSERT INTO debian_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)"
        for release in resp.text.splitlines()[1:]:
            split_release = release.split(",")
            # append empty string if last fields not given
            for i in range(len(split_release), 8):
                split_release.append("")
            version, _, codename, _, _, eol, eol_lts, eol_lts = split_release

            # skip development releases
            if codename in ("sid", "experimental"):
                continue

            if not eol:
                eol = None
            if not eol_lts:
                eol_lts = None

            db_cursor.execute(insert_release_query, ("debian", version, codename, eol, eol_lts))
            DEBIAN_RELEASES[codename] = version

        db_conn.commit()
        db_cursor.close()
        db_conn.close()

    except Exception as e:
        LOGGER.error(f"Ran into an error when trying to retrieve Debian releases")
        raise e

    return True


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    success = download_debian_release_version_codename_data(vulndb_config)
    if not success:
        return False, []

    with open(DEBIAN_HARDCODED_MATCHES_FILE) as f:
        pkg_cpe_matches_hardcoded = json.loads(f.read())

    vulndb_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    vulndb_cursor = vulndb_conn.cursor()
    productdb_conn = get_database_connection(productdb_config)
    productdb_cursor = productdb_conn.cursor()
    try:
        resp = requests.get(CVE_DEBIAN_API_URL, headers=REQUEST_HEADERS)
        if resp.status_code != 200:
            LOGGER.error(
                f"Got response code {resp.status_code} when trying to retrieve Debian vuln data"
            )
            return False, []
        cves_debian = json.loads(resp.text)

        vuln_data = {}
        pkgs_latest_versions = {}
        pkg_cpe_map = {}
        pkgs_no_cpe = []

        # go over every package
        for initial_pkg, vulns in cves_debian.items():
            if stop_update.is_set():
                return False, []

            # sometimes, package has version in its name, e.g. apache2, libssh2 or log4j1.2
            version_in_name_match = VERSION_IN_NAME_RE.findall(initial_pkg)
            all_pkgs = [(None, initial_pkg)]
            if version_in_name_match:
                new_pkg = initial_pkg.replace(version_in_name_match[0][-1], "")
                if new_pkg.endswith("-") or new_pkg.endswith("_"):
                    new_pkg = new_pkg[:-1]
                all_pkgs.append((version_in_name_match[0][-1], new_pkg))

            for version_start, pkg in all_pkgs:
                vuln_data[pkg] = {}
                cpe = None
                if pkg in pkg_cpe_matches_hardcoded:
                    cpe = pkg_cpe_matches_hardcoded[pkg]

                # go over every package's vulns
                all_affected_nvd_cpes = []
                for cve_id, vuln_details in vulns.items():
                    # store all encountered general product cpes
                    affected_nvd_cpes = get_versionless_cpes_of_nvd_cves(
                        [cve_id], vulndb_cursor
                    )
                    all_affected_nvd_cpes += affected_nvd_cpes

                    # try to match pkg to CPE via this vuln
                    if cpe is None and len(affected_nvd_cpes) == 1:
                        if pkg.lower() in affected_nvd_cpes[0].lower():
                            cpe = affected_nvd_cpes[0]

                    # retrieve fixed versions
                    vuln_data[pkg][cve_id] = []
                    for release_codename, status in vuln_details["releases"].items():
                        status_text = status.get("status", "")
                        if status_text in ("resolved",):
                            fixed_version = status["fixed_version"]
                            latest_version = ""
                            if release_codename in status["repositories"]:
                                latest_version = status["repositories"][release_codename]

                            # remove unneeded endings and such like '+deb11u14'
                            clean_fixed_version = get_clean_version(fixed_version)
                            vuln_data[pkg][cve_id].append(
                                (release_codename, clean_fixed_version)
                            )
                            if latest_version:
                                latest_version = get_clean_version(latest_version)
                                if pkg not in pkgs_latest_versions:
                                    pkgs_latest_versions[pkg] = {}
                                if release_codename not in pkgs_latest_versions[pkg]:
                                    pkgs_latest_versions[pkg][release_codename] = set()
                                pkgs_latest_versions[pkg][release_codename].add((version_start, latest_version))

                # try to retrieve a CPE for the product name by comparing it with the NVD's affected CPEs
                if not cpe:
                    most_similar = None
                    for cpe in all_affected_nvd_cpes:
                        sim = compute_cosine_similarity(cpe[10:], pkg, r"[a-zA-Z0-9]+")
                        if not most_similar or sim > most_similar[1]:
                            most_similar = (cpe, sim)

                    if most_similar and most_similar[1] > SIM_SCORE_THRES_NVD_CPE_RETRIEVAL:
                        cpe = most_similar[0]

                # try to use cpe_search to find CPE (may yield quite some false positives,
                # but that doesn't matter for now, since no vulnerability retrieval is planned)
                if not cpe:
                    cpe_search_results = search_cpes(pkg, productdb_cursor)
                    cpe_search_cpes = cpe_search_results.get("cpes", [])
                    if not cpe_search_cpes:
                        cpe_search_cpes = cpe_search_results.get("pot_cpes", [])
                    if cpe_search_cpes:
                        cpe_parts = cpe_search_cpes[0][0].split(":")
                        cpe = ":".join(cpe_parts[:5] + ["*"] * 8)

                if not cpe:
                    pkgs_no_cpe.append(pkg)
                else:
                    pkg_cpe_map[pkg] = cpe

        # create fixed version table in vulndb
        if vulndb_config["TYPE"] == "sqlite":
            vulndb_cursor.execute("DROP TABLE IF EXISTS debian_backpatches;")
            create_backpatches_table = "CREATE TABLE debian_backpatches (cve_id VARCHAR(25), codename VARCHAR(25), cpe VARCHAR(255), fixed_version VARCHAR(100), PRIMARY KEY(cve_id, codename, cpe, fixed_version));"
            import sqlite3

            sql_integrity_error = sqlite3.IntegrityError
        elif vulndb_config["TYPE"] == "mariadb":
            create_backpatches_table = "CREATE OR REPLACE TABLE debian_backpatches (cve_id VARCHAR(25) CHARACTER SET ascii, codename VARCHAR(25) CHARACTER SET ascii, cpe VARCHAR(255) CHARACTER SET utf8, fixed_version VARCHAR(100) CHARACTER SET utf8, PRIMARY KEY(cve_id, codename, cpe, fixed_version));"
            import mariadb

            sql_integrity_error = mariadb.IntegrityError
        vulndb_cursor.execute(create_backpatches_table)

        insert_patch_info_query = "INSERT INTO debian_backpatches VALUES (?, ?, ?, ?);"
        for pkg in vuln_data:
            if stop_update.is_set():
                return False, []
            if pkg not in pkg_cpe_map:
                continue

            for cve_id, fixed_details in vuln_data[pkg].items():
                for release_codename, fixed_version in fixed_details:
                    try:
                        # special case for firefox, thunderbird, etc. "esr"
                        if "esr" in fixed_version and (
                            "esr" in pkg_cpe_map[pkg] or pkg == "thunderbird"
                        ):
                            fixed_version = fixed_version.replace("esr", "")
                        vulndb_cursor.execute(
                            insert_patch_info_query,
                            (cve_id, release_codename, pkg_cpe_map[pkg], fixed_version),
                        )
                    # unique constrained failed, b/c sometimes two packages rightfully match
                    # to same CPE and cause duplicate insert, since version is also the same
                    except sql_integrity_error:
                        pass

        # create latest pkg versions table
        if vulndb_config["TYPE"] == "sqlite":
            vulndb_cursor.execute("DROP TABLE IF EXISTS debian_latest_pkg_versions;")
            create_latest_releases_table = "CREATE TABLE debian_latest_pkg_versions (cpe VARCHAR(255), pkg VARCHAR(100), codename VARCHAR(25), version_start VARCHAR(25), latest_version VARCHAR(100), PRIMARY KEY(cpe, pkg, codename, version_start, latest_version));"
        elif vulndb_config["TYPE"] == "mariadb":
            create_latest_releases_table = "CREATE OR REPLACE TABLE debian_latest_pkg_versions (cpe VARCHAR(255) CHARACTER SET utf8, pkg VARCHAR(100) CHARACTER SET ascii, codename VARCHAR(25) CHARACTER SET ascii, version_start VARCHAR(25) CHARACTER SET utf-8, latest_version VARCHAR(100) CHARACTER SET utf8, PRIMARY KEY(cpe, pkg, codename, version_start, latest_version));"
        vulndb_cursor.execute(create_latest_releases_table)

        insert_latest_version_info_query = (
            "INSERT INTO debian_latest_pkg_versions VALUES (?, ?, ?, ?, ?);"
        )
        for pkg, latest_version_info in pkgs_latest_versions.items():
            if stop_update.is_set():
                return False, []
            if pkg not in pkg_cpe_map:
                continue

            for release_codename, latest_versions in latest_version_info.items():
                for version_start, latest_version in latest_versions:
                    try:
                        # insert CPE truncated like it's done in end_of_life_date module
                        cpe = pkg_cpe_map[pkg]
                        cpe = ":".join(cpe.split(":")[:5]) + ":"
                        vulndb_cursor.execute(
                            insert_latest_version_info_query,
                            (cpe, pkg, release_codename, version_start, latest_version),
                        )
                    # unique constrained failed, b/c sometimes two packages rightfully match
                    # to same CPE and cause duplicate insert, since version is also the same
                    except sql_integrity_error:
                        pass

        vulndb_conn.commit()

    except Exception as e:
        LOGGER.error(f"Ran into an error when trying to retrieve Debian vuln data")
        raise e
    finally:
        vulndb_cursor.close()
        vulndb_conn.close()
        productdb_cursor.close()
        productdb_conn.close()

    return True, []
