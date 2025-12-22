import logging
import os
import re
import sys

import requests
import ujson
from cpe_search.cpe_search import search_cpes
from univers.versions import DebianVersion

from search_vulns.modules.linux_distro_backpatches.utils import (
    get_hardcoded_pkg_cpe_matches,
    save_deb_pkg_cpe_map_to_file,
    split_deb_pkg_name,
    split_pkg_name_with_version,
    strip_epoch_from_version,
    summarize_distro_backpatch,
)
from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    compute_cosine_similarity,
    get_cpe_product_prefix,
    get_database_connection,
    get_versionless_cpes_of_nvd_cves,
    split_cpe,
)

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search", "nvd.search_vulns_nvd"]
LOGGER = logging.getLogger()

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"
}
CVE_DEBIAN_API_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_RELEASES_URL = "https://debian.pages.debian.net/distro-info-data/debian.csv"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DEBIAN_NOT_FOUND_NAME = {}
DEBIAN_RELEASES = {}
SIM_SCORE_THRES_NVD_CPE_RETRIEVAL = 0.35
VERSION_IN_NAME_RE = re.compile(r"([a-zA-Z\-_])+(\d[\d\.]*)$")
CLEAN_DEB_FROM_VERSION_RE = re.compile(r"[\+\~]deb(ian)?\d+(u\d+)?")


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

    pkg_cpe_matches_hardcoded = get_hardcoded_pkg_cpe_matches()
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
        cves_debian = ujson.loads(resp.text)

        vuln_data = {}
        pkgs_latest_versions = {}
        pkg_cpe_map = {}
        cpe_pkgs_map = {}
        all_pkgs = set()

        # go over every package
        for initial_pkg, vulns in cves_debian.items():
            if stop_update.is_set():
                return False, []

            # sometimes, package has version in its name, e.g. apache2, libssh2 or log4j1.2
            # but also, there are valid packages like aria2, atari800 or as31
            pkg, version_start = split_pkg_name_with_version(initial_pkg)

            if pkg not in vuln_data:
                vuln_data[pkg] = {}
            cpe = None
            if pkg in pkg_cpe_matches_hardcoded:
                cpe = pkg_cpe_matches_hardcoded[pkg]
            elif pkg in pkg_cpe_map:
                cpe = pkg_cpe_map[pkg]

            # go over every package's vulns
            all_affected_nvd_cpes = []
            for cve_id, vuln_details in vulns.items():
                # retrieve fixed versions
                backpatch_infos = []
                if cve_id not in vuln_data[pkg]:
                    vuln_data[pkg][cve_id] = []

                for release_codename, status in vuln_details["releases"].items():
                    if release_codename not in DEBIAN_RELEASES:
                        continue
                    release_number = DEBIAN_RELEASES[release_codename]
                    status_text = status.get("status", "")
                    if status_text in ("resolved",):
                        fixed_version = status["fixed_version"]
                        latest_version = ""

                        # remove unneeded endings and such like '+deb11u14'
                        fixed_version = CLEAN_DEB_FROM_VERSION_RE.sub("", fixed_version)
                        # strip epoch for simplicity
                        fixed_version = strip_epoch_from_version(fixed_version)
                    else:
                        fixed_version = str(sys.maxsize)
                    backpatch_infos.append((release_number, version_start, fixed_version))

                    # store info about latest version
                    if release_codename in status["repositories"]:
                        latest_version = status["repositories"][release_codename]
                        if latest_version:
                            latest_version = CLEAN_DEB_FROM_VERSION_RE.sub("", latest_version)
                            if pkg not in pkgs_latest_versions:
                                pkgs_latest_versions[pkg] = {}
                            if version_start not in pkgs_latest_versions[pkg]:
                                pkgs_latest_versions[pkg][version_start] = []
                            pkgs_latest_versions[pkg][version_start].append(
                                (release_number, latest_version)
                            )

                    # store all encountered general product cpes
                    affected_nvd_cpes = get_versionless_cpes_of_nvd_cves(
                        [cve_id], vulndb_cursor
                    )
                    all_affected_nvd_cpes += affected_nvd_cpes

                    # try to match pkg to CPE via this vuln
                    if cpe is None and len(affected_nvd_cpes) == 1:
                        if any(
                            term in affected_nvd_cpes[0].lower()
                            for term in split_deb_pkg_name(pkg.lower())
                        ):
                            cpe = affected_nvd_cpes[0]

                backpatch_infos = summarize_distro_backpatch(backpatch_infos)
                vuln_data[pkg][cve_id].extend(backpatch_infos)

            # try to retrieve a CPE for the product name by comparing it with the NVD's affected CPEs
            if not cpe:
                most_similar = None
                for affected_cpe in all_affected_nvd_cpes:
                    sim1 = compute_cosine_similarity(affected_cpe[10:], pkg, r"[a-zA-Z0-9]+")
                    sim2 = compute_cosine_similarity(
                        affected_cpe[10:], initial_pkg, r"[a-zA-Z0-9]+"
                    )
                    sim = sim1 if sim1 > sim2 else sim2
                    if not most_similar or sim > most_similar[1]:
                        most_similar = (affected_cpe, sim)

                if most_similar and most_similar[1] > SIM_SCORE_THRES_NVD_CPE_RETRIEVAL:
                    cpe = most_similar[0]

            # try to use cpe_search to find CPE (may yield quite some false positives,
            # but that doesn't matter for now, since no vulnerability retrieval is planned)
            if not cpe:
                cpe_search_results = search_cpes(pkg, productdb_cursor, count=1)
                cpe_search_cpes = cpe_search_results.get("cpes", [])
                if not cpe_search_cpes:
                    cpe_search_cpes = cpe_search_results.get("pot_cpes", [])
                if cpe_search_cpes:
                    cpe_parts = cpe_search_cpes[0][0].split(":")
                    cpe = ":".join(cpe_parts[:5] + ["*"] * 8)

            if cpe:
                pkg_cpe_map[pkg] = cpe
                if cpe not in cpe_pkgs_map:
                    cpe_pkgs_map[cpe] = set()
                cpe_pkgs_map[cpe].add(pkg)
            all_pkgs.add(pkg)

        # try to use cpe_search to find CPE (may yield quite some false positives,
        # but that doesn't matter for now, since no vulnerability retrieval is planned)
        for pkg in all_pkgs - set(pkg_cpe_map):
            if stop_update.is_set():
                return False, []

            if vuln_data.get(pkg):
                cpe_search_results = search_cpes(pkg, productdb_cursor, count=1)
                cpe_search_cpes = cpe_search_results.get("cpes", [])
                if not cpe_search_cpes:
                    cpe_search_cpes = cpe_search_results.get("pot_cpes", [])
                if cpe_search_cpes:
                    cpe_parts = cpe_search_cpes[0][0].split(":")
                    cpe = ":".join(cpe_parts[:5] + ["*"] * 8)
                    pkg_cpe_map[pkg] = cpe
                    if cpe not in cpe_pkgs_map:
                        cpe_pkgs_map[cpe] = set()
                    cpe_pkgs_map[cpe].add(pkg)

        # create fixed version table in vulndb using CPE indirection to keep DB smaller
        if vulndb_config["TYPE"] == "sqlite":
            vulndb_cursor.execute("DROP TABLE IF EXISTS debian_backpatches;")
            create_backpatches_table = "CREATE TABLE debian_backpatches (cve_id VARCHAR(25), debian_release_version VARCHAR(6), cpe_prefix_id INTEGER, version_start VARCHAR(100), version_fixed VARCHAR(100), PRIMARY KEY(cve_id, debian_release_version, cpe_prefix_id, version_start, version_fixed));"
            vulndb_cursor.execute("DROP TABLE IF EXISTS debian_pkg_cpes;")
            create_debian_pkg_cpes_table = "CREATE TABLE debian_pkg_cpes (cpe_prefix_id INTEGER, cpe_prefix VARCHAR(150), PRIMARY KEY(cpe_prefix_id));"
            import sqlite3

            sql_integrity_error = sqlite3.IntegrityError
        elif vulndb_config["TYPE"] == "mariadb":
            create_backpatches_table = "CREATE OR REPLACE TABLE debian_backpatches (cve_id VARCHAR(25) CHARACTER SET ascii, debian_release_version VARCHAR(6) CHARACTER SET ascii, cpe_prefix_id INTEGER, version_start VARCHAR(100) CHARACTER SET utf8, version_fixed VARCHAR(100) CHARACTER SET utf8, PRIMARY KEY(cve_id, debian_release_version, cpe_prefix_id, version_start, version_fixed));"
            create_debian_pkg_cpes_table = "CREATE OR REPLACE TABLE debian_pkg_cpes (cpe_prefix_id INTEGER, cpe_prefix VARCHAR(150) CHARACTER SET ascii, PRIMARY KEY(cpe_prefix_id));"
            import mariadb

            sql_integrity_error = mariadb.IntegrityError

        vulndb_cursor.execute(create_backpatches_table)
        vulndb_cursor.execute(create_debian_pkg_cpes_table)

        cpe_id_map, cpe_id_count = {}, 0
        insert_patch_info_query = "INSERT INTO debian_backpatches VALUES (?, ?, ?, ?, ?);"
        insert_pkg_cpe_query = "INSERT INTO debian_pkg_cpes VALUES (?, ?);"
        inserted_backpatch_data = {}

        for pkg in vuln_data:
            if stop_update.is_set():
                return False, []
            if pkg not in pkg_cpe_map:
                continue

            cpe = pkg_cpe_map[pkg]
            if cpe not in cpe_id_map:
                cpe_id = cpe_id_count
                cpe_id_map[cpe] = cpe_id
                vulndb_cursor.execute(
                    insert_pkg_cpe_query, (cpe_id, get_cpe_product_prefix(cpe))
                )
                cpe_id_count += 1
            else:
                cpe_id = cpe_id_map[cpe]

            if cpe not in inserted_backpatch_data:
                inserted_backpatch_data[cpe] = {}

            for cve_id, backpatch_data in vuln_data[pkg].items():
                for debian_release_version, version_start, version_fixed in backpatch_data:
                    # use earliest fixed version in case of contradicting information
                    earliest_version_fixed = version_fixed
                    if version_start in inserted_backpatch_data[cpe].get(cve_id, {}).get(
                        debian_release_version, {}
                    ):
                        continue
                    for other_pkg in cpe_pkgs_map[cpe]:
                        if other_pkg == pkg:
                            continue
                        if other_pkg not in vuln_data:
                            continue
                        if cve_id not in vuln_data[other_pkg]:
                            continue

                        for (
                            other_release,
                            other_version_start,
                            other_version_fixed,
                        ) in vuln_data[other_pkg][cve_id]:
                            if earliest_version_fixed == "-1":
                                break
                            if other_release != debian_release_version:
                                continue
                            if other_version_start != version_start:
                                continue
                            if not other_version_fixed:
                                continue
                            if not earliest_version_fixed:
                                earliest_version_fixed = other_version_fixed
                                continue
                            if other_version_fixed == "-1":
                                earliest_version_fixed = other_version_fixed
                                break
                            try:
                                if DebianVersion(other_version_fixed) < DebianVersion(
                                    earliest_version_fixed
                                ):
                                    earliest_version_fixed = other_version_fixed
                            except ValueError:
                                # sometimes, non-version strings are provided in Ubuntu Security Data
                                pass

                    if cve_id not in inserted_backpatch_data[cpe]:
                        inserted_backpatch_data[cpe][cve_id] = {}
                    if debian_release_version not in inserted_backpatch_data[cpe][cve_id]:
                        inserted_backpatch_data[cpe][cve_id][debian_release_version] = {}
                    if (
                        version_start
                        not in inserted_backpatch_data[cpe][cve_id][debian_release_version]
                    ):
                        inserted_backpatch_data[cpe][cve_id][debian_release_version][
                            version_start
                        ] = earliest_version_fixed

                    try:
                        # special case for firefox, thunderbird, etc. "esr"
                        if "esr" in earliest_version_fixed and (
                            "esr" in pkg_cpe_map[pkg] or pkg == "thunderbird"
                        ):
                            earliest_version_fixed = earliest_version_fixed.replace("esr", "")

                        # correct erroneous version_start
                        if version_start.replace(".", "") in split_cpe(cpe)[4]:
                            version_start = ""

                        vulndb_cursor.execute(
                            insert_patch_info_query,
                            (
                                cve_id,
                                debian_release_version,
                                cpe_id,
                                version_start,
                                earliest_version_fixed,
                            ),
                        )
                    # unique constrained failed, b/c sometimes two packages rightfully match
                    # to same CPE and cause duplicate insert, since version is also the same
                    except sql_integrity_error:
                        pass

        # create latest pkg versions table
        if vulndb_config["TYPE"] == "sqlite":
            vulndb_cursor.execute("DROP TABLE IF EXISTS debian_latest_pkg_versions;")
            create_latest_releases_table = "CREATE TABLE debian_latest_pkg_versions (cpe_prefix_id INTEGER, pkg VARCHAR(100), debian_release_version VARCHAR(6), version_start VARCHAR(25), latest_version VARCHAR(100), PRIMARY KEY(cpe_prefix_id, pkg, debian_release_version, version_start, latest_version));"
        elif vulndb_config["TYPE"] == "mariadb":
            create_latest_releases_table = "CREATE OR REPLACE TABLE debian_latest_pkg_versions (cpe_prefix_id INTEGER, pkg VARCHAR(100) CHARACTER SET ascii, debian_release_version VARCHAR(6) CHARACTER SET ascii, version_start VARCHAR(25) CHARACTER SET utf8, latest_version VARCHAR(100) CHARACTER SET utf8, PRIMARY KEY(cpe_prefix_id, pkg, debian_release_version, version_start, latest_version));"
        vulndb_cursor.execute(create_latest_releases_table)

        insert_latest_version_info_query = (
            "INSERT INTO debian_latest_pkg_versions VALUES (?, ?, ?, ?, ?);"
        )
        for pkg, pkg_data in pkgs_latest_versions.items():
            if stop_update.is_set():
                return False, []
            if pkg not in pkg_cpe_map:
                continue

            cpe = pkg_cpe_map[pkg]
            if cpe not in cpe_id_map:
                cpe_id = cpe_id_count
                cpe_id_map[cpe] = cpe_id
                vulndb_cursor.execute(
                    insert_pkg_cpe_query, (cpe_id, get_cpe_product_prefix(cpe))
                )
                cpe_id_count += 1
            else:
                cpe_id = cpe_id_map[cpe]

            for version_start, latest_versions in pkg_data.items():
                # correct erroneous version_start
                if version_start.replace(".", "") in split_cpe(cpe)[4]:
                    version_start = ""

                for debian_release, latest_version in latest_versions:
                    try:
                        vulndb_cursor.execute(
                            insert_latest_version_info_query,
                            (cpe_id, pkg, debian_release, version_start, latest_version),
                        )
                    # unique constrained failed, b/c sometimes two packages rightfully match
                    # to same CPE and cause duplicate insert, since version is also the same
                    except sql_integrity_error:
                        pass

        vulndb_conn.commit()

        # save pkg_cpe_map for other linux distro modules
        save_deb_pkg_cpe_map_to_file(pkg_cpe_map)

    except Exception as e:
        LOGGER.error(f"Ran into an error when trying to retrieve Debian vuln data")
        raise e
    finally:
        vulndb_cursor.close()
        vulndb_conn.close()
        productdb_cursor.close()
        productdb_conn.close()

    return True, []
