import logging
import os
import re
import shutil
import sys

import requests
import ujson
from cpe_search.cpe_search import search_cpes
from univers.versions import DebianVersion

from search_vulns.modules.linux_distro_backpatches.utils import (
    del_deb_pkg_cpe_map_file,
    get_clean_version,
    load_deb_pkg_cpe_map_from_file,
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

REQUIRES_BUILT_MODULES = [
    "cpe_search.search_vulns_cpe_search",
    "nvd.search_vulns_nvd",
    "linux_distro_backpatches.debian.search_vulns_debian",
    "linux_distro_backpatches.search_vulns_download_resources",
]
LOGGER = logging.getLogger()
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
UBUNTU_RELEASES_API_URL = "https://ubuntu.com/security/releases.json"
UBUNTU_DATAFEED_DIR = os.path.join(SCRIPT_DIR, "ubuntu_data_feeds")
UBUNTU_RELEASES = {}
DISTRO_CODENAMES = []
SIM_SCORE_THRES_NVD_CPE_RETRIEVAL = 0.35
BASIC_VERSION_RE = re.compile(r"(\d+([\._:\+~\-][\da-zA-Z]+)+)")


########################################################################################
### Created with help of original connector to Ubuntu by https://github.com/MRuppDev ###
########################################################################################


def create_ubuntu_release_codename_mapping(vulndb_config):
    """Download ubuntu release data via Ubuntu Security API and store mapping data"""

    global UBUNTU_RELEASES

    # initial request to set paramters
    headers = {
        "accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:112.0) Gecko/20100101 Firefox/112.0",
    }

    # try multiple times over, since the API has connection issues
    success = False
    for _ in range(10):
        try:
            # time out after 1s
            ubuntu_api_initial_response = requests.get(
                UBUNTU_RELEASES_API_URL, headers=headers, timeout=1
            )
            ubuntu_api_initial_response.raise_for_status()  # Optional: treat HTTP errors as failures
            success = True
            break
        except requests.RequestException as e:
            pass

    if not success:
        LOGGER.error(
            "Could not retrieve Ubuntu releases from https://ubuntu.com/security/releases.json"
        )
        return False, []
    releases_raw = ubuntu_api_initial_response.json()["releases"]

    db_conn = get_database_connection(vulndb_config)
    db_cursor = db_conn.cursor()

    # create codename-version table in vulndb
    if vulndb_config["TYPE"] == "sqlite":
        db_cursor.execute("DROP TABLE IF EXISTS ubuntu_codename_version_mapping;")
        create_mapping_table = "CREATE TABLE ubuntu_codename_version_mapping (version VARCHAR(23), codename VARCHAR(25), support_expires DATETIME, esm_lts_expires DATETIME, PRIMARY KEY(codename));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_mapping_table = "CREATE OR REPLACE TABLE ubuntu_codename_version_mapping (version VARCHAR(15) CHARACTER SET ascii, codename VARCHAR(25) CHARACTER SET ascii, support_expires DATETIME, esm_lts_expires DATETIME, PRIMARY KEY(codename));"
    db_cursor.execute(create_mapping_table)

    query = "INSERT INTO ubuntu_codename_version_mapping (version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?)"

    # extract codename and version from json
    for release in releases_raw:
        codename = release["codename"]

        if codename == "upstream":
            # use big number as version for upstream
            if not release["version"]:
                version = 999
            if not release["support_expires"]:
                support_expires = "9999-12-31"
            if not release["esm_expires"]:
                esm_expires = "9999-12-31"
        else:
            version = release["version"]
            support_expires = str(release["support_expires"]).split("T")[0]
            esm_expires = str(release["esm_expires"]).split("T")[0]

        # add information to database and dict
        db_cursor.execute(query, (version, codename, support_expires, esm_expires))
        UBUNTU_RELEASES[codename] = version

    db_conn.commit()
    db_conn.close()
    return True


def get_version_end_ubuntu(status, note):
    """Return a version_end matching the format from the database and reflecting the status"""

    if "," in note:
        note = note.split(",")[1].strip()
    version_end = note

    # if distro is not affected or package does-not-exists(dne). use version_end = -1 to describe it
    if status in ("not-affected", "DNE"):
        if note and BASIC_VERSION_RE.match(note):
            version_end = "-" + note  # detect version_start and signal as negative
        else:
            version_end = "-1"
    elif status == "pending":
        # update is ready, but not enrolled
        if note:
            version_end = get_clean_version(note, DISTRO_CODENAMES)
            version_end = note
        # distro is vulnerable, but no update ready. use MAX_INT to describe it
        else:
            version_end = str(sys.maxsize)
    # distro is vulnerable, but no update ready. use MAX_INT to describe it
    elif status in ["needed", "active", "deferred"]:
        version_end = str(sys.maxsize)  # use maxsize-1 if distinction is useful
    # distro could be vulnerable, but needs further investigation. use MAX_INT to describe it
    elif status == "needs-triage":
        version_end = str(sys.maxsize)
    # status ignored can have many reasons, try to find a suiting version for the most popular cases
    elif status == "ignored":
        if not note or any(
            note.startswith(string)
            for string in ["only", "code", "superseded", "was not-affected"]
        ):
            version_end = "-1"
        else:
            version_end = str(sys.maxsize)

    # check if multiple versions are given, e.g. in CVE-2014-3547
    if " " in version_end:
        versions = BASIC_VERSION_RE.findall(version_end)
        if versions:
            earliest_version = versions[0][0]
            for cur_version in versions[1:]:
                if DebianVersion(cur_version[0]) < DebianVersion(earliest_version):
                    earliest_version = cur_version[0]
            version_end = earliest_version
        else:
            version_end = str(sys.maxsize)

    return version_end


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    global UBUNTU_RELEASES, DISTRO_CODENAMES

    try:
        # retrieve Ubuntu codename to version number mapping
        success = create_ubuntu_release_codename_mapping(vulndb_config)
        if not success:
            return False, []

        DISTRO_CODENAMES = list(UBUNTU_RELEASES.keys())
        vulndb_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        vulndb_cursor = vulndb_conn.cursor()
        vulndb_cursor.execute("SELECT codename FROM debian_codename_version_mapping")
        debian_codenames = [codename[0] for codename in vulndb_cursor.fetchall()]
        DISTRO_CODENAMES.extend(debian_codenames)
        vulndb_cursor.close()
        vulndb_conn.close()

        # process vulnerability data and try finding matching CPEs
        vulndb_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        vulndb_cursor = vulndb_conn.cursor()
        productdb_conn = get_database_connection(productdb_config)
        productdb_cursor = productdb_conn.cursor()

        pkg_cpe_map = (
            load_deb_pkg_cpe_map_from_file()
        )  # also contains hardcoded matches already
        all_pkgs = set()
        cpe_pkgs_map = {}
        vuln_data = {}
        working_dir = os.path.join(UBUNTU_DATAFEED_DIR, "ubuntu")
        for dir_year in os.listdir(working_dir):
            working_year_dir = os.path.join(working_dir, dir_year)
            for filename in os.listdir(working_year_dir):
                with open(os.path.join(working_year_dir, filename), "r") as f:
                    cve = ujson.load(f)
                    cve_id = cve["Candidate"]

                    for initial_pkg in cve["Patches"]:
                        if stop_update.is_set():
                            return False, []

                        # sometimes, package has version in its name, e.g. apache2, libssh2 or log4j1.2
                        pkg, version_start = split_pkg_name_with_version(initial_pkg, 2)
                        if pkg == "linux" or pkg.startswith("linux-"):
                            continue  # skip because too much unneeded data
                        if pkg not in vuln_data:
                            vuln_data[pkg] = {}

                        # retrieve fixed versions and summarize backpatch data
                        if cve_id not in vuln_data[pkg]:
                            vuln_data[pkg][cve_id] = []

                        backpatch_info = {}
                        for release_codename, status in cve["Patches"][initial_pkg].items():
                            version_end = get_version_end_ubuntu(
                                status["Status"],
                                status["Note"],
                            )
                            # if note contains a separate version_start info
                            vuln_version_start = version_start
                            if version_end != "-1" and version_end.startswith("-"):
                                # just treat as normal fixed statement for now
                                version_end = version_end[1:]
                            # strip epoch for simplicity
                            version_end = strip_epoch_from_version(version_end)
                            backpatch_info[release_codename] = (vuln_version_start, version_end)
                        for codename in list(backpatch_info):
                            if "/" in codename:
                                codename_parts = codename.split("/")
                                codename_part_in = None
                                for part in codename_parts:
                                    if part in UBUNTU_RELEASES:
                                        codename_part_in = part
                                        break

                                if codename_part_in:
                                    # prefer best available backpatch info for variants like ESM etc.
                                    if (
                                        codename_part_in not in backpatch_info
                                        or not backpatch_info[codename_part_in][1]
                                    ):
                                        backpatch_info[codename_part_in] = backpatch_info[
                                            codename
                                        ]
                                    elif backpatch_info[codename][1] == "-1":
                                        backpatch_info[codename_part_in] = backpatch_info[
                                            codename
                                        ]
                                    elif backpatch_info[codename_part_in][
                                        1
                                    ] != "-1" and DebianVersion(
                                        backpatch_info[codename][1]
                                    ) < DebianVersion(
                                        backpatch_info[codename_part_in][1]
                                    ):
                                        backpatch_info[codename_part_in] = backpatch_info[
                                            codename
                                        ]
                                del backpatch_info[codename]
                            elif codename not in UBUNTU_RELEASES:
                                del backpatch_info[codename]

                        backpatch_info_version_numbers = []
                        for codename, (
                            version_start_vuln,
                            version_end,
                        ) in backpatch_info.items():
                            backpatch_info_version_numbers.append(
                                (UBUNTU_RELEASES[codename], version_start_vuln, version_end)
                            )
                        backpatches_summarized = summarize_distro_backpatch(
                            backpatch_info_version_numbers
                        )
                        vuln_data[pkg][cve_id].extend(backpatches_summarized)

                        # try to retrieve a CPE for the product name by comparing it with the NVD's affected CPEs
                        cpe = None
                        if pkg in pkg_cpe_map:
                            cpe = pkg_cpe_map[pkg]

                        all_affected_nvd_cpes = []
                        if not cpe:
                            # store all encountered general product cpes
                            affected_nvd_cpes = get_versionless_cpes_of_nvd_cves(
                                [cve_id], vulndb_cursor
                            )

                        # try to match pkg to CPE via this vuln
                        if not cpe and len(affected_nvd_cpes) == 1:
                            if any(
                                term in affected_nvd_cpes[0].lower()
                                for term in split_deb_pkg_name(pkg.lower())
                            ):
                                cpe = affected_nvd_cpes[0]

                        if not cpe and vuln_data[pkg]:
                            most_similar = None
                            for affected_cpe in all_affected_nvd_cpes:
                                sim1 = compute_cosine_similarity(
                                    affected_cpe[10:], pkg, r"[a-zA-Z0-9]+"
                                )
                                sim2 = compute_cosine_similarity(
                                    affected_cpe[10:], initial_pkg, r"[a-zA-Z0-9]+"
                                )
                                sim = sim1 if sim1 > sim2 else sim2
                                if not most_similar or sim > most_similar[1]:
                                    most_similar = (affected_cpe, sim)

                            if (
                                most_similar
                                and most_similar[1] > SIM_SCORE_THRES_NVD_CPE_RETRIEVAL
                            ):
                                cpe = most_similar[0]

                        if cpe:
                            if pkg not in pkg_cpe_map and vuln_data[pkg]:
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
            vulndb_cursor.execute("DROP TABLE IF EXISTS ubuntu_backpatches;")
            create_backpatches_table = "CREATE TABLE ubuntu_backpatches (cve_id VARCHAR(25), ubuntu_release_version VARCHAR(6), cpe_prefix_id INTEGER, version_start VARCHAR(100), version_fixed VARCHAR(100), PRIMARY KEY(cve_id, ubuntu_release_version, cpe_prefix_id, version_start, version_fixed));"
            vulndb_cursor.execute("DROP TABLE IF EXISTS ubuntu_pkg_cpes;")
            create_ubuntu_pkg_cpes_table = "CREATE TABLE ubuntu_pkg_cpes (cpe_prefix_id INTEGER, cpe_prefix VARCHAR(150), PRIMARY KEY(cpe_prefix_id));"
            import sqlite3

            sql_integrity_error = sqlite3.IntegrityError
        elif vulndb_config["TYPE"] == "mariadb":
            create_backpatches_table = "CREATE OR REPLACE TABLE ubuntu_backpatches (cve_id VARCHAR(25) CHARACTER SET ascii, ubuntu_release_version VARCHAR(6) CHARACTER SET ascii, cpe_prefix_id INTEGER, version_start VARCHAR(100) CHARACTER SET utf8, version_fixed VARCHAR(100) CHARACTER SET utf8, PRIMARY KEY(cve_id, ubuntu_release_version, cpe_prefix_id, version_start, version_fixed));"
            create_ubuntu_pkg_cpes_table = "CREATE OR REPLACE TABLE ubuntu_pkg_cpes (cpe_prefix_id INTEGER, cpe_prefix VARCHAR(150) CHARACTER SET ascii, PRIMARY KEY(cpe_prefix_id));"
            import mariadb

            sql_integrity_error = mariadb.IntegrityError

        vulndb_cursor.execute(create_backpatches_table)
        vulndb_cursor.execute(create_ubuntu_pkg_cpes_table)

        cpe_id_map, cpe_id_count = {}, 0
        insert_patch_info_query = "INSERT INTO ubuntu_backpatches VALUES (?, ?, ?, ?, ?);"
        insert_pkg_cpe_query = "INSERT INTO ubuntu_pkg_cpes VALUES (?, ?);"
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

            for cve_id, fixed_details in vuln_data[pkg].items():
                for ubuntu_release_version, version_start, version_fixed in fixed_details:
                    # use earliest fixed version in case of contradicting information
                    earliest_version_fixed = version_fixed
                    if version_start in inserted_backpatch_data[cpe].get(cve_id, {}).get(
                        ubuntu_release_version, {}
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
                            if other_release != ubuntu_release_version:
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
                    if ubuntu_release_version not in inserted_backpatch_data[cpe][cve_id]:
                        inserted_backpatch_data[cpe][cve_id][ubuntu_release_version] = {}
                    if (
                        version_start
                        not in inserted_backpatch_data[cpe][cve_id][ubuntu_release_version]
                    ):
                        inserted_backpatch_data[cpe][cve_id][ubuntu_release_version][
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
                                ubuntu_release_version,
                                cpe_id,
                                version_start,
                                earliest_version_fixed,
                            ),
                        )
                    # unique constrained failed, b/c sometimes two packages rightfully match
                    # to same CPE and cause duplicate insert, since version is also the same
                    except sql_integrity_error:
                        pass

        vulndb_conn.commit()
    except Exception as e:
        LOGGER.error(f"Ran into an error when trying to retrieve Ubuntu vuln data")
        raise e
    finally:
        vulndb_cursor.close()
        vulndb_conn.close()
        productdb_cursor.close()
        productdb_conn.close()

    # remove processed resources
    del_deb_pkg_cpe_map_file()
    if os.path.isdir(UBUNTU_DATAFEED_DIR):
        shutil.rmtree(UBUNTU_DATAFEED_DIR)

    return True, []
