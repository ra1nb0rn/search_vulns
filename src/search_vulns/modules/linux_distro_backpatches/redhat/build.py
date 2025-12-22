import logging
import os
import re
import shutil
import sys

import ujson
from cpe_search.cpe_search import search_cpes
from univers.versions import RpmVersion

from search_vulns.cpe_version import CPEVersion
from search_vulns.modules.linux_distro_backpatches.utils import (
    get_hardcoded_pkg_cpe_matches,
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
    "linux_distro_backpatches.search_vulns_download_resources",
]

LOGGER = logging.getLogger()
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
REDHAT_DATAFEED_DIR = os.path.join(SCRIPT_DIR, "vuln-list-redhat")
REDHAT_RELEASES = {}
SIM_SCORE_THRES_NVD_CPE_RETRIEVAL = 0.35
NEVRA_RE = re.compile(r"^(.+?)[-:]((?:\d+:)?[A-Za-z0-9_.~+]+)(?:-([A-Za-z0-9_.]+))?$")
RHEL_IN_PKG_RE = re.compile(r"(-?rhel([\d\.]+))-?")
PKG_REVERSE_STRUCTURE_FIX_RE = re.compile(r"([\w\-_]+)[:]([\d\.]+)\/(.*)")
PKG_NAME_SPLIT_RE = re.compile(r"[^a-zA-Z\d]")
NO_MATCH_CPE_KEYWORDS = ["http", "httpd", "server", "application", "service", "services"]


########################################################################################
### Created with help of original connector to Red Hat by https://github.com/MRuppDev ###
########################################################################################


def get_package_details(redhat_package_data):
    if "package_name" in redhat_package_data:  # affected_release entry
        package = redhat_package_data["package_name"]
    elif "package" in redhat_package_data:  # package_state entry
        package = redhat_package_data["package"]

    cpe = redhat_package_data["cpe"]
    cpe_split = cpe.split(":")

    # change e.g. 'container-tools:4.0/podman' to 'podman4.0'
    rev_struct_match = PKG_REVERSE_STRUCTURE_FIX_RE.match(package)
    if rev_struct_match:
        if (
            "redhat" not in rev_struct_match.group(1).lower()
            and "rhel" not in rev_struct_match.group(1).lower()
        ):
            package = rev_struct_match.group(3)
            concat_version = "".join([c for c in rev_struct_match.group(2) if c.isdigit()])
            package = package.replace(concat_version, "")
            package += rev_struct_match.group(2)
        else:
            package = rev_struct_match.group(3)
            release = rev_struct_match.group(2)

    if "/" in package:
        package = package.split("/", maxsplit=1)[1]

    nevra_keyword = None
    for el in ("el", "EL", "rhel", "RHEL", "ent", "ENT"):
        # decider for RPM NEVRA string
        if (
            "." + el in package
            and not package.endswith(el)
            and package[package.find("." + el) + 3].isdigit()
        ):
            nevra_keyword = el
            break
    if nevra_keyword:
        match = NEVRA_RE.match(package)
        package = match.group(1)
        version = match.group(2)
        release = match.group(3)
        if "el" in release:
            before, release = release.split("." + nevra_keyword, 1)
            if before:
                version += "-" + before
        else:
            version += "-" + release
            release = ""
    else:
        version, release = "", ""
        if ":" in package:
            package, version = package.rsplit(":", maxsplit=1)

        if not package:
            package = " ".join(cpe_split[2:4])

        if not version:
            title_version = ""
            if not redhat_package_data["product_name"].startswith("Red Hat"):
                title_words = redhat_package_data["product_name"].split(" ")
                title_contains_package, title_version = False, ""
                for word in title_words:
                    if word in package:
                        title_contains_package = True
                    if all(c == "." or c.isdigit() for c in word):
                        title_version = word
                    if title_contains_package and title_version:
                        break
            cpe_version = ""
            if (
                cpe_split
                and (cpe_split[2] in package or cpe_split[3] in package)
                and len(cpe_split) > 4
            ):
                cpe_version = cpe.split(":")[4]
            if CPEVersion(cpe_version) > CPEVersion(title_version):
                version = cpe_version
            else:
                version = title_version

    rhel_in_package_match = RHEL_IN_PKG_RE.findall(package)
    if rhel_in_package_match:
        package = package.replace(rhel_in_package_match[0][0], "")
        if not release:
            release = rhel_in_package_match[0][1]

    if package and len(package) < 3 and len(cpe_split) > 3:  # assume error and use CPE fallback
        package = package + "-" + cpe_split[3]

    if not release:
        if "enterprise_linux" in cpe or cpe_split[3].endswith("rhel") or "el" in cpe_split[-1]:
            release = cpe_split[-1]
        elif redhat_package_data["product_name"].startswith("Red Hat Enterprise Linux"):
            release = (
                redhat_package_data["product_name"][len("Red Hat Enterprise Linux") :]
                .strip()
                .split(" ")[0]
            )
        else:
            release = ""
    if release:
        release = release.replace("_", ".")
        if "." in release:
            release = release[: release.find(".") + 2]
        release = "".join([c for c in release if c.isdigit() or c == "."])

    if release:  # make 9 and 9.0 identical
        release = str(float(release))

    # for simplicity, strip epoch
    if version:
        version = strip_epoch_from_version(version)

    return package, version, release


def get_version_init_dot_count(fixed_version):
    dot_count = 0
    for char in fixed_version:
        if char == ".":
            dot_count += 1
        elif not char.isalnum():
            break
    return dot_count


def get_unified_fixed_version(fixed_version, unified_dot_count):
    unified_fixed_version = ""
    cur_dot_count = 0
    for char in fixed_version:
        if char.isalnum() or cur_dot_count >= unified_dot_count:
            unified_fixed_version += char
        elif char == ".":
            unified_fixed_version += char
            cur_dot_count += 1
        elif char in ("-", "_", "+"):
            unified_fixed_version += "."
            cur_dot_count += 1
        else:
            unified_fixed_version += char

    return unified_fixed_version


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    try:
        # init
        vulndb_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        vulndb_cursor = vulndb_conn.cursor()
        productdb_conn = get_database_connection(productdb_config)
        productdb_cursor = productdb_conn.cursor()

        cpe_pkgs_map = {}
        pkg_cpe_map = get_hardcoded_pkg_cpe_matches()
        for pkg, cpe in pkg_cpe_map.items():
            if cpe not in cpe_pkgs_map:
                cpe_pkgs_map[cpe] = set()
            cpe_pkgs_map[cpe].add(pkg)

        vuln_data = {}
        all_pkgs = set()

        # process vuln data
        working_dir = os.path.join(REDHAT_DATAFEED_DIR, "api")
        for dir_year in os.listdir(working_dir):
            working_year_dir = os.path.join(working_dir, dir_year)
            for filename in os.listdir(working_year_dir):
                if stop_update.is_set():
                    return False, []

                with open(os.path.join(working_year_dir, filename), "r") as f:
                    cve = ujson.load(f)
                    cve_id = cve["name"]

                    fixed_releases = cve["affected_release"]
                    package_state = cve["package_state"]
                    if not fixed_releases:
                        fixed_releases = []
                    if not package_state:
                        package_state = []

                    # first, extract raw backpatch infos (different releases have different package names)
                    backpatch_infos = {}
                    all_package_details = fixed_releases + package_state
                    fixed_version_init_dot_counts = (
                        {}
                    )  # e.g. CVE-2025-13467 with "26.2.11-1" and "26.2-12"
                    for pkg_release in all_package_details:
                        # ignore empty package names if more than one entries exist
                        if (
                            not pkg_release.get("package")
                            and not pkg_release.get("package_name")
                            and len(all_package_details) > 1
                        ):
                            continue

                        package_details = get_package_details(pkg_release)
                        if not package_details:
                            continue
                        package, fixed_version, release = package_details

                        # skip if some other Red Hat product is affected
                        package_split = PKG_NAME_SPLIT_RE.split(package)
                        product_name = pkg_release.get("product_name", "").lower()
                        if not any(
                            word.lower() in product_name for word in package_split if word
                        ):
                            if (
                                "RHEL" not in product_name
                                and "red hat enterprise linux" not in product_name
                            ):
                                continue

                        if not fixed_version and "fix_state" in pkg_release:
                            fix_state = pkg_release["fix_state"]
                            if fix_state.lower() in [
                                "affected",
                                "fix deferred",
                                "new",
                                "will not fix",
                                "under investigation",
                            ]:
                                fixed_version = str(sys.maxsize)
                            elif fix_state.lower() == "not affected":
                                fixed_version = "-1"

                        # skip if no version was provided
                        if not fixed_version:
                            continue
                        if not release:
                            release = "999"

                        pkg, version_start = split_pkg_name_with_version(package)
                        if not version_start:
                            # check if CPE contains version start, e.g. CVE-2025-13467
                            cpe_split = pkg_release["cpe"].split(":")
                            if len(cpe_split) > 4:
                                if (
                                    fixed_version != str(sys.maxsize)
                                    and fixed_version.startswith(cpe_split[4])
                                    and cpe_split[4] != fixed_version
                                ):
                                    version_start = cpe_split[4]

                        # e.g. php53 in CVE-2013-3735
                        try:
                            if 9 < int(version_start) < 100:
                                version_start = version_start[0] + "." + version_start[1]
                        except:
                            pass

                        if pkg not in backpatch_infos:
                            backpatch_infos[pkg] = {}
                        if version_start not in backpatch_infos[pkg]:
                            backpatch_infos[pkg][version_start] = {}

                        # sometimes, two fixed versions are given, e.g. CVE-2023-44487
                        stored_fixed_version = backpatch_infos[pkg][version_start].get(release)
                        if not stored_fixed_version or RpmVersion(fixed_version) < RpmVersion(
                            stored_fixed_version
                        ):
                            backpatch_infos[pkg][version_start][release] = fixed_version

                        fixed_version_init_dot_count = get_version_init_dot_count(fixed_version)
                        if version_start:
                            if version_start not in fixed_version_init_dot_counts:
                                fixed_version_init_dot_counts[version_start] = 0
                            if (
                                fixed_version_init_dot_count
                                > fixed_version_init_dot_counts[version_start]
                            ):
                                fixed_version_init_dot_counts[version_start] = (
                                    fixed_version_init_dot_count
                                )

                    # get CPEs for current vuln
                    affected_nvd_cpes = get_versionless_cpes_of_nvd_cves(
                        [cve_id], vulndb_cursor
                    )

                    # merge and summarize backpatch infos, plus try to find CPE
                    for pkg in backpatch_infos:
                        # summarize backpatch infos and save it
                        for version_start in backpatch_infos[pkg]:
                            pkg_version_backpatch_infos = []
                            for release in backpatch_infos[pkg][version_start]:
                                # only use specific version_start backpatch if general statement
                                # about product was not provided.
                                if not version_start or release not in backpatch_infos[pkg].get(
                                    "", []
                                ):
                                    if version_start:
                                        unified_version = get_unified_fixed_version(
                                            backpatch_infos[pkg][version_start][release],
                                            fixed_version_init_dot_counts[version_start],
                                        )
                                    else:
                                        unified_version = backpatch_infos[pkg][version_start][
                                            release
                                        ]
                                    pkg_version_backpatch_infos.append(
                                        (release, version_start, unified_version)
                                    )

                            backpatches_summarized = summarize_distro_backpatch(
                                pkg_version_backpatch_infos
                            )

                            if pkg not in vuln_data:
                                vuln_data[pkg] = {}
                            if cve_id not in vuln_data[pkg]:
                                vuln_data[pkg][cve_id] = {}

                            for release, version_start, version_fixed in backpatches_summarized:
                                if cve_id not in vuln_data[pkg]:
                                    vuln_data[pkg][cve_id] = {}
                                if release not in vuln_data[pkg][cve_id]:
                                    vuln_data[pkg][cve_id][release] = {}
                                if version_start not in vuln_data[pkg][cve_id][release]:
                                    vuln_data[pkg][cve_id][release][
                                        version_start
                                    ] = version_fixed

                        # try to find CPE for pkg via current vuln
                        cpe = pkg_cpe_map.get(pkg, "")
                        if not cpe and len(affected_nvd_cpes) == 1:
                            if any(
                                term not in NO_MATCH_CPE_KEYWORDS
                                and term in affected_nvd_cpes[0].lower()
                                for term in split_deb_pkg_name(pkg.lower())
                            ):
                                cpe = affected_nvd_cpes[0]

                        # try to retrieve a CPE for the product name by comparing it with the NVD's affected CPEs
                        if not cpe and vuln_data[pkg]:
                            most_similar = None
                            for affected_cpe in affected_nvd_cpes:
                                initial_pkg = pkg.replace(".", "")
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
                                and any(
                                    term not in NO_MATCH_CPE_KEYWORDS
                                    and term in most_similar[0].lower()
                                    for term in split_deb_pkg_name(pkg.lower())
                                )
                            ):
                                cpe = most_similar[0]

                        if cpe and vuln_data[pkg]:
                            pkg_cpe_map[pkg] = cpe
                            if cpe not in cpe_pkgs_map:
                                cpe_pkgs_map[cpe] = set()
                            cpe_pkgs_map[cpe].add(pkg)
                        all_pkgs.add(pkg)

        # try to use cpe_search to find remaining CPEs (may yield quite some false positives,
        # but that doesn't matter for now, since no vulnerability retrieval is planned)
        for pkg in all_pkgs - set(pkg_cpe_map):
            if stop_update.is_set():
                return False, []

            if vuln_data[pkg]:
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
            vulndb_cursor.execute("DROP TABLE IF EXISTS redhat_backpatches;")
            create_backpatches_table = "CREATE TABLE redhat_backpatches (cve_id VARCHAR(25), redhat_release_version VARCHAR(6), cpe_prefix_id INTEGER, version_start VARCHAR(25), version_fixed VARCHAR(100), PRIMARY KEY(cve_id, redhat_release_version, cpe_prefix_id, version_start, version_fixed));"
            vulndb_cursor.execute("DROP TABLE IF EXISTS redhat_pkg_cpes;")
            create_redhat_pkg_cpes_table = "CREATE TABLE redhat_pkg_cpes (cpe_prefix_id INTEGER, cpe_prefix VARCHAR(150), PRIMARY KEY(cpe_prefix_id));"
            import sqlite3

            sql_integrity_error = sqlite3.IntegrityError
        elif vulndb_config["TYPE"] == "mariadb":
            create_backpatches_table = "CREATE OR REPLACE TABLE redhat_backpatches (cve_id VARCHAR(25) CHARACTER SET ascii, redhat_release_version VARCHAR(6) CHARACTER SET ascii, cpe_prefix_id INTEGER, version_start VARCHAR(25) CHARACTER SET utf8, version_fixed VARCHAR(100) CHARACTER SET utf8, PRIMARY KEY(cve_id, redhat_release_version, cpe_prefix_id, version_start, version_fixed));"
            create_redhat_pkg_cpes_table = "CREATE OR REPLACE TABLE redhat_pkg_cpes (cpe_prefix_id INTEGER, cpe_prefix VARCHAR(150) CHARACTER SET ascii, PRIMARY KEY(cpe_prefix_id));"
            import mariadb

            sql_integrity_error = mariadb.IntegrityError

        vulndb_cursor.execute(create_backpatches_table)
        vulndb_cursor.execute(create_redhat_pkg_cpes_table)

        cpe_id_map, cpe_id_count = {}, 0
        insert_patch_info_query = "INSERT INTO redhat_backpatches VALUES (?, ?, ?, ?, ?);"
        insert_pkg_cpe_query = "INSERT INTO redhat_pkg_cpes VALUES (?, ?);"
        inserted_backpatch_data = {}

        for i, pkg in enumerate(vuln_data):
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

            # use most precise fixed version if Red Hat contains duplicate information
            # also use earliest fixed version in case of contradicting information
            for cve_id, fixed_details in vuln_data[pkg].items():
                for release in fixed_details:
                    for version_start, version_fixed in fixed_details[release].items():
                        more_concrete_version_fixed = ""
                        earliest_version_fixed = version_fixed
                        if version_start in inserted_backpatch_data[cpe].get(cve_id, {}).get(
                            release, {}
                        ):
                            continue
                        for other_pkg in cpe_pkgs_map[cpe]:
                            if other_pkg == pkg:
                                continue
                            if other_pkg not in vuln_data:
                                continue
                            if cve_id not in vuln_data[other_pkg]:
                                continue
                            if release not in vuln_data[other_pkg][cve_id]:
                                continue
                            if version_start not in vuln_data[other_pkg][cve_id][release]:
                                continue
                            other_version_fixed = vuln_data[other_pkg][cve_id][release][
                                version_start
                            ]
                            if other_version_fixed.count(".") > version_fixed.count("."):
                                more_concrete_version_fixed = other_version_fixed
                                break
                            if RpmVersion(other_version_fixed) < RpmVersion(
                                earliest_version_fixed
                            ):
                                earliest_version_fixed = other_version_fixed

                        if more_concrete_version_fixed:
                            version_fixed = more_concrete_version_fixed
                        else:
                            version_fixed = earliest_version_fixed

                        if cve_id not in inserted_backpatch_data[cpe]:
                            inserted_backpatch_data[cpe][cve_id] = {}
                        if release not in inserted_backpatch_data[cpe][cve_id]:
                            inserted_backpatch_data[cpe][cve_id][release] = {}
                        if version_start not in inserted_backpatch_data[cpe][cve_id][release]:
                            inserted_backpatch_data[cpe][cve_id][release][
                                version_start
                            ] = version_fixed

                        try:
                            # special case for firefox, thunderbird, etc. "esr"
                            if "esr" in version_fixed and (
                                "esr" in pkg_cpe_map[pkg] or pkg == "thunderbird"
                            ):
                                version_fixed = version_fixed.replace("esr", "")

                            # correct erroneous version_start
                            if version_start.replace(".", "") in split_cpe(cpe)[4]:
                                version_start = ""

                            vulndb_cursor.execute(
                                insert_patch_info_query,
                                (
                                    cve_id,
                                    release,
                                    cpe_id,
                                    version_start,
                                    version_fixed,
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
    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)

    return True, []
