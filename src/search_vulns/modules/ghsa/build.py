import logging
import os
import re
import shutil
import subprocess

import ujson
from cpe_search.cpe_search import add_cpes_to_db, search_cpes
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import (
    CVSS2MalformedError,
    CVSS3MalformedError,
    CVSS4MalformedError,
)

from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    compute_cosine_similarity,
    download_github_folder,
    get_database_connection,
)

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search", "nvd.search_vulns_nvd"]

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
GHSA_GITHUB_REPO = "https://github.com/github/advisory-database"
GHSA_GITHUB_DIR = os.path.join(SCRIPT_DIR, "ghsa-database")
GHSA_HARDCODED_MATCHES_FILE = os.path.join(SCRIPT_DIR, "ghsa_hardcoded_matches.json")
DIFFICULT_PACKAGE_PREFIXES = [
    "github.com/go",
    "github.com/microsoft/go",
    "microsoft/microsoft",
    "python-",
]
LOGGER = logging.getLogger()


def cleanup():
    if os.path.exists(GHSA_GITHUB_DIR):
        shutil.rmtree(GHSA_GITHUB_DIR)


def parse_ghsa_data(vulndb_cursor, productdb_config):
    """Parse all GitHub-reviewed GHSA entries"""

    pname_cpe_map = {}
    ghsa_affects_map = {}
    ghsa_no_cpe_yet = []
    sim_score_thres_good_cpe = 0.35
    description_meta_info_re = re.compile(r"^([\*\:]*[A-Z ]+[\*\:]+)")

    # retrieve hardcoded matches and store them in product DB
    with open(GHSA_HARDCODED_MATCHES_FILE) as f:
        ghsa_hardcoded_matches = ujson.loads(f.read())
    all_hardcoded_cpes = list(set(ghsa_hardcoded_matches.values()))
    add_cpes_to_db(all_hardcoded_cpes, {"DATABASE": productdb_config}, check_duplicates=True)

    # only traverse reviewed advisories, since only those have information about affected software
    for dirpath, dirnames, files in os.walk(
        os.path.join(GHSA_GITHUB_DIR, "advisories/github-reviewed")
    ):
        # sort dirnames and files to have deterministic execution
        # use reverse to process vulns of recent years first
        dirnames.sort(reverse=True)
        files.sort(reverse=True)

        for file in files:
            with open(os.path.join(dirpath, file)) as af:
                advisory = ujson.load(af)

            if advisory.get("withdrawn", ""):  # skip withdrawn entries
                continue

            # extract affects statements and map them to the same structure as the nvd_cpe table
            ghsa_id = advisory["id"]
            ghsa_affects_map[ghsa_id] = []
            advisory_affected_pnames = set()
            for pkg in advisory["affected"]:
                pname = pkg["package"]["name"].lower()
                ecosystem = pkg["package"]["ecosystem"].lower()
                single_version_affected = False
                affected_ranges = []
                advisory_affected_pnames.add(pname)

                # extract affected version ranges
                introduced = ""
                for pkg_range in pkg.get("ranges", []):  # usually just one entry
                    introduced, fixed, is_version_end_incl = "", "", False
                    for event in pkg_range.get("events"):
                        if "introduced" in event and not introduced:
                            introduced = event["introduced"]
                        if "fixed" in event and not fixed:
                            fixed = event["fixed"]
                        if "last_affected" in event and not fixed:
                            fixed = event["last_affected"]
                            is_version_end_incl = True

                        # strip alpha/beta information, b/c it cannot be mapped consistently
                        # and non-contradictory, e.g., GHSA-p6gg-5hf4-4rgj and GHSA-6hh7-46r2-vf29
                        if "-alpha" in introduced or "-beta" in introduced:
                            introduced = introduced.split("-", maxsplit=1)[0]
                        if "-alpha" in fixed or "-beta" in fixed:
                            fixed = fixed.split("-", maxsplit=1)[0]
                        if fixed == introduced:
                            continue

                    if not fixed:
                        db_specific_fixed = pkg.get("database_specific", {}).get(
                            "last_known_affected_version_range", ""
                        )
                        if db_specific_fixed.startswith("<="):
                            fixed = db_specific_fixed[2:].strip()
                            is_version_end_incl = True
                        elif db_specific_fixed.startswith("<"):
                            fixed = db_specific_fixed[1:].strip()
                            is_version_end_incl = False

                    affected_ranges.append(
                        (pname, ecosystem, introduced, fixed, is_version_end_incl)
                    )
                for version in pkg.get("versions", []):  # usually just one entry or omitted
                    if (
                        not introduced or version == introduced
                    ):  # just a single version is affected
                        single_version_affected = True
                    ghsa_affects_map[ghsa_id].append((pname, ecosystem, version))
                if (
                    not single_version_affected
                ):  # only add range(s) if more than one version is affected
                    for affected_range in affected_ranges:
                        ghsa_affects_map[ghsa_id].append(affected_range)

            # get list of all CVE aliasses, retrieve all their affected CPEs
            # and try to match every product name to one of these CPEs
            all_cves = []
            for alias in advisory["aliases"]:
                if alias.startswith("CVE-"):
                    all_cves.append(alias)

            all_nvd_cpes = set()
            for cve_id in all_cves:
                vulndb_cursor.execute("SELECT cpe FROM nvd_cpe WHERE cve_id = ?", (cve_id,))
                nvd_cpes = vulndb_cursor.fetchall()
                if nvd_cpes:  # MariaDB returns None and SQLite an empty list
                    for cpe in nvd_cpes:
                        cpe_split = cpe[0].split(":")
                        cpe_version_wildcarded = (
                            ":".join(cpe_split[:5]) + ":*:*:" + ":".join(cpe_split[7:])
                        )
                        all_nvd_cpes.add(cpe_version_wildcarded)

            for pname in advisory_affected_pnames:
                if pname in pname_cpe_map:
                    continue

                if pname in ghsa_hardcoded_matches:
                    pname_cpe_map[pname] = (ghsa_hardcoded_matches[pname], 1)
                elif len(advisory_affected_pnames) == 1 and len(all_nvd_cpes) == 1:
                    pname_cpe_map[pname] = (next(iter(all_nvd_cpes)), 1)
                else:
                    # try to retrieve a CPE for the product name by comparing it with the NVD's affected CPEs
                    most_similar = None
                    for cpe in all_nvd_cpes:
                        sim = compute_cosine_similarity(cpe[10:], pname, r"[a-zA-Z0-9]+")
                        if not most_similar or sim > most_similar[1]:
                            most_similar = (cpe, sim)

                    if most_similar and most_similar[1] > sim_score_thres_good_cpe:
                        if (
                            pname not in pname_cpe_map
                            or most_similar[1] > pname_cpe_map[pname][1]
                        ):
                            pname_cpe_map[pname] = most_similar
                    else:
                        ghsa_no_cpe_yet.append((pname, ghsa_id))

            # retrieve CVSS version, vector, score and GHSA severity
            if advisory["severity"]:
                cvss_vector = advisory["severity"][0]["score"]
                if cvss_vector.endswith("/"):  # e.g. error with GHSA-g88v-2j67-9rmx
                    cvss_vector = cvss_vector[:-1]
                cvss_version = cvss_vector[cvss_vector.find(":") + 1 : cvss_vector.find("/")]
                cvss_score = "-1.0"
                try:
                    if cvss_version[0] == "2":
                        cvss_score = CVSS2(cvss_vector).scores()[0]
                    if cvss_version[0] == "3":
                        cvss_score = CVSS3(cvss_vector).scores()[0]
                    if cvss_version[0] == "4":
                        cvss_score = CVSS4(cvss_vector).scores()[0]
                except (CVSS2MalformedError, CVSS3MalformedError, CVSS4MalformedError):
                    pass  # if cvss vector is malformed, skip score calculation
            else:
                cvss_score, cvss_vector, cvss_version = "-1.0", "", ""
            severity = advisory["database_specific"].get("severity", "N/A")

            # retrieve description and dates
            # take care to keep meta information from vuln details / summary
            description, other_description = advisory.get("details", ""), ""
            if description and len(description) > 600:  # use summary instead of long text
                other_description = description
                description = advisory.get("summary", "")
            else:
                other_description = advisory.get("summary", "")
            meta_info_match = description_meta_info_re.match(other_description)
            if meta_info_match:
                if not description.startswith(meta_info_match.group(0)):
                    description = meta_info_match.group(0) + " " + description

            published = advisory["published"].replace("T", " ").replace("Z", "")
            last_modified = advisory["modified"].replace("T", " ").replace("Z", "")

            # put new GHSA entry into DB
            vulndb_cursor.execute(
                "INSERT INTO ghsa VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    ghsa_id,
                    ",".join(advisory["aliases"]),
                    description,
                    published,
                    last_modified,
                    cvss_version,
                    cvss_score,
                    cvss_vector,
                    severity,
                ),
            )

    return pname_cpe_map, ghsa_affects_map, ghsa_no_cpe_yet


def complete_pname_cpe_map(pname_cpe_map, ghsa_no_cpe_yet, productdb_config):
    """If a CPE couldn't be found by comparing a product name with the NVD's
    CPEs for the same vulnerbility, use cpe_search to attempt finding a CPE."""

    productdb_conn = get_database_connection(productdb_config, sqlite_timeout=SQLITE_TIMEOUT)
    productdb_cursor = productdb_conn.cursor()
    for pname, ghsa_id in ghsa_no_cpe_yet:
        product_cpe = pname_cpe_map.get(pname, None)
        if not product_cpe:
            # skip assigning CPEs to cerrtain packages for now, because it's too
            # difficult, e.g., GHSA-78hx-gp6g-7mj6 or https://github.com/advisories/GHSA-7mc6-x925-7qvx
            if any(pname.startswith(prefix) for prefix in DIFFICULT_PACKAGE_PREFIXES):
                pname_cpe_map[pname] = (pname, None)
                continue

            cpe_search_results = search_cpes(pname, productdb_cursor)
            cpe_search_cpes = cpe_search_results.get("cpes", [])
            if not cpe_search_cpes:
                cpe_search_cpes = cpe_search_results.get("pot_cpes", [])
            if cpe_search_cpes:
                cpe_parts = cpe_search_cpes[0][0].split(":")
                product_cpe = ":".join(cpe_parts[:5] + ["*"] * 8)
                pname_cpe_map[pname] = (product_cpe, 0)
            else:
                pname_cpe_map[pname] = (pname, None)

    productdb_cursor.close()
    productdb_conn.close()


def store_applicability_data(vulndb_cursor, ghsa_affects_map, pname_cpe_map, db_type):
    """Store all retrieved applicability data in DB and return newly created CPEs"""

    cpe_creation_github_ref_re = re.compile(
        r"^(https://)?github.com/([\w.\-]+)\/([\w.\-]+)/?[^/]*$"
    )
    cpe_creation_slash_re = re.compile(r"^([\w.\-]+)\/([\w.\-]+)/?[^/]*$")
    cpe_creation_single_word_re = re.compile(r"^\w+$")

    if db_type == "sqlite":
        import sqlite3

        sql_integrity_error = sqlite3.IntegrityError
    elif db_type == "mariadb":
        import mariadb

        sql_integrity_error = mariadb.IntegrityError

    # Add affects statements of every GHSA vulnerability to DB and create CPEs if necessary
    newly_created_cpes = set()
    for ghsa_id, affects in ghsa_affects_map.items():
        cpe_affected_version_map = {}
        cpe_number_version_ranges_map = {}

        for product in affects:
            if not product:
                continue

            pname = product[0]
            if any(pname.startswith(prefix) for prefix in DIFFICULT_PACKAGE_PREFIXES):
                continue  # again, skip difficult packages for now

            cpe_entry = pname_cpe_map.get(pname, (pname, ""))
            cpe = (
                pname  # fall back to pname if no CPE could be found (without much use for now)
            )
            if cpe_entry[1] is not None:
                cpe = cpe_entry[0]

            # create custom CPE if vendor and product name are somewhat clear
            # to achieve this, try to match the GHSA product name to a vendor:product structure
            if not cpe.startswith("cpe:2.3:"):
                cpe_vendor, cpe_product = "", ""
                cpe_creation_match = cpe_creation_github_ref_re.match(cpe)
                if cpe_creation_match:
                    cpe_vendor, cpe_product = cpe_creation_match.group(
                        2
                    ), cpe_creation_match.group(3)
                if not cpe_vendor:
                    cpe_creation_match = cpe_creation_slash_re.match(cpe)
                    if cpe_creation_match:
                        cpe_vendor, cpe_product = cpe_creation_match.group(
                            1
                        ), cpe_creation_match.group(2)
                if not cpe_vendor:
                    cpe_creation_match = cpe_creation_single_word_re.match(cpe)
                    if cpe_creation_match:
                        cpe_vendor, cpe_product = cpe_creation_match.group(
                            0
                        ), cpe_creation_match.group(0)

                if cpe_vendor:
                    cpe = "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*" % (cpe_vendor, cpe_product)
                    cpe_entry = (cpe, 0)
                    newly_created_cpes.add(cpe)
                    pname_cpe_map[pname] = cpe_entry

            # collect plain information about affects statements and how many different version ranges are listed
            product_ver_str = ujson.dumps(product[2:])
            if cpe not in cpe_affected_version_map:
                cpe_affected_version_map[cpe] = {}
            if product_ver_str not in cpe_affected_version_map[cpe]:
                cpe_affected_version_map[cpe][product_ver_str] = 0
            cpe_affected_version_map[cpe][product_ver_str] += 1

            pname = (
                product[1] + ":" + pname
            )  # prefix with ecosystem to create unique identifier
            if cpe not in cpe_number_version_ranges_map:
                cpe_number_version_ranges_map[cpe] = {}
            if pname not in cpe_number_version_ranges_map[cpe]:
                cpe_number_version_ranges_map[cpe][pname] = 0
            cpe_number_version_ranges_map[cpe][pname] += 1

        # convert plain version range information to CPE affects statements and put into vuln DB
        # also try to solve problem: different GHSA product names are matched to same CPE, where the
        # match is bad sometimes. To not pollute the vuln data too much, do not put outliers into DB,
        # when every other affects statement of the vulnerability speaks against it.
        for cpe, version_ranges in cpe_number_version_ranges_map.items():
            number_version_ranges = max(list(version_ranges.values()))
            cpe_affected_version_map[cpe] = [
                ver_range_count for ver_range_count in cpe_affected_version_map[cpe].items()
            ]
            cpe_affected_version_map[cpe] = sorted(
                cpe_affected_version_map[cpe], key=lambda ver_range: ver_range[1], reverse=True
            )
            for ver_range in cpe_affected_version_map[cpe][:number_version_ranges]:
                ver_range = ujson.loads(ver_range[0])

                # try to detect and fix defective version ranges by comparing with other affected products
                if number_version_ranges == 1 and ver_range[0] == "0" and not ver_range[1]:
                    if all(
                        len(cpe_affected_version_map[other_cpe]) == 1
                        for other_cpe in cpe_affected_version_map
                    ):
                        for other_cpe in cpe_affected_version_map:
                            if len(cpe_affected_version_map[other_cpe]) == 1:
                                ver_range = ujson.loads(
                                    cpe_affected_version_map[other_cpe][0][0]
                                )
                                break

                cpe_split = cpe.split(":")
                if cpe.startswith("cpe:2.3:"):  # skip products without CPE
                    if len(ver_range) == 1:
                        cpe = (
                            ":".join(cpe_split[:5])
                            + ":"
                            + ver_range[0]
                            + ":"
                            + ":".join(cpe_split[6:])
                        )
                        try:
                            vulndb_cursor.execute(
                                "INSERT INTO ghsa_cpe VALUES(?, ?, ?, ?, ?, ?)",
                                (ghsa_id, cpe, "", False, "", False),
                            )
                        except sql_integrity_error:
                            # probably UniqueConstraint, which can happen if a different
                            # product name is matched to the same CPE
                            pass
                    elif len(ver_range) == 3:
                        cpe_split[5] = "*"
                        cpe = ":".join(cpe_split)
                        try:
                            vulndb_cursor.execute(
                                "INSERT INTO ghsa_cpe VALUES(?, ?, ?, ?, ?, ?)",
                                (ghsa_id, cpe, ver_range[0], True, ver_range[1], ver_range[2]),
                            )
                        except sql_integrity_error:
                            # probably UniqueConstraint, which can happen if a different
                            # product name is matched to the same CPE
                            pass

    return newly_created_cpes


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    """Add GitHub Security Advisory DB data to vuln DB"""

    # download GitHub reviewed advisories from GHSA repo
    cleanup()
    LOGGER.info("Downloading GHSA database")
    success = download_github_folder(
        GHSA_GITHUB_REPO, "advisories/github-reviewed/", GHSA_GITHUB_DIR
    )
    if not success:
        LOGGER.error("Could not download latest resources of the GHSA")
        return False, []

    # set up DB connection and tables
    vulndb_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    vulndb_cursor = vulndb_conn.cursor()

    if vulndb_config["TYPE"] == "sqlite":
        create_ghsa_table_stmt = "DROP TABLE IF EXISTS ghsa; CREATE TABLE ghsa (ghsa_id VARCHAR(20), aliases VARCHAR(100), description TEXT, published DATETIME, last_modified DATETIME, cvss_version CHAR(3), base_score CHAR(3), vector VARCHAR(200), severity VARCHAR(15), PRIMARY KEY(ghsa_id));"
        create_ghsa_cpe_table_stmt = "DROP TABLE IF EXISTS ghsa_cpe; CREATE TABLE ghsa_cpe(ghsa_id VARCHAR(20), cpe VARCHAR(255), cpe_version_start VARCHAR(100), is_cpe_version_start_including BOOL, cpe_version_end VARCHAR(100), is_cpe_version_end_including BOOL, PRIMARY KEY(ghsa_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_ghsa_table_stmt = "CREATE OR REPLACE TABLE ghsa (ghsa_id VARCHAR(20) CHARACTER SET ascii, aliases VARCHAR(100)  CHARACTER SET ascii, description TEXT, published DATETIME, last_modified DATETIME, cvss_version CHAR(3) CHARACTER SET ascii, base_score CHAR(4) CHARACTER SET ascii, vector VARCHAR(200) CHARACTER SET ascii, severity VARCHAR(15) CHARACTER SET ascii, PRIMARY KEY(ghsa_id));"
        create_ghsa_cpe_table_stmt = "CREATE OR REPLACE TABLE ghsa_cpe (ghsa_id VARCHAR(20) CHARACTER SET ascii, cpe VARCHAR(255) CHARACTER SET utf8, cpe_version_start VARCHAR(100)  CHARACTER SET utf8, is_cpe_version_start_including BOOL, cpe_version_end VARCHAR(100)  CHARACTER SET utf8, is_cpe_version_end_including BOOL, PRIMARY KEY(ghsa_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including), INDEX(cpe) USING BTREE);"

    for stmt in create_ghsa_table_stmt.split(";"):
        if stmt:
            vulndb_cursor.execute(stmt + ";")
    for stmt in create_ghsa_cpe_table_stmt.split(";"):
        if stmt:
            vulndb_cursor.execute(stmt + ";")

    if stop_update.is_set():
        cleanup()
        return False, []

    # parse raw GHSA data feeds
    LOGGER.info("Parsing GHSA vulnerabilities")
    pname_cpe_map, ghsa_affects_map, ghsa_no_cpe_yet = parse_ghsa_data(
        vulndb_cursor, productdb_config
    )
    vulndb_conn.commit()
    if stop_update.is_set():
        cleanup()
        return False, []

    # use cpe_search to try and find missing pname <-> CPE matches and add them to the map
    LOGGER.info("Trying to find CPEs for unmatched GHSA product names")
    complete_pname_cpe_map(pname_cpe_map, ghsa_no_cpe_yet, productdb_config)
    if stop_update.is_set():
        cleanup()
        return False, []

    # store parsed GHSA vulnerability affects statements in DB
    LOGGER.info("Storing GHSA applicability data and creating CPEs if needed")
    newly_created_cpes = store_applicability_data(
        vulndb_cursor, ghsa_affects_map, pname_cpe_map, vulndb_config["TYPE"]
    )
    vulndb_conn.commit()
    vulndb_cursor.close()
    vulndb_conn.close()
    if stop_update.is_set():
        cleanup()
        return False, []

    # add newly_created_cpes to CPE dict
    LOGGER.info("Storing created CPEs in product DB if any exist")
    add_cpes_to_db(newly_created_cpes, {"DATABASE": productdb_config}, check_duplicates=False)
    if stop_update.is_set():
        cleanup()
        return False, []

    cleanup()

    return True, []
