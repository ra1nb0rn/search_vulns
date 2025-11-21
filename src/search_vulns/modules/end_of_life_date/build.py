import logging
import os
import re
import shutil
import subprocess

import ujson
from cpe_search.cpe_search import search_cpes

from search_vulns.modules.utils import SQLITE_TIMEOUT, get_database_connection

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search"]

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
EOLD_GITHUB_REPO = "https://github.com/endoflife-date/endoflife.date"
EOLD_GITHUB_DIR = os.path.join(SCRIPT_DIR, "endoflife.date")
EOLD_HARDCODED_MATCHES_FILE = os.path.join(SCRIPT_DIR, "eold_hardcoded_matches.json")
LOGGER = logging.getLogger()


def cleanup():
    if os.path.isdir(EOLD_GITHUB_DIR):
        shutil.rmtree(EOLD_GITHUB_DIR)


def parse_eold_product_releases(release_info_raw):
    # parse manually instead of using a third-party YAML parser
    releases = []

    for release_raw in re.split(r"- *releaseCycle", release_info_raw):
        release_raw = release_raw.strip()
        release_raw = release_raw.strip()
        if not release_raw:
            continue

        release = {}
        added_back_cycle_key = False
        for line in release_raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            elif "#" in line:
                line = line[: line.find("#")]
            if not added_back_cycle_key:
                line = "-   releaseCycle" + line
                added_back_cycle_key = True

            if line.startswith("-"):
                line = line[1:]
                line = line.strip()

            key, val = line.split(":", maxsplit=1)
            key, val = key.strip(), val.strip()
            if len(key) > 1 and key.startswith('"') and key.endswith('"'):
                key = key[1:-1].strip()
            if len(val) > 1 and val.startswith('"') and val.endswith('"'):
                val = val[1:-1].strip()
            if len(key) > 1 and key.startswith("'") and key.endswith("'"):
                key = key[1:-1].strip()
            if len(val) > 1 and val.startswith("'") and val.endswith("'"):
                val = val[1:-1].strip()
            release[key] = val
        if release:
            releases.append(release)

    return releases


def parse_eold_data(productdb_config, stop_update):
    # load hardcoded EOLD product --> CPE matches
    hardcoded_matches = {}
    with open(EOLD_HARDCODED_MATCHES_FILE) as f:
        hardcoded_matches = ujson.loads(f.read())

    eold_products_dir = os.path.join(EOLD_GITHUB_DIR, "products")
    product_title_re = re.compile(r"---\s*[tT]itle: ([^\n]+)")
    product_eold_id_re = re.compile(r"permalink: /([^\n]+)")
    product_releases_re = re.compile(r"^[Rr]eleases:(.*?)---", re.MULTILINE | re.DOTALL)

    # create endoflife.date data
    productdb_conn = get_database_connection(productdb_config, sqlite_timeout=SQLITE_TIMEOUT)
    productdb_cursor = productdb_conn.cursor()
    eold_data = {}
    for filename in os.listdir(eold_products_dir):
        if stop_update.is_set():
            return None

        with open(os.path.join(eold_products_dir, filename)) as f:
            product_content = f.read()

        # work around (temporary) EoLD data bug, see https://github.com/endoflife-date/endoflife.date/commit/2c23c3f7e58a19cbefed814d3125403b61a7b035#diff-788cea2420ea468fc502aabb8477fb4063f25db4091d95004e0ca31bc6b52227R22
        product_content = product_content.replace("releases:\nreleases:", "releases:")

        eold_product_title = product_title_re.search(product_content)
        if not eold_product_title:
            continue
        eold_product_title = eold_product_title.group(1)

        eold_product_id = product_eold_id_re.search(product_content)
        if not eold_product_id:
            eold_product_id = os.path.basename(filename)
        else:
            eold_product_id = eold_product_id.group(1)

        product_releases = product_releases_re.search(product_content)
        if not product_releases:
            continue

        product_releases = parse_eold_product_releases(product_releases.group(1))
        cpes = []
        if eold_product_id in hardcoded_matches or eold_product_id.lower() in hardcoded_matches:
            cpes = hardcoded_matches[eold_product_id]
            cpes = [":".join(cpe.split(":")[:5]) + ":" for cpe in cpes]
        else:
            cpe_results = search_cpes(eold_product_title, productdb_cursor)
            cpe = ""
            if cpe_results and cpe_results["cpes"]:
                cpe = cpe_results["cpes"][0][0]
            elif cpe_results["pot_cpes"]:
                cpe = cpe_results["pot_cpes"][0][0]
            if cpe:
                cpe = ":".join(cpe.split(":")[:5]) + ":"
                cpes = [cpe]

        eold_entry = {
            "eold-id": eold_product_id,
            "eold-title": eold_product_title,
            "releases": product_releases,
        }
        for cpe in cpes:
            eold_data[cpe] = eold_entry

    productdb_cursor.close()
    productdb_conn.close()
    return eold_data


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # download endoflife.date repo
    cleanup()
    return_code = subprocess.call(
        "git clone --depth 1 %s '%s'" % (EOLD_GITHUB_REPO, EOLD_GITHUB_DIR),
        shell=True,
        stderr=subprocess.DEVNULL,
    )
    if return_code != 0 or stop_update.is_set():
        LOGGER.error("Could not download latest resources of endoflife.date")
        cleanup()
        return False, []

    # parse endoflife.date data
    eold_data = parse_eold_data(productdb_config, stop_update)
    if stop_update.is_set():
        LOGGER.info("Aborting because of global stop signal")
        cleanup()
        return False, []

    # create table in DB and put endoflife.data data into DB
    vulndb_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    vulndb_cursor = vulndb_conn.cursor()
    if vulndb_config["TYPE"] == "sqlite":
        create_eol_date_table = "DROP TABLE IF EXISTS eol_date_data; CREATE TABLE eol_date_data (cpe_prefix VARCHAR(255), release_id INTEGER, eold_id VARCHAR(255), eold_title VARCHAR(255), version_start VARCHAR(100), version_latest VARCHAR(100), eol_info VARCHAR(25), PRIMARY KEY (cpe_prefix, release_id));"
    elif vulndb_config["TYPE"] == "mariadb":
        create_eol_date_table = "CREATE OR REPLACE TABLE eol_date_data (cpe_prefix VARCHAR(255), release_id INTEGER, eold_id VARCHAR(255), eold_title VARCHAR(255), version_start VARCHAR(100), version_latest VARCHAR(100), eol_info VARCHAR(25), PRIMARY KEY (cpe_prefix, release_id));"

    # necessary because SQLite can't handle more than one query a time
    for query in create_eol_date_table.split(";"):
        if query:
            vulndb_cursor.execute(query + ";")

    for cpe, eold_entry in eold_data.items():
        # iterate over releases in reversed order, s.t. oldest release always has unique ID 0
        for i, release in enumerate(reversed(eold_entry["releases"])):
            version_start = release["releaseCycle"]
            version_latest = release.get("latest", "")  # e.g. slackware
            eol_info = release.get("eol", "false")
            db_data = (
                cpe,
                i,
                eold_entry["eold-id"],
                eold_entry["eold-title"],
                version_start,
                version_latest,
                eol_info,
            )
            vulndb_cursor.execute(
                "INSERT INTO eol_date_data VALUES (?, ?, ?, ?, ?, ?, ?)", db_data
            )

    vulndb_cursor.close()
    vulndb_conn.commit()
    vulndb_conn.close()

    cleanup()
    return True, []
