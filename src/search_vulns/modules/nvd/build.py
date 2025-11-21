import asyncio
import logging
import os
import shutil
import subprocess

import aiohttp
import requests
import ujson
from aiolimiter import AsyncLimiter
from cpe_search.cpe_search import add_cpes_to_db

from search_vulns.modules.utils import (
    SQLITE_TIMEOUT,
    get_database_connection,
    split_cpe,
)

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search"]

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CREATE_DB_BINARY = os.path.join(SCRIPT_DIR, "create_db")
INSTALL_SCRIPT = os.path.join(SCRIPT_DIR, "install.sh")
NVD_DATAFEED_DIR = os.path.join(SCRIPT_DIR, "nvd_data_feeds")
CREATE_SQL_STATEMENTS_FILE = os.path.join(SCRIPT_DIR, "create_sql_statements.json")
API_RESULTS_PER_PAGE = 2000
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_UPDATE_SUCCESS = None
LOGGER = logging.getLogger()


def ensure_is_installed():
    if not os.path.isfile(CREATE_DB_BINARY):
        install(silent=True)


def install(silent=False):
    if not silent:
        subprocess.run([INSTALL_SCRIPT])
    else:
        with open(os.devnull, "w") as f:
            subprocess.run([INSTALL_SCRIPT], stdout=f, stderr=f)


def cleanup():
    if os.path.exists(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)


def add_vuln_cpes_to_product_db(productdb_config, vulndb_config):
    """Add CPEs only present in NVD vulnerability data to cpe_search DB"""

    # get distinct official NVD CPEs
    db_conn_cpes = get_database_connection(productdb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor_cpes = db_conn_cpes.cursor()
    db_cursor_cpes.execute("SELECT DISTINCT cpe FROM cpe_entries")
    nvd_official_cpes = db_cursor_cpes.fetchall()
    nvd_official_cpes = set([cpe[0] for cpe in nvd_official_cpes])
    db_cursor_cpes.close()
    db_conn_cpes.close()

    # get distinct CPEs from vulns
    db_conn_vulndb = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
    db_cursor_vulndb = db_conn_vulndb.cursor()
    db_cursor_vulndb.execute("SELECT DISTINCT cpe FROM nvd_cpe")
    vuln_cpes = db_cursor_vulndb.fetchall()
    vuln_cpes = set([cpe[0] for cpe in vuln_cpes])
    db_cursor_vulndb.close()
    db_conn_vulndb.close()

    not_contained_cpes = vuln_cpes - nvd_official_cpes

    # influence similarity scores to be slightly lower to decrease likelihood of some
    # outlier CPE overshadowing genuine CPEs used with the majority of vulns and contained
    # in the official dictionary
    not_contained_cpe_infos = []
    for cpe in not_contained_cpes:
        cpe_name = (
            " ".join(split_cpe(cpe)[3:]).replace(" *", " ").replace(" -", " ").replace("_", " ")
        )
        cpe_name += " (s34rch-vuln5-s34rch-vuln5)"
        not_contained_cpe_infos.append((cpe, cpe_name))

    add_cpes_to_db(
        not_contained_cpe_infos, {"DATABASE": productdb_config}, check_duplicates=False
    )


async def api_request(headers, params, requestno):
    """Perform request to API for one task"""

    global NVD_UPDATE_SUCCESS

    if NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS:
        return None

    retry_limit = 3
    retry_interval = 6
    for _ in range(retry_limit + 1):
        async with aiohttp.ClientSession() as session:
            try:
                cve_api_data_response = await session.get(
                    url=CVE_API_URL, headers=headers, params=params
                )
                if (
                    cve_api_data_response.status == 200
                    and cve_api_data_response.text is not None
                ):
                    return await cve_api_data_response.json()
                else:
                    LOGGER.warning(
                        f"Received status code {cve_api_data_response.status} on request {requestno} Retrying..."
                    )
                await asyncio.sleep(retry_interval)
            except Exception as e:
                LOGGER.error(
                    "Got the following exception when downloading vuln data via API: %s"
                    % str(e)
                )
                NVD_UPDATE_SUCCESS = False
                return None


def write_data_to_json_file(api_data, requestno):
    """Perform creation of cve json files"""

    with open(os.path.join(NVD_DATAFEED_DIR, f"nvdcve-2.0-{requestno}.json"), "a") as outfile:
        ujson.dump(api_data, outfile)


async def worker(headers, params, requestno, rate_limit):
    """Handle requests within its offset space asychronously, then performs processing steps to produce final database."""

    global NVD_UPDATE_SUCCESS

    async with rate_limit:
        api_data_response = await api_request(
            headers=headers, params=params, requestno=requestno
        )

    if NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS:
        return None

    write_data_to_json_file(api_data=api_data_response, requestno=requestno)


async def full_update_async(productdb_config, vulndb_config, module_config, stop_update):
    global NVD_UPDATE_SUCCESS

    nvd_api_key = os.getenv("NVD_API_KEY")
    if not nvd_api_key:
        nvd_api_key = module_config["NVD_API_KEY"]

    if nvd_api_key:
        LOGGER.info("API Key found - Requests will be sent at a rate of 25 per 30s.")
        rate_limit = AsyncLimiter(25.0, 30.0)
    else:
        LOGGER.info("No API Key found - Requests will be sent at a rate of 5 per 30s.")
        rate_limit = AsyncLimiter(5.0, 30.0)

    # download vulnerability data via NVD's API
    if os.path.exists(NVD_DATAFEED_DIR):
        shutil.rmtree(NVD_DATAFEED_DIR)
    os.makedirs(NVD_DATAFEED_DIR)
    offset = 0

    # initial request to set paramters
    params = {"resultsPerPage": API_RESULTS_PER_PAGE, "startIndex": offset}
    if nvd_api_key:
        headers = {"apiKey": nvd_api_key}
    else:
        headers = {}

    numTotalResults = None
    for _ in range(3):
        try:
            cve_api_initial_response = requests.get(
                url=CVE_API_URL, headers=headers, params=params
            )
            numTotalResults = cve_api_initial_response.json().get("totalResults")
        except:
            continue
        break

    if numTotalResults is None or cve_api_initial_response.status_code != requests.codes.ok:
        cleanup()
        return "Could not make initial request for parameter setting to https://services.nvd.nist.gov/rest/json/cves/2.0"

    # make necessary amount of requests
    requestno = 0
    tasks = []
    while offset <= numTotalResults:
        requestno += 1
        params = {"resultsPerPage": API_RESULTS_PER_PAGE, "startIndex": offset}
        task = asyncio.create_task(
            worker(headers=headers, params=params, requestno=requestno, rate_limit=rate_limit)
        )
        tasks.append(task)
        offset += API_RESULTS_PER_PAGE

    while True:
        if stop_update.is_set():
            NVD_UPDATE_SUCCESS = False

        _, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED, timeout=2)
        if len(pending) < 1 or (NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS):
            break

    if (not len(os.listdir(NVD_DATAFEED_DIR))) or (
        NVD_UPDATE_SUCCESS is not None and not NVD_UPDATE_SUCCESS
    ):
        NVD_UPDATE_SUCCESS = False
        cleanup()
        return (
            "Could not download vuln data from https://services.nvd.nist.gov/rest/json/cves/2.0"
        )

    # build local NVD copy with downloaded data feeds
    LOGGER.info("Building vulnerability database")
    create_db_env = {
        "DATABASE_TYPE": vulndb_config.get("TYPE", ""),
        "DATABASE_NAME": vulndb_config.get("NAME", ""),
        "DATABASE_HOST": vulndb_config.get("HOST", ""),
        "DATABASE_PORT": str(vulndb_config.get("PORT", "")),
        "DATABASE_USER": vulndb_config.get("USER", ""),
        "DATABASE_PASSWORD": vulndb_config.get("PASSWORD", ""),
        "OVERWRITE_DB": "FALSE",
    }
    create_db_call = [CREATE_DB_BINARY, NVD_DATAFEED_DIR, CREATE_SQL_STATEMENTS_FILE]
    with open(os.devnull, "w") as outfile:
        return_code = subprocess.call(
            create_db_call, stdout=outfile, stderr=subprocess.STDOUT, env=create_db_env
        )

    if return_code != 0:
        NVD_UPDATE_SUCCESS = False
        cleanup()
        return f"Building NVD database failed with status code {return_code}."

    shutil.rmtree(NVD_DATAFEED_DIR)

    if stop_update.is_set():
        return

    # add CPEs only contained in vulns to product DB
    add_vuln_cpes_to_product_db(productdb_config, vulndb_config)


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    ensure_is_installed()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    error = loop.run_until_complete(
        full_update_async(productdb_config, vulndb_config, module_config, stop_update)
    )
    if error:
        LOGGER.error(error)
        return False, []
    else:
        return True, []
