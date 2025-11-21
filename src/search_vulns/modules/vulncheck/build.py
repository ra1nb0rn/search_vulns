import asyncio
import logging
import os
import shutil

import aiohttp
from aiolimiter import AsyncLimiter
from cpe_search.cpe_search import add_cpes_to_db

from search_vulns.modules.utils import SQLITE_TIMEOUT, get_database_connection

REQUIRES_BUILT_MODULES = ["cpe_search.search_vulns_cpe_search", "nvd.search_vulns_nvd"]
LOGGER = logging.getLogger()
VULNCHECK_UPDATE_SUCCESS = None


async def vulncheck_worker(cveids, headers):
    """Pull cve<->cpe data for the given cveids asyncronously and return results"""

    global VULNCHECK_UPDATE_SUCCESS

    affects_statements = []
    retry_limit = 3
    retry_interval = 10
    async with aiohttp.ClientSession() as session:
        for cveid in cveids:
            if VULNCHECK_UPDATE_SUCCESS is not None and not VULNCHECK_UPDATE_SUCCESS:
                return []

            # get extra data from vulncheck API
            vulncheck_data = None
            for _ in range(retry_limit + 1):
                try:
                    vulncheck_url = "https://api.vulncheck.com/v3/index/nist-nvd2"
                    params = {"cve": cveid}
                    vulncheck_response = await session.get(
                        url=vulncheck_url, headers=headers, params=params
                    )
                    if vulncheck_response.status == 200 and vulncheck_response.text is not None:
                        vulncheck_data = await vulncheck_response.json()
                        if vulncheck_data is not None:
                            break
                except Exception as e:
                    if VULNCHECK_UPDATE_SUCCESS is None:
                        LOGGER.warning(
                            "Got an exception when downloading data from vulncheck API: %s"
                            % str(e)
                        )
                await asyncio.sleep(retry_interval)

            if vulncheck_data is None:
                if VULNCHECK_UPDATE_SUCCESS is None:
                    LOGGER.warning("Could not get vulncheck data for: %s" % str(cveid))
                VULNCHECK_UPDATE_SUCCESS = False
                return []

            # extract CPE configurations data from vulncheck's extra data
            if vulncheck_data.get("data", []):
                for vc_configs_entry in vulncheck_data["data"][0].get("vcConfigurations", []):
                    for vc_configs_node in vc_configs_entry.get("nodes", []):
                        for cpe_entry in vc_configs_node.get("cpeMatch", []):
                            if not cpe_entry["vulnerable"]:
                                continue
                            cpe = cpe_entry["criteria"]
                            cpe_version_start, cpe_version_end = "", ""
                            is_cpe_version_start_incl, is_cpe_version_end_incl = False, False
                            if "versionStartIncluding" in cpe_entry:
                                cpe_version_start = cpe_entry["versionStartIncluding"]
                                is_cpe_version_start_incl = True
                            elif "versionStartExcluding" in cpe_entry:
                                cpe_version_start = cpe_entry["versionStartExcluding"]
                                is_cpe_version_start_incl = False

                            if "versionEndIncluding" in cpe_entry:
                                cpe_version_end = cpe_entry["versionEndIncluding"]
                                is_cpe_version_end_incl = True
                            elif "versionEndExcluding" in cpe_entry:
                                cpe_version_end = cpe_entry["versionEndExcluding"]
                                is_cpe_version_end_incl = False

                            affects_statements.append(
                                (
                                    cveid,
                                    cpe,
                                    cpe_version_start,
                                    is_cpe_version_start_incl,
                                    cpe_version_end,
                                    is_cpe_version_end_incl,
                                )
                            )

    if VULNCHECK_UPDATE_SUCCESS is not None and not VULNCHECK_UPDATE_SUCCESS:
        return []

    return affects_statements


async def full_update_async(productdb_config, vulndb_config, module_config, stop_update):
    # Pull extra CVE <-> CPE data from vulncheck (if configured)
    global VULNCHECK_UPDATE_SUCCESS

    vulncheck_api_key = os.getenv("VULNCHECK_API_KEY")
    if not vulncheck_api_key:
        vulncheck_api_key = module_config.get("VULNCHECK_API_KEY", "")

    if vulncheck_api_key:
        LOGGER.info("[+] Adding CVE (NVD) <-> CPE information from VulnCheck")
        db_conn = get_database_connection(vulndb_config, sqlite_timeout=SQLITE_TIMEOUT)
        db_cursor = db_conn.cursor()

        # retrieve CVEs without vulnerable CPE
        db_cursor.execute(
            "SELECT cve_id from nvd where cve_id not in (SELECT DISTINCT cve_id FROM nvd_cpe);"
        )
        cves_no_cpe = [result[0] for result in db_cursor.fetchall()]

        # retrieve CVEs with only one general CPE affected
        db_cursor.execute(
            'SELECT DISTINCT cve_id FROM nvd_cpe WHERE cpe LIKE "cpe:2.3:%:%:%:*:*:*:*:*:*:*:*" AND cpe_version_start = "" AND cpe_version_end = "" AND cve_id IN (SELECT cve_id FROM nvd_cpe GROUP BY cve_id HAVING COUNT(*) = 1);'
        )
        cves_one_general_cpe = [result[0] for result in db_cursor.fetchall()]

        vulncheck_cves = cves_no_cpe + cves_one_general_cpe
        offset, batchsize = 0, 200
        headers = {"Authorization": "Bearer %s" % vulncheck_api_key}
        tasks = []

        # vulncheck API does not require a rate limit, see https://vulncheck.com/blog/nvd-plus-plus
        while offset < len(vulncheck_cves):
            cveids = vulncheck_cves[offset : min(offset + batchsize, len(vulncheck_cves))]
            task = asyncio.create_task(vulncheck_worker(cveids=cveids, headers=headers))
            tasks.append(task)
            offset += batchsize

        while True:
            if stop_update.is_set():
                VULNCHECK_UPDATE_SUCCESS = False

            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.ALL_COMPLETED, timeout=2
            )
            if len(pending) < 1:
                break

        if VULNCHECK_UPDATE_SUCCESS is not None and not VULNCHECK_UPDATE_SUCCESS:
            return f"Retrieving data from VulnCheck failed."

        # create vulncheck NVD++ table and insert data
        if vulndb_config["TYPE"] == "sqlite":
            import sqlite3

            sql_integrity_error = sqlite3.IntegrityError
            db_cursor.execute("DROP TABLE IF EXISTS vulncheck_nvd_cpe;")
            db_cursor.execute(
                "CREATE TABLE vulncheck_nvd_cpe (cve_id VARCHAR(25), cpe VARCHAR(255), cpe_version_start VARCHAR(100), is_cpe_version_start_including BOOL, cpe_version_end VARCHAR(100), is_cpe_version_end_including BOOL, PRIMARY KEY(cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including));"
            )
        elif vulndb_config["TYPE"] == "mariadb":
            import mariadb

            sql_integrity_error = mariadb.IntegrityError
            db_cursor.execute(
                "CREATE OR REPLACE TABLE vulncheck_nvd_cpe (cve_id VARCHAR(25) CHARACTER SET ascii, cpe VARCHAR(255) CHARACTER SET utf8, cpe_version_start VARCHAR(100)  CHARACTER SET utf8, is_cpe_version_start_including BOOL, cpe_version_end VARCHAR(100)  CHARACTER SET utf8, is_cpe_version_end_including BOOL, PRIMARY KEY(cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including), INDEX(cpe) USING BTREE);"
            )
        db_conn.commit()
        db_cursor.close()

        # insert all NVD++ affects statements into DB
        db_cursor = db_conn.cursor()
        insert_nvd_cpe_query = "INSERT INTO vulncheck_nvd_cpe VALUES(?, ?, ?, ?, ?, ?);"
        for task in done:
            if stop_update.is_set():
                return f"Received global stop update signal."

            affects_statements = task.result()
            for stmt in affects_statements:
                if not stmt:
                    continue
                try:
                    db_cursor.execute(insert_nvd_cpe_query, stmt)
                except sql_integrity_error:
                    pass
        db_conn.commit()
        db_cursor.close()
        db_conn.close()


def full_update(productdb_config, vulndb_config, module_config, stop_update):
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
