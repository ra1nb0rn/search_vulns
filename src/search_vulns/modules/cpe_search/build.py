import asyncio
import os
import threading
import time

from cpe_search.cpe_search import update as update_cpe_search

from search_vulns.core import get_version
from search_vulns.modules.utils import download_file

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CPE_DEPRECATIONS_ARTIFACT_URL = f"https://github.com/ra1nb0rn/search_vulns/releases/download/v{get_version()}/deprecated-cpes.json"


def setup():
    # avoid circular import
    global DEPRECATED_CPES_FILE, DEPRECATED_CPES_FILE_BUILD
    from search_vulns.modules.cpe_search.search_vulns_cpe_search import (
        DEPRECATED_CPES_FILE,
    )

    DEPRECATED_CPES_FILE_BUILD = DEPRECATED_CPES_FILE + ".build"
    if os.path.isfile(DEPRECATED_CPES_FILE_BUILD):
        os.remove(DEPRECATED_CPES_FILE_BUILD)


def update(productdb_config, vulndb_config, module_config, stop_update):
    setup()

    download_file(
        CPE_DEPRECATIONS_ARTIFACT_URL, DEPRECATED_CPES_FILE_BUILD, show_progressbar=True
    )

    os.replace(DEPRECATED_CPES_FILE_BUILD, DEPRECATED_CPES_FILE)

    return True, [DEPRECATED_CPES_FILE]


def check_stop_and_signal(stop_self, stop_update, global_stop_signal):
    while not stop_self:
        if global_stop_signal.is_set():
            stop_update.append("stop")
            return
        time.sleep(0.25)


async def handle_cpes_update(cpe_search_config, stop_update):
    stop_checker = []
    stop_module_update = []

    check_stop_and_signal_thread = threading.Thread(
        target=check_stop_and_signal, args=(stop_checker, stop_module_update, stop_update)
    )
    check_stop_and_signal_thread.start()

    try:
        success = await update_cpe_search(
            config=cpe_search_config, create_db=False, stop_update=stop_module_update
        )
    except:
        success = False
    stop_checker.append("stop")
    check_stop_and_signal_thread.join()

    return success


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # set up cpe_search update data
    setup()
    cpe_search_config = {"DATABASE": {}}
    cpe_search_config["DEPRECATED_CPES_FILE"] = DEPRECATED_CPES_FILE_BUILD
    nvd_api_key = os.getenv("NVD_API_KEY")
    if not nvd_api_key:
        nvd_api_key = module_config["NVD_API_KEY"]
    cpe_search_config["NVD_API_KEY"] = nvd_api_key
    for key, val in productdb_config.items():
        cpe_search_config["DATABASE"][key] = val

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        success = loop.run_until_complete(handle_cpes_update(cpe_search_config, stop_update))
    except:
        success = False
    if success:
        os.replace(DEPRECATED_CPES_FILE_BUILD, DEPRECATED_CPES_FILE)
        return True, [DEPRECATED_CPES_FILE]
    else:
        if os.path.isfile(DEPRECATED_CPES_FILE_BUILD):
            os.remove(DEPRECATED_CPES_FILE_BUILD)
        return False, []
