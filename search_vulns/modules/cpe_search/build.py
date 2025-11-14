import asyncio
import os
import shutil
import subprocess
import threading
import time

import requests

from modules.cpe_search.cpe_search.cpe_search import update as update_cpe_search

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
INSTALL_SCRIPT = os.path.join(SCRIPT_DIR, "install.sh")
CPE_DEPRECATIONS_ARTIFACT_URL = (
    "https://github.com/ra1nb0rn/search_vulns/releases/latest/download/deprecated-cpes.json"
)


def install(silent=False):
    if not silent:
        subprocess.run([INSTALL_SCRIPT])
    else:
        with open(os.devnull, "w") as f:
            subprocess.run([INSTALL_SCRIPT], stdout=f, stderr=f)


def setup():
    # avoid circular import
    global DEPRECATED_CPES_FILE, DEPRECATED_CPES_FILE_BUILD
    from modules.cpe_search.search_vulns_cpe_search import DEPRECATED_CPES_FILE

    DEPRECATED_CPES_FILE_BUILD = DEPRECATED_CPES_FILE + ".build"
    if not os.path.isfile(
        os.path.join(os.path.join(SCRIPT_DIR, "cpe_search"), "cpe_search.py")
    ):
        install(silent=True)

    if os.path.isfile(DEPRECATED_CPES_FILE_BUILD):
        os.remove(DEPRECATED_CPES_FILE_BUILD)


def update(productdb_config, vulndb_config, module_config, stop_update):
    setup()

    response = requests.get(CPE_DEPRECATIONS_ARTIFACT_URL, stream=True)
    response.raise_for_status()  # Raise an error for bad status codes

    with open(DEPRECATED_CPES_FILE_BUILD, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

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
