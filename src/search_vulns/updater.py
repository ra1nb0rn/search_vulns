import logging
import os
import shlex
import subprocess
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from multiprocessing import Manager

import requests

from .core import MODULE_DIRECTORY, PROJECT_DIR, get_modules, get_version
from .cpe_version import CPEVersion
from .modules.utils import download_file, get_database_connection, is_safe_db_name

UPDATE_MODULES = None
UPDATE_LOGS_DIR = os.path.join(PROJECT_DIR, "update_logs")
SV_RELEASE_URL = "https://github.com/ra1nb0rn/search_vulns/releases/"
LATEST_RELEASE_URL = SV_RELEASE_URL + "/latest"
PRODUCT_DB_ARTIFACT_URL = SV_RELEASE_URL + f"download/v{get_version()}/productdb.db3"
VULNDB_ARTIFACT_URL = SV_RELEASE_URL + f"download/v{get_version()}/vulndb.db3"
MARIADB_CONVERT_SCRIPT = os.path.join(
    os.path.join(PROJECT_DIR, "resources"), "sqlite_to_mariadb.sh"
)
MARIADB_CONVERT_CNF_FILE = os.path.join(
    os.path.join(PROJECT_DIR, "resources"), "sqlite_mariadb_convert.cnf"
)
LOG_LEVEL = logging.DEBUG
MAX_PROCESS_COUNT = os.cpu_count()


def _setup_new_shared_databases(config):
    """Set up the shared databases and init temporary renaming of databases"""

    orig_productdb_name = config["PRODUCT_DATABASE"]["NAME"]
    orig_vulndb_name = config["VULN_DATABASE"]["NAME"]
    if not is_safe_db_name(orig_productdb_name, config["PRODUCT_DATABASE"]["TYPE"].lower()):
        print("Potentially malicious product database name detected, canceling update.")
        return False
    if not is_safe_db_name(orig_vulndb_name, config["VULN_DATABASE"]["TYPE"].lower()):
        print("Potentially malicious vuln database name detected, canceling update.")
        return False

    if config["PRODUCT_DATABASE"]["TYPE"].lower() == "sqlite":
        temp_productdb_name = orig_productdb_name + ".update"
        if os.path.isfile(temp_productdb_name):
            os.remove(temp_productdb_name)
    else:
        temp_productdb_name = orig_productdb_name + "_update"
    config["PRODUCT_DATABASE"]["NAME"] = temp_productdb_name

    if config["VULN_DATABASE"]["TYPE"].lower() == "sqlite":
        temp_vulndb_name = orig_vulndb_name + ".update"
        if os.path.isfile(temp_vulndb_name):
            os.remove(temp_vulndb_name)
    else:
        temp_vulndb_name = orig_vulndb_name + "_update"
    config["VULN_DATABASE"]["NAME"] = temp_vulndb_name

    for db_name in ("PRODUCT_DATABASE", "VULN_DATABASE"):
        if config[db_name]["TYPE"].lower() == "sqlite":
            db_conn = get_database_connection(config[db_name])
            db_cursor = db_conn.cursor()
        elif config[db_name]["TYPE"].lower() == "mariadb":
            db_conn = get_database_connection(config[db_name], db_name="")
            db_cursor = db_conn.cursor()
            db_cursor.execute(f'CREATE OR REPLACE DATABASE {config[db_name]["NAME"]};')
        db_conn.commit()
        db_cursor.close()
        db_conn.close()

    return (orig_productdb_name, temp_productdb_name), (orig_vulndb_name, temp_vulndb_name)


def _overwrite_old_shared_databases(config, productdb_namepair, vulndb_namepair):
    """Overwrite the current, now old, database with the new ones from the update"""

    for db in ("PRODUCT_DATABASE", "VULN_DATABASE"):
        if db == "PRODUCT_DATABASE":
            orig_db_name, temp_db_name = productdb_namepair
        else:
            orig_db_name, temp_db_name = vulndb_namepair

        if config[db]["TYPE"] == "sqlite":
            if os.path.isfile(temp_db_name):
                os.rename(temp_db_name, orig_db_name)
        else:
            db_conn = get_database_connection(config[db], db_name="")
            db_cursor = db_conn.cursor()
            db_cursor.execute(f"CREATE OR REPLACE DATABASE {orig_db_name};")  # remove old DB

            # first move tables
            db_cursor.execute(
                'SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = "BASE TABLE";',
                (temp_db_name,),
            )
            all_tables = db_cursor.fetchall()
            for table in all_tables:
                table = table[0]
                db_cursor.execute(
                    f"RENAME TABLE `{temp_db_name}`.`{table}` TO `{orig_db_name}`.`{table}`;"
                )

            # then recreate views, since they cannot be moved
            db_cursor.execute(
                "SELECT table_name FROM information_schema.views WHERE table_schema = ?;",
                (temp_db_name,),
            )
            all_views = db_cursor.fetchall()
            for view in all_views:
                view = view[0]
                db_cursor.execute(f"SHOW CREATE VIEW `{temp_db_name}`.`{view}`")
                create_view_stmt = db_cursor.fetchone()[1]
                create_view_stmt = create_view_stmt.replace(
                    f"{temp_db_name}.", f"{orig_db_name}."
                )
                create_view_stmt = create_view_stmt.replace(
                    f"`{temp_db_name}`.", f"`{orig_db_name}`."
                )
                db_cursor.execute(create_view_stmt)
                db_cursor.execute(f"DROP VIEW `{temp_db_name}`.`{view}`")

            db_cursor.execute(f"DROP DATABASE {temp_db_name};")  # remove empty temp DB
            db_conn.commit()
            db_cursor.close()
            db_conn.close()


def is_version_outdated():
    """Return True if a newer search_vulns version was published on GitHub"""

    current_version = get_version()
    resp = requests.get(LATEST_RELEASE_URL, allow_redirects=False)

    latest_release_url = resp.headers.get("location")
    latest_tag = latest_release_url.split("/")[-1]
    latest_version = latest_tag[1:]
    if CPEVersion(latest_version) > CPEVersion(current_version):
        return True
    return False


def insert_update_timestamp_into_vulndb(config):
    """Insert the current time as last update timestamp into vulndb."""

    db_config = config["DATABASE_CONNECTION"]
    db_config["NAME"] = config["VULN_DATABASE"]["NAME"]
    db_conn = get_database_connection(db_config)
    db_cursor = db_conn.cursor()

    # create table storing timestamp of last date update
    db_cursor.execute(
        "CREATE TABLE IF NOT EXISTS meta_last_data_update (UTCTimestamp DATETIME NOT NULL);"
    )

    # insert current time as last update time
    current_datetime_utc = datetime.now(timezone.utc)
    db_cursor.execute(
        "INSERT INTO meta_last_data_update (UTCTimestamp) VALUES (?)",
        (current_datetime_utc.replace(tzinfo=None),),
    )

    db_conn.commit()
    db_cursor.close()
    db_conn.close()


def update(config):
    """Perform a shallow update by downloading the latest resources from GitHub"""

    if is_version_outdated():
        if config["VULN_DATABASE"]["TYPE"] == "mariadb" or os.path.isfile(
            config["VULN_DATABASE"]["NAME"]
        ):
            print(
                "[-] Local software version is outdated. Please update or build resources yourself."
            )
            return False, []
        else:
            print(
                "[-] Warning: Local software version is outdated. Further database updates will not be possible without updating."
            )

    # setup DBs from config and do not overwrite existing data
    print("[+] Downloading latest versions of resources ...")
    db_names = _setup_new_shared_databases(config)
    if not db_names:
        return False
    orig_productdb_name, temp_productdb_name = db_names[0]
    orig_vulndb_name, temp_vulndb_name = db_names[1]

    download_productdb_out, download_vulndb_out = temp_productdb_name, temp_vulndb_name
    if config["PRODUCT_DATABASE"]["TYPE"] == "mariadb":
        download_productdb_out = os.path.join(
            os.path.join(PROJECT_DIR, "resources"), download_productdb_out
        )
    if config["VULN_DATABASE"]["TYPE"] == "mariadb":
        download_vulndb_out = os.path.join(
            os.path.join(PROJECT_DIR, "resources"), download_vulndb_out
        )

    # download shared productdb and vulndb
    try:
        download_file(PRODUCT_DB_ARTIFACT_URL, download_productdb_out, show_progressbar=True)
    except:
        print("[-] Could not download latest productdb file")
        return False, []

    try:
        download_file(VULNDB_ARTIFACT_URL, download_vulndb_out, show_progressbar=True)
    except:
        print("[-] Could not download latest vulndb file")
        return False, []

    # convert downloaded SQLite DBs to MariaDB if necessary
    for db in ("PRODUCT_DATABASE", "VULN_DATABASE"):
        if config[db]["TYPE"] == "mariadb":
            print("[+] Migrating %s from SQLite to MariaDB" % db)
        if config[db]["TYPE"] == "mariadb":
            # write DB network address and credentials to secure config file
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = 0o600  # rw------- permissions
            fd = os.open(MARIADB_CONVERT_CNF_FILE, flags, mode)

            with os.fdopen(fd, "w") as f:
                f.write("[client]\n")
                f.write(f"user = {config[db]['USER']}\n")
                f.write(f"password = {config[db]['PASSWORD']}\n")
                f.write(f"host = {config[db]['HOST']}\n")
                f.write(f"port = {config[db]['PORT']}\n")

            if db == "PRODUCT_DATABASE":
                tempdb = download_productdb_out
            else:
                tempdb = download_vulndb_out

            return_code = subprocess.call(
                f'{MARIADB_CONVERT_SCRIPT} {shlex.quote(tempdb)} {MARIADB_CONVERT_CNF_FILE} {config[db]["NAME"]}',
                shell=True,
            )
            if os.path.isfile(MARIADB_CONVERT_CNF_FILE):
                os.remove(MARIADB_CONVERT_CNF_FILE)

            if return_code != 0:
                print("[-] Migration of database failed")
                return False, []

    # run update function of all modules if present
    modules = get_modules()
    process_manager = Manager()
    stop_update = process_manager.Event()
    success, artifacts = True, []
    for mid in sorted(modules):
        module = modules[mid]
        if hasattr(module, "update") and callable(module.update):
            module_config = config["MODULES"].get(mid, {})
            try:
                m_results = module.update(
                    config["PRODUCT_DATABASE"],
                    config["VULN_DATABASE"],
                    module_config,
                    stop_update,
                )
                if m_results:
                    m_success, m_artifacts = m_results
                else:
                    m_success, m_artifacts = True, []
                if not m_success:
                    success = False
                    print(f"[-] Module {mid} ran did not update successfully.")
                if m_artifacts:
                    for artifact in m_artifacts:
                        if not os.path.isabs(artifact):
                            artifact_path_prefix = MODULE_DIRECTORY
                            for mdir in mid.split(".")[:-1]:
                                artifact_path_prefix = os.path.join(artifact_path_prefix, mdir)
                            artifact = os.path.join(artifact_path_prefix, artifact)
                        artifacts.append(artifact)
            except Exception as e:
                print(f"[-] Module {mid} ran into an error:")
                traceback.print_exception(type(e), e, e.__traceback__)
                success = False

        if stop_update.is_set() or not success:
            print("[-] The update was aborted.")
            success = False
            break

    # rename DBs and if converted, remove downloaded files if any
    _overwrite_old_shared_databases(
        config, (orig_productdb_name, temp_productdb_name), (orig_vulndb_name, temp_vulndb_name)
    )
    if os.path.isfile(download_productdb_out):
        os.remove(download_productdb_out)
    if os.path.isfile(download_vulndb_out):
        os.remove(download_vulndb_out)

    # insert timestamp of this data update into vuln DB
    config["VULN_DATABASE"]["NAME"] = orig_vulndb_name
    insert_update_timestamp_into_vulndb(config)

    return success, artifacts


def _run_full_update_module_wrapper(module_id, config, stop_update):
    """Wrapper for full_update of modules to work with multiprocessing"""

    # Set up logging for module
    log_filename = os.path.join(UPDATE_LOGS_DIR, f"{module_id}.log")
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():  # clear existing handlers
        root_logger.handlers.clear()
    root_logger.setLevel(LOG_LEVEL)

    # Create file handler (append mode)
    fh = logging.FileHandler(log_filename, mode="a")
    fh.setLevel(LOG_LEVEL)

    formatter = logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s")
    fh.setFormatter(formatter)
    root_logger.addHandler(fh)

    # Run module
    modules = get_modules()
    module_config = config["MODULES"].get(module_id, {})
    module_results = modules[module_id].full_update(
        config["PRODUCT_DATABASE"], config["VULN_DATABASE"], module_config, stop_update
    )
    if module_results:
        success, artifacts = module_results
    else:
        success, artifacts = True, []

    # Remove empty logs
    if os.path.exists(log_filename) and os.path.getsize(log_filename) == 0:
        os.remove(log_filename)

    return success, artifacts


def _run_full_update_modules(config, module_ids=None):
    """
    Run full_update procedure of all or given modules if available
    in-place and manage results.
    """

    # setup modules and update tasks
    artifacts = []
    os.makedirs(UPDATE_LOGS_DIR, exist_ok=True)
    modules = get_modules()
    remaining_update_modules, finished_update_modules = [], []
    for mid in sorted(modules):
        module = modules[mid]
        if hasattr(module, "full_update") and callable(module.full_update):
            if not module_ids or mid in module_ids:
                remaining_update_modules.append(mid)
            if module_ids and mid not in module_ids:
                finished_update_modules.append(mid)

    process_manager = Manager()
    stop_update = process_manager.Event()

    with ProcessPoolExecutor(max_workers=MAX_PROCESS_COUNT) as executor:
        running_modules = {}

        while (remaining_update_modules or running_modules) and not stop_update.is_set():
            # Schedule new modules if slots are available
            for module_id in remaining_update_modules:
                if len(running_modules) >= MAX_PROCESS_COUNT:
                    break  # Do not exceed core count

                module = modules[module_id]
                module_requires = []
                if hasattr(module, "REQUIRES_BUILT_MODULES"):
                    module_requires = module.REQUIRES_BUILT_MODULES
                if all(req_module in finished_update_modules for req_module in module_requires):
                    future = executor.submit(
                        _run_full_update_module_wrapper, module_id, config, stop_update
                    )
                    running_modules[future] = module_id
                    remaining_update_modules.remove(module_id)
                    print("[>] Module started: %s" % module_id)

            # Check for completed futures and collect artifacts
            done_futures = [future for future in running_modules if future.done()]
            for future in done_futures:
                module_id = running_modules[future]
                finished_update_modules.append(module_id)
                del running_modules[future]
                print("[<] Module finished: %s" % module_id)

                # handle error in module
                try:
                    success, module_artifacts = future.result()
                except Exception as e:
                    print(f"[-] Module {module_id} ran into an error:")
                    traceback.print_exception(type(e), e, e.__traceback__)
                    stop_update.set()
                    continue

                if not success:
                    print(
                        f"[-] Module {module_id} did not finish successfully. Therefore, the update is canceled."
                    )
                    stop_update.set()
                    continue

                if module_artifacts:
                    for artifact in module_artifacts:
                        if not os.path.isabs(artifact):
                            artifact_path_prefix = MODULE_DIRECTORY
                            for mdir in module_id.split(".")[:-1]:
                                artifact_path_prefix = os.path.join(artifact_path_prefix, mdir)
                            artifact = os.path.join(artifact_path_prefix, artifact)
                        artifacts.append(artifact)

            # Sleep briefly to avoid busy waiting
            time.sleep(0.25)

    if stop_update.is_set():
        return False, []
    return True, artifacts


def full_update(config):
    """Perform full update of all modules out-of-place"""

    # setup DBs from config and do not overwrite existing data
    db_names = _setup_new_shared_databases(config)
    if not db_names:
        return False, []
    orig_productdb_name, temp_productdb_name = db_names[0]
    orig_vulndb_name, temp_vulndb_name = db_names[1]

    # run every module update in a separate process
    success, artifacts = _run_full_update_modules(config)

    # in case of SQLite, force WAL checkpoint
    for db in ("PRODUCT_DATABASE", "VULN_DATABASE"):
        if config[db]["TYPE"] == "sqlite":
            db_conn = get_database_connection(config[db])
            db_cursor = db_conn.cursor()
            db_cursor.execute("PRAGMA wal_checkpoint(FULL);")
            db_conn.commit()
            db_cursor.close()
            db_conn.close()

    # clean up on error, move new DBs to old DBs on success
    if not success:
        for db in ("PRODUCT_DATABASE", "VULN_DATABASE"):
            temp_db_name = temp_productdb_name if db == "PRODUCT_DATABASE" else temp_vulndb_name

            if config[db]["TYPE"] == "sqlite" and os.path.isfile(temp_db_name):
                os.remove(temp_db_name)
            elif config[db]["TYPE"] == "mariadb":
                db_conn = get_database_connection(config[db], db_name="")
                db_cursor = db_conn.cursor()
                db_cursor.execute(f"DROP DATABASE IF EXISTS {temp_db_name};")
                db_conn.commit()
                db_cursor.close()
                db_conn.close()
        print("[-] The update failed because an error occurred.")
    else:
        # if SQLite is used, vacuum databases to minimize size
        print("[+] Update successful, cleaning up.")
        if config[db]["TYPE"] == "sqlite":
            for db in ("PRODUCT_DATABASE", "VULN_DATABASE"):
                temp_db_name = (
                    temp_productdb_name if db == "PRODUCT_DATABASE" else temp_vulndb_name
                )
                db_conn = get_database_connection(config[db])
                db_cursor = db_conn.cursor()
                db_cursor.execute("VACUUM;")
                db_conn.commit()
                db_cursor.close()
                db_conn.close()

        # move product DB and vuln DB
        _overwrite_old_shared_databases(
            config,
            (orig_productdb_name, temp_productdb_name),
            (orig_vulndb_name, temp_vulndb_name),
        )

        # insert timestamp of this data update into vuln DB
        config["VULN_DATABASE"]["NAME"] = orig_vulndb_name
        insert_update_timestamp_into_vulndb(config)

    # remove log directory if it's empty
    if os.path.isdir(UPDATE_LOGS_DIR) and not os.listdir(UPDATE_LOGS_DIR):
        os.rmdir(UPDATE_LOGS_DIR)

    return success, artifacts
