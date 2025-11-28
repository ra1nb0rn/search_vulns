import copy
import importlib.util
import json
import os
import threading

from cpe_search.cpe_search import cpe_matches_query

from .modules.utils import get_database_connection
from .vulnerability import MatchReason

# general variables and settings
PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CONFIG_FILE = os.path.join(PROJECT_DIR, "config.json")
IS_FULLY_INSTALLED_FILE = os.path.join(PROJECT_DIR, ".is_installed")
MODULE_DIRECTORY = os.path.join(PROJECT_DIR, "modules")
MODULE_ENTRY_PREFIX = "search_vulns_"
MODULES = None
LOAD_MODULES_MUTEX = threading.Lock()


# Optional dependency groups used for better error messages when modules
# require extras that are not installed by default.
OPTIONAL_DEP_GROUPS = {
    "Flask": "web",
    "gunicorn": "web",
    "gevent": "web",
    "markdown": "web",
    "mariadb": "mariadb",
}


def get_version():
    """Return current version of search_vulns"""
    from importlib.metadata import PackageNotFoundError, version

    try:
        pkg_version = version("search_vulns")
    except PackageNotFoundError:
        pkg_version = "unknown"
    return pkg_version


def _load_config(config_file=DEFAULT_CONFIG_FILE):
    """Load config from file"""

    with open(config_file) as f:  # default: config.json
        config = json.loads(f.read())

    for db in ("VULN_DATABASE", "PRODUCT_DATABASE"):
        # copy values from shared connection entry
        copy_connection_values = True
        for db_conn_info in ("TYPE", "HOST", "USER", "PASSWORD", "PORT"):
            if db_conn_info in config["DATABASE_CONNECTION"] and db_conn_info in config[db]:
                copy_connection_values = False
        if copy_connection_values:
            for db_conn_info in ("TYPE", "HOST", "USER", "PASSWORD", "PORT"):
                if db_conn_info in config["DATABASE_CONNECTION"]:
                    config[db][db_conn_info] = config["DATABASE_CONNECTION"][db_conn_info]

        # for sqlite make DB path absolute
        db_type = ""
        for key, val in config[db].items():
            if key.lower() == "type":
                db_type = val
                break
        if db_type == "sqlite":
            for key, val in config[db].items():
                if key.lower() == "name":
                    if not os.path.isabs(val):
                        if val != os.path.expanduser(val):  # home-relative path was given
                            val = os.path.expanduser(val)
                        else:
                            val = os.path.join(
                                os.path.dirname(os.path.abspath(config_file)), val
                            )
                        config[db][key] = val
                    break

    return config


def merge_module_vulns(all_module_vulns, modules_data_preference):
    """Deduplicate vulnerabilities from different sources and combine aliases"""

    merged_vulns = {}
    merge_order = modules_data_preference
    merge_order += sorted(list(set(all_module_vulns.keys()) - set(modules_data_preference)))

    # go over every module and its vulns
    for module_id in merge_order:
        if module_id not in all_module_vulns:
            continue

        vulns = all_module_vulns[module_id]
        tracked_alias_map = {}

        for vuln_id, vuln in vulns.items():
            tracked_alias = None
            for alias in vuln.aliases:
                # check if the id for this vuln is already tracked
                if alias in merged_vulns:
                    tracked_alias = alias
                    break
                if alias in tracked_alias_map:
                    tracked_alias = tracked_alias_map[alias]
                    break

                # otherwise, check directly if the current vulnerability
                # was already processed via an alias
                for merged_vuln_id, merged_vuln in merged_vulns.items():
                    if alias in merged_vuln.aliases:
                        tracked_alias = merged_vuln_id

            if not tracked_alias:
                merged_vulns[vuln_id] = vuln
                for alias in vuln.aliases:
                    if alias not in tracked_alias_map:
                        tracked_alias_map[alias] = []
                    tracked_alias_map[alias].append(alias)
            else:
                old_vuln_id = merged_vulns[tracked_alias].id
                merged_vulns[tracked_alias].merge_with_vulnerability(vuln)
                new_vuln_id = merged_vulns[tracked_alias].id

                # other vulnerability had a higher match_reason and vuln attributes were changed
                if old_vuln_id != new_vuln_id:
                    merged_vulns[new_vuln_id] = merged_vulns[old_vuln_id]
                    del merged_vulns[old_vuln_id]
                    if old_vuln_id in tracked_alias_map:
                        tracked_alias_map[new_vuln_id] = tracked_alias_map[old_vuln_id]
                        del tracked_alias_map[old_vuln_id]
                    else:
                        tracked_alias_map[new_vuln_id] = list(merged_vulns[new_vuln_id].aliases)
                tracked_alias_map[new_vuln_id] = list(merged_vulns[new_vuln_id].aliases)

    return merged_vulns


def get_modules():
    global MODULES

    if MODULES is None:
        LOAD_MODULES_MUTEX.acquire()

        MODULES = {}
        for root, _, files in os.walk(MODULE_DIRECTORY):
            for filename in files:
                if filename.startswith(MODULE_ENTRY_PREFIX) and filename.endswith(".py"):
                    filepath = os.path.join(root, filename)
                    module_id = filepath.replace(MODULE_DIRECTORY, "")[1:]
                    module_id = os.path.splitext(module_id)[0].replace("/", ".")
                    module_name = os.path.splitext(filename)[0]
                    spec = importlib.util.spec_from_file_location(module_name, filepath)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        # Set search_vulns package as module's package to fix relative imports
                        module.__package__ = module_id.rpartition(".")[0]
                        try:
                            spec.loader.exec_module(module)
                        except ModuleNotFoundError as exc:
                            missing_dep = getattr(exc, "name", str(exc))
                            opt_group = OPTIONAL_DEP_GROUPS.get(missing_dep)
                            if opt_group:
                                from .cli import YELLOW, printit

                                printit(
                                    "[!] Skipping module '{module_id}' – missing optional dependency '{missing_dep}'.".format(
                                        module_id=module_id, missing_dep=missing_dep
                                    )
                                    + " Install extras via 'pip install \"search-vulns[{opt_group}]\"' to enable it.".format(
                                        opt_group=opt_group
                                    ),
                                    color=YELLOW,
                                )
                                continue
                            raise
                        MODULES[module_id] = module
        LOAD_MODULES_MUTEX.release()

    return MODULES


def _search_vulns(
    query,
    product_ids,
    vuln_db_cursor,
    config,
    module_run_order,
    extra_params,
    ignore_general_product_vulns,
    include_single_version_vulns,
):
    """Search for known vulnerabilities based on the given query of product"""

    all_module_vulns = {}
    search_vulns_modules = get_modules()
    for mid in module_run_order:
        module = search_vulns_modules[mid]
        if hasattr(module, "search_vulns") and callable(module.search_vulns):
            m_config = config["MODULES"].get(mid, {})
            module_vulns = module.search_vulns(
                query, product_ids, vuln_db_cursor, m_config, extra_params
            )
            all_module_vulns[mid] = module_vulns

    # merge / deduplicate vulns (reason: different data sources, equivalent prodcut IDs and more)
    vulns = merge_module_vulns(all_module_vulns, config.get("MODULES_DATA_PREFERENCE", []))

    # potentially delete too imprecisely matched vulnerabilities
    for vuln_id in list(vulns.keys()):
        if (
            ignore_general_product_vulns
            and vulns[vuln_id].match_reason == MatchReason.GENERAL_PRODUCT_UNCERTAIN
        ):
            del vulns[vuln_id]
            continue
        if (
            not include_single_version_vulns
            and vulns[vuln_id].match_reason == MatchReason.SINGLE_HIGHER_VERSION
        ):
            del vulns[vuln_id]

    return vulns


def search_product_ids(
    query, product_db_cursor, is_product_id_query, config, known_product_ids={}
):
    search_vulns_result = search_vulns(
        query,
        known_product_ids,
        None,
        product_db_cursor,
        is_product_id_query,
        False,
        False,
        False,
        config,
        True,
    )
    return search_vulns_result["product_ids"], search_vulns_result["pot_product_ids"]


def _search_product_ids(
    query,
    product_db_cursor,
    is_product_id_query,
    config,
    module_run_order,
    known_product_ids={},
    extra_params={},
):
    """Search for product IDs matching the query"""

    query = query.strip()
    search_vulns_modules = get_modules()
    product_ids = copy.deepcopy(known_product_ids) if known_product_ids else {}
    pot_product_ids = {}

    for mid in module_run_order:
        module = search_vulns_modules[mid]
        if hasattr(module, "search_product_ids") and callable(module.search_product_ids):
            m_config = config["MODULES"].get(mid, {})
            new_ids, new_pot_ids = module.search_product_ids(
                query,
                product_db_cursor,
                product_ids,
                is_product_id_query,
                m_config,
                extra_params,
            )
            for key, value in new_ids.items():
                if key not in product_ids:
                    product_ids[key] = value
                else:
                    product_ids[key] = list(set(product_ids.get(key, []) + value))
            for key, value in new_pot_ids.items():
                if key not in pot_product_ids:
                    pot_product_ids[key] = []
                pot_product_ids[key] += value

    return product_ids, pot_product_ids


def _retrieve_module_run_order():
    """Determine order to run search_vulns modules in"""
    search_vulns_modules = get_modules()
    remaining_modules = list(search_vulns_modules)
    module_run_order = []

    while remaining_modules:
        for mid in remaining_modules:
            module = search_vulns_modules[mid]

            module_requires = []
            if hasattr(module, "REQUIRES_RAN_MODULES"):
                module_requires = module.REQUIRES_RAN_MODULES

            if all(req_module in module_run_order for req_module in module_requires):
                module_run_order.append(mid)
                remaining_modules.remove(mid)
    return module_run_order


def search_vulns(
    query,
    known_product_ids=None,
    vuln_db_cursor=None,
    product_db_cursor=None,
    is_product_id_query=False,
    ignore_general_product_vulns=False,
    include_single_version_vulns=False,
    include_patched=False,
    config=None,
    skip_vuln_search=False,
):
    """Search for known vulnerabilities based on the given query"""

    # create DB handle if not given
    if not config:
        config = _load_config()

    close_vuln_db_after, close_product_db_after = False, False
    if not skip_vuln_search and not vuln_db_cursor:
        vuln_db_conn = get_database_connection(config["VULN_DATABASE"])
        vuln_db_cursor = vuln_db_conn.cursor()
        close_vuln_db_after = True
    if not product_db_cursor:
        product_db_conn = get_database_connection(config["PRODUCT_DATABASE"])
        product_db_cursor = product_db_conn.cursor()
        close_product_db_after = True

    query_processed = query.strip()
    search_vulns_modules = get_modules()
    module_run_order = _retrieve_module_run_order()

    # preprocess query
    extra_params = {}
    for mid in module_run_order:
        module = search_vulns_modules[mid]
        if hasattr(module, "preprocess_query") and callable(module.preprocess_query):
            m_config = config["MODULES"].get(mid, {})
            new_query, mod_extra_params = module.preprocess_query(
                query_processed, known_product_ids, vuln_db_cursor, product_db_cursor, m_config
            )
            if new_query:
                query_processed = new_query
            for key, val in mod_extra_params.items():
                extra_params[key] = val

    # search for product IDs
    product_ids, pot_product_ids = _search_product_ids(
        query_processed,
        product_db_cursor,
        is_product_id_query,
        config,
        module_run_order,
        known_product_ids,
        extra_params,
    )

    # search for vulnerabilities or skip this step
    if not skip_vuln_search:
        vulns = _search_vulns(
            query_processed,
            product_ids,
            vuln_db_cursor,
            config,
            module_run_order,
            extra_params,
            ignore_general_product_vulns,
            include_single_version_vulns,
        )

        # add extra information to identified vulnerabilities, like exploits or tracking information
        for mid in module_run_order:
            module = search_vulns_modules[mid]
            if hasattr(module, "add_extra_vuln_info") and callable(module.add_extra_vuln_info):
                m_config = config["MODULES"].get(mid, {})
                module.add_extra_vuln_info(vulns, vuln_db_cursor, m_config, extra_params)

    else:
        vulns = {}

    # create results and post process results, e.g. to add non-vulnerability related information
    results = {}
    results["product_ids"] = product_ids
    results["vulns"] = vulns
    results["pot_product_ids"] = pot_product_ids

    for mid in module_run_order:
        module = search_vulns_modules[mid]
        if hasattr(module, "postprocess_results") and callable(module.postprocess_results):
            m_config = config["MODULES"].get(mid, {})
            module.postprocess_results(
                results,
                query_processed,
                vuln_db_cursor,
                product_db_cursor,
                m_config,
                extra_params,
            )

    # remove patched vulns from results
    if not include_patched:
        del_vuln_ids = []
        for vuln_id, vuln in results["vulns"].items():
            if vuln.is_patched():
                del_vuln_ids.append(vuln_id)
        for vuln_id in del_vuln_ids:
            del results["vulns"][vuln_id]

    if close_vuln_db_after:
        vuln_db_cursor.close()
        vuln_db_conn.close()
    if close_product_db_after:
        product_db_cursor.close()
        product_db_conn.close()

    return results


def check_and_try_sv_rerun_with_created_cpes(
    query,
    sv_result,
    ignore_general_product_vulns,
    include_single_version_vulns,
    include_patched,
    use_created_product_ids,
    config,
):
    """On bad result, rerun with created CPEs if possible"""

    # check if result is good, i.e. vulns or product IDs were found
    all_product_ids = []
    for pids in sv_result["product_ids"].values():
        all_product_ids += pids

    is_good_result = True
    if not sv_result["vulns"]:
        if not all_product_ids:
            is_good_result = False
        else:
            # small sanity check on retrieved CPE
            check_str = sv_result["product_ids"]["cpe"][0][8:]
            if any(char.isdigit() for char in query) and not any(
                char.isdigit() for char in check_str
            ):
                is_good_result = False

    # if a good product ID couldn't be found, use a created one if configured and appropriate
    if (
        not is_good_result
        and sv_result["pot_product_ids"].get("cpe", [])
        and use_created_product_ids
    ):
        created_cpe = None
        for pot_cpe in sv_result["pot_product_ids"]["cpe"]:
            if cpe_matches_query(pot_cpe[0], query):
                created_cpe = pot_cpe[0]
                is_good_result = True
                break

        if is_good_result:
            sv_result = search_vulns(
                created_cpe,
                None,
                None,
                None,
                False,
                ignore_general_product_vulns,
                include_single_version_vulns,
                include_patched,
                config,
            )

    return is_good_result, sv_result


def serialize_vulns_in_result(result):
    """Serialize the vulnerabilities in the provided result."""

    serial_vulns = {}
    for vuln_id, vuln in result["vulns"].items():
        serial_vulns[vuln_id] = vuln.to_dict()
    result["vulns"] = serial_vulns


def is_fully_installed():
    return os.path.isfile(IS_FULLY_INSTALLED_FILE)
