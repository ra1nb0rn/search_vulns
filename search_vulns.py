#!/usr/bin/env python3

import argparse
import copy
import importlib.util
import json
import os
import re
import sys
import threading

from modules.cpe_search.cpe_search.cpe_search import cpe_matches_query
from modules.utils import get_database_connection
from vulnerability import MatchReason

# general variables and settings
PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CONFIG_FILE = os.path.join(PROJECT_DIR, "config.json")
MODULE_DIRECTORY = os.path.join(PROJECT_DIR, "modules")
MODULE_ENTRY_PREFIX = "search_vulns_"
MODULES = None
LOAD_MODULES_MUTEX = threading.Lock()
VERSION_FILE = os.path.join(PROJECT_DIR, "version.txt")
DEDUP_LINEBREAKS_RE_1 = re.compile(r"(\r\n)+")
DEDUP_LINEBREAKS_RE_2 = re.compile(r"\n+")

# define ANSI color escape sequences
# Taken from: http://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html
# and: http://www.topmudsites.com/forums/showthread.php?t=413
SANE = "\u001b[0m"
GREEN = "\u001b[32m"
BRIGHT_GREEN = "\u001b[32;1m"
RED = "\u001b[31m"
YELLOW = "\u001b[33m"
BRIGHT_BLUE = "\u001b[34;1m"
MAGENTA = "\u001b[35m"
BRIGHT_CYAN = "\u001b[36;1m"


def printit(text: str = "", end: str = "\n", color=SANE):
    """A small print wrapper function"""

    print(color, end="")
    print(text, end=end)
    if color != SANE:
        print(SANE, end="")
    sys.stdout.flush()


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


def print_vulns(vulns, to_string=False):
    """Print the supplied vulnerabilities"""

    out_string = ""
    vuln_ids_sorted = sorted(
        list(vulns), key=lambda vuln_Id: float(vulns[vuln_Id].cvss), reverse=True
    )
    for vuln_id in vuln_ids_sorted:
        vuln_node = vulns[vuln_id]
        description = DEDUP_LINEBREAKS_RE_2.sub(
            "\n", DEDUP_LINEBREAKS_RE_1.sub("\r\n", vuln_node.description.strip())
        )

        if not to_string:
            print_str = GREEN + vuln_node.id + SANE
            print_str += (
                " ("
                + MAGENTA
                + "CVSSv"
                + vuln_node.cvss_ver
                + "/"
                + str(vuln_node.cvss)
                + SANE
                + ")"
            )
            if vuln_node.cisa_known_exploited:
                print_str += " (" + RED + "Actively exploited" + SANE + ")"
        else:
            print_str = vuln_node.id
            print_str += " (" "CVSSv" + vuln_node.cvss_ver + "/" + str(vuln_node.cvss) + ")"
            if vuln_node.cisa_known_exploited:
                print_str += " (Actively exploited)"
        print_str += ": " + description + "\n"

        if vuln_node.exploits:
            vuln_exploits = list(vuln_node.exploits)
            if not to_string:
                print_str += YELLOW + "Exploits:  " + SANE + vuln_exploits[0] + "\n"
            else:
                print_str += "Exploits:  " + vuln_exploits[0] + "\n"

            if len(vuln_exploits) > 1:
                for edb_link in vuln_exploits[1:]:
                    print_str += len("Exploits:  ") * " " + edb_link + "\n"

        print_str += "Reference: " + vuln_node.aliases[vuln_node.id]
        print_str += ", " + vuln_node.published.split(" ")[0]
        if not to_string:
            printit(print_str)
        else:
            out_string += print_str + "\n"

    if to_string:
        return out_string


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
                        spec.loader.exec_module(module)
                        MODULES[module_id] = module
        LOAD_MODULES_MUTEX.release()

    return MODULES


def _search_vulns(
    query,
    product_ids,
    vuln_db_cursor,
    ignore_general_product_vulns,
    include_single_version_vulns,
    config,
):
    """Search for known vulnerabilities based on the given query of product"""

    all_module_vulns = {}
    search_vulns_modules = get_modules()
    for mid, module in search_vulns_modules.items():
        if hasattr(module, "search_vulns") and callable(module.search_vulns):
            m_config = config["MODULES"].get(mid, {})
            module_vulns = module.search_vulns(query, product_ids, vuln_db_cursor, m_config)
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


def _search_product_ids(
    query, product_db_cursor, is_product_id_query, config, known_product_ids={}
):
    """Search for product IDs matching the query"""

    query = query.strip()
    search_vulns_modules = get_modules()
    product_ids = copy.deepcopy(known_product_ids) if known_product_ids else {}
    pot_product_ids = {}

    for mid, module in search_vulns_modules.items():
        if hasattr(module, "search_product_ids") and callable(module.search_product_ids):
            m_config = config["MODULES"].get(mid, {})
            new_ids, new_pot_ids = module.search_product_ids(
                query, product_db_cursor, product_ids, is_product_id_query, m_config
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


def search_vulns(
    query,
    product_ids=None,
    vuln_db_cursor=None,
    product_db_cursor=None,
    is_product_id_query=False,
    ignore_general_product_vulns=False,
    include_single_version_vulns=False,
    config=None,
):
    """Search for known vulnerabilities based on the given query"""

    # create DB handle if not given
    if not config:
        config = _load_config()

    close_vuln_db_after, close_product_db_after = False, False
    if not vuln_db_cursor:
        vuln_db_conn = get_database_connection(config["VULN_DATABASE"])
        vuln_db_cursor = vuln_db_conn.cursor()
        close_vuln_db_after = True
    if not product_db_cursor:
        product_db_conn = get_database_connection(config["PRODUCT_DATABASE"])
        product_db_cursor = product_db_conn.cursor()
        close_product_db_after = True

    query_stripped = query.strip()
    search_vulns_modules = get_modules()

    # search for product IDs
    product_ids, pot_product_ids = _search_product_ids(
        query, product_db_cursor, is_product_id_query, config, product_ids
    )

    # search for vulnerabilities
    vulns = _search_vulns(
        query_stripped,
        product_ids,
        vuln_db_cursor,
        ignore_general_product_vulns,
        include_single_version_vulns,
        config,
    )

    if not vulns:
        return {"product_ids": product_ids, "vulns": {}, "pot_product_ids": pot_product_ids}

    # add extra information to identified vulnerabilities, like exploits or tracking information
    for mid, module in search_vulns_modules.items():
        if hasattr(module, "add_extra_vuln_info") and callable(module.add_extra_vuln_info):
            m_config = config["MODULES"].get(mid, {})
            module.add_extra_vuln_info(vulns, vuln_db_cursor, m_config)

    # create results and add non-vulnerability extra information related to query
    results = {}
    results["product_ids"] = product_ids
    results["vulns"] = vulns
    results["pot_product_ids"] = pot_product_ids

    for mid, module in search_vulns_modules.items():
        if hasattr(module, "add_extra_result_info") and callable(module.add_extra_result_info):
            m_config = config["MODULES"].get(mid, {})
            module_extra_results = module.add_extra_result_info(
                query, product_ids, vuln_db_cursor, m_config
            )
            for key, value in module_extra_results.items():
                if key not in results:
                    results[key] = value
                else:
                    for i in range(1, 10):
                        new_key = key + "_" + str(i)
                        if new_key not in results:
                            results[new_key] = value
                            break

    if close_vuln_db_after:
        vuln_db_cursor.close()
        vuln_db_conn.close()
    if close_product_db_after:
        product_db_cursor.close()
        product_db_conn.close()

    return results


def serialize_vulns(vulns):
    """Serialize the provided vulnerabilities."""


def parse_args():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(
        description="Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)"
    )
    parser.add_argument(
        "-u",
        "--update",
        action="store_true",
        help="Download the latest version of the the local vulnerability and software database",
    )
    parser.add_argument(
        "--full-update",
        action="store_true",
        help="Fully (re)build the local vulnerability and software database",
    )
    parser.add_argument(
        "-a",
        "--artifacts",
        action="store_true",
        help="Print JSON list of artifacts created during full update",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="txt",
        choices={"txt", "json"},
        help="Output format, either 'txt' or 'json' (default: 'txt')",
    )
    parser.add_argument(
        "-o", "--output", type=str, help="File to write found vulnerabilities to"
    )
    parser.add_argument(
        "-q",
        "--query",
        dest="queries",
        metavar="QUERY",
        action="append",
        help="A query, either software title like 'Apache 2.4.39' or a product ID string (e.g. CPE 2.3)",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=DEFAULT_CONFIG_FILE,
        help="A config file to use (default: config.json)",
    )
    parser.add_argument(
        "-V", "--version", action="store_true", help="Print the version of search_vulns"
    )
    parser.add_argument(
        "--cpe-search-threshold",
        type=float,
        default=None,
        help="Similarity threshold used for retrieving a CPE via the cpe_search tool",
    )
    parser.add_argument(
        "--ignore-general-product-vulns",
        action="store_true",
        help="Ignore vulnerabilities that only affect a general product (i.e. without version)",
    )
    parser.add_argument(
        "--include-single-version-vulns",
        action="store_true",
        help="Include vulnerabilities that only affect one specific version of a product when querying a lower version",
    )
    parser.add_argument(
        "--use-created-product-ids",
        action="store_true",
        help="If no matching product ID exists in the software database, automatically use matching ones created by search_vulns",
    )

    args = parser.parse_args()
    if not args.update and not args.queries and not args.full_update and not args.version:
        parser.print_help()
    return args


def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.update == True:
        from updater import update

        config = _load_config(args.config)
        success, artifacts = update(config)
        if args.artifacts:
            print(json.dumps(artifacts))
        if not success:
            sys.exit(1)
    elif args.full_update == True:
        from updater import full_update

        config = _load_config(args.config)
        success, artifacts = full_update(config)
        if args.artifacts:
            print(json.dumps(artifacts))
        if not success:
            sys.exit(1)
    elif args.version == True:
        with open(VERSION_FILE) as f:
            print(f.read())
        return

    if not args.queries:
        return

    # retrieve known vulnerabilities for every query and print them
    config = _load_config(args.config)
    all_vulns = {}
    out_string = ""
    for query in args.queries:
        # Prepare arguments and search for vulnerabilities
        query = query.strip()

        if args.cpe_search_threshold:
            config["MODULES"]["cpe_search.search_vulns_cpe_search"][
                "CPE_SEARCH_THRESHOLD"
            ] = args.cpe_search_threshold
        config["MODULES"]["cpe_search.search_vulns_cpe_search"][
            "CPE_SEARCH_COUNT"
        ] = 1  # limit for CLI usage

        if args.format.lower() == "txt":
            if not args.output:
                printit("[+] %s (" % query, color=BRIGHT_BLUE, end="")
            else:
                out_string += "[+] %s (" % query

        sv_result = search_vulns(
            query,
            None,
            None,
            None,
            False,
            args.ignore_general_product_vulns,
            args.include_single_version_vulns,
            config,
        )

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
            and args.use_created_product_ids
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
                    args.ignore_general_product_vulns,
                    args.include_single_version_vulns,
                    config,
                )
                all_product_ids = []
                for pids in sv_result["product_ids"].values():
                    all_product_ids += pids

        if not is_good_result:
            if args.format.lower() == "txt":
                if not args.output:
                    printit(")", color=BRIGHT_BLUE)
                    printit("Warning: Could not find matching software for query", color=RED)
                    printit()
                    continue
                else:
                    out_string += ")\nWarning: Could not find matching software for query\n\n"
            else:
                all_vulns[query] = "Warning: Could not find matching software for query"
            continue

        if args.format.lower() == "txt":
            if not args.output:
                printit("/".join(all_product_ids) + ")", color=BRIGHT_BLUE)
            else:
                out_string += "/".join(all_product_ids) + ")\n"

        # "sort" vulnerabilities by CVSS score
        if sv_result["vulns"]:
            vuln_ids_sorted = sorted(
                list(sv_result["vulns"]),
                key=lambda vuln_id: float(sv_result["vulns"][vuln_id].cvss),
                reverse=True,
            )
            sorted_vulns = {}
            for vuln_id in vuln_ids_sorted:
                sorted_vulns[vuln_id] = sv_result["vulns"][vuln_id]
            sv_result["vulns"] = sorted_vulns

        # prepare output
        if args.format.lower() == "txt":
            # print found vulnerabilities
            if not args.output:
                print_vulns(sv_result["vulns"])
            else:
                out_string += print_vulns(sv_result["vulns"], to_string=True)
        else:
            # serialize vulns for json output
            serial_vulns = {}
            for vuln_id, vuln in sv_result["vulns"].items():
                serial_vulns[vuln_id] = vuln.to_dict()
            sv_result["vulns"] = serial_vulns

        all_vulns[query] = sv_result

    # provide final output
    if args.output:
        with open(args.output, "w") as f:
            if args.format.lower() == "json":
                f.write(json.dumps(all_vulns))
            else:
                f.write(out_string)
    elif args.format.lower() == "json":
        print(json.dumps(all_vulns))


if __name__ == "__main__":
    main()
