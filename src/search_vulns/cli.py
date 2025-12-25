#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys

from .core import (
    DEFAULT_CONFIG_FILE,
    _load_config,
    check_and_try_sv_rerun_with_created_cpes,
    get_version,
    is_fully_installed,
    search_vulns,
    serialize_vulns_in_result,
)

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

DEDUP_LINEBREAKS_RE_1 = re.compile(r"(\r\n)+")
DEDUP_LINEBREAKS_RE_2 = re.compile(r"\n+")


def printit(text: str = "", end: str = "\n", color=SANE):
    """A small print wrapper function"""

    print(color, end="")
    print(text, end=end)
    if color != SANE:
        print(SANE, end="")
    sys.stdout.flush()


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


def parse_args():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(
        description="Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)"
    )
    parser.add_argument(
        "-u",
        "--update",
        action="store_true",
        help="Download the latest version of the the local vulnerability and software database from GitHub repo",
    )
    parser.add_argument(
        "--full-update",
        action="store_true",
        help="Fully (re)build the local vulnerability and software database",
    )
    parser.add_argument(
        "--full-update-module",
        metavar="MODULE_ID",
        nargs="+",
        type=str,
        help="Fully (re)build the local database for the given module(s) in-place",
    )
    parser.add_argument(
        "--full-install",
        action="store_true",
        help="Fully install search_vulns, including all dependencies (python packages, system packages etc.)",
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
        help="A query, either a software title like 'Apache 2.4.39', a product ID string (e.g. CPE 2.3) or a list of vuln IDs",
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
    parser.add_argument(
        "--include-patched",
        action="store_true",
        help="Include vulnerabilities reported as (back)patched, e.g. by Debian Security Tracker, in results",
    )

    args = parser.parse_args()
    if (
        not args.update
        and not args.queries
        and not args.full_update
        and not args.full_update_module
        and not args.version
        and not args.full_install
    ):
        parser.print_help()
    return args


def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.full_install:
        from .installer import full_install

        success = full_install()
        if not success:
            sys.exit(1)

    config = _load_config(args.config)

    # Autoset update to True if resource files are missing (only check SQLite config)
    if (
        (
            config["DATABASE_CONNECTION"] == "sqlite"
            and not os.path.exists(config["VULN_DATABASE"]["NAME"])
        )
        and not args.full_install
        and not args.update
        and not args.full_update
    ):
        printit(
            "[!] Vulnerability database file not found, setting 'update' to 'True'",
            color=YELLOW,
        )
        args.update = True

    if args.update == True:
        from .updater import update

        success, artifacts = update(config)
        if args.artifacts:
            print(json.dumps(artifacts))
        if not success:
            sys.exit(1)
    elif args.full_update == True:
        if not is_fully_installed():
            printit(
                "[!] Cannot perform full update without fully installed search_vulns version",
                color=RED,
            )
            sys.exit(1)

        from .updater import full_update

        success, artifacts = full_update(config)
        if args.artifacts:
            print(json.dumps(artifacts))
        if not success:
            sys.exit(1)
    elif args.version == True:
        print(get_version())
        return

    if args.full_update_module:
        from .updater import _run_full_update_modules

        success, artifacts = _run_full_update_modules(config, args.full_update_module)
        if not success:
            print("[-] Update failed")
        else:
            print("[+] Update successful")

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
            args.include_patched,
            config,
        )

        # check if result is good, i.e. vulns or product IDs were found
        is_good_result, sv_result = check_and_try_sv_rerun_with_created_cpes(
            query,
            sv_result,
            args.ignore_general_product_vulns,
            args.include_single_version_vulns,
            args.include_patched,
            args.use_created_product_ids,
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
            serialize_vulns_in_result(sv_result)

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
