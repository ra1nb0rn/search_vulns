#!/usr/bin/env python3

import argparse
import json
import os
import sys

from ..core import (
    DEFAULT_CONFIG_FILE,
    _load_config,
    get_modules,
    get_version,
    is_fully_installed,
)
from .backend import DEFAULT_API_URL, select_backend
from .formatters import (
    BRIGHT_BLUE,
    RED,
    YELLOW,
    format_ansi,
    format_json_batch,
    format_md,
    parse_md_cols,
    print_vulns,
    printit,
    sort_and_cap_vulns,
    strip_ansi,
)
from .interactive import run_interactive_loop


# ------------------------------------------------ helpers
def _read_query_file(path: str) -> list:
    try:
        with open(path) as fh:
            return [
                line.strip() for line in fh if line.strip() and not line.strip().startswith("#")
            ]
    except OSError as exc:
        print(f"Error: Cannot read query file '{path}': {exc}", file=sys.stderr)
        sys.exit(1)


# ------------------------------------------------ arg parsing
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
        choices={"txt", "json", "ansi", "md"},
        help="Output format: txt, json, ansi, or md (default: ansi (interactive), txt (otherwise))",
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
        "--list-modules", action="store_true", help="Print all available modules"
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
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key for remote search (overrides SV_API_KEY env var)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default=None,
        help=f"API base URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--query-file",
        type=str,
        default=None,
        help="File with queries, one per line (# comments and blank lines skipped)",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Interactive mode: suggest product IDs, pick, then search",
    )
    parser.add_argument(
        "--vuln-count",
        type=int,
        default=None,
        help="Max number of vulnerabilities per query (sorted by criticality)",
    )
    parser.add_argument(
        "--md-cols",
        type=str,
        default=None,
        help="Columns for markdown format (default: id,cvss,description)",
    )

    args = parser.parse_args()
    if (
        not args.update
        and not args.queries
        and not args.full_update
        and not args.full_update_module
        and not args.version
        and not args.full_install
        and not args.list_modules
        and not args.interactive
        and not args.query_file
    ):
        parser.print_help()
    return args


# ------------------------------------------------ main
def main():
    # parse args and run update routine if requested
    args = parse_args()

    if args.full_install:
        from ..installer import full_install

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

    if args.list_modules:
        module_ids = sorted(get_modules())
        print("\n".join(module_ids))
        sys.exit(0)
    if args.update == True:
        from ..updater import update

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

        from ..updater import full_update

        success, artifacts = full_update(config)
        if args.artifacts:
            print(json.dumps(artifacts))
        if not success:
            sys.exit(1)
    elif args.version == True:
        print(get_version())
        return

    if args.full_update_module:
        from ..updater import _run_full_update_modules

        success, artifacts = _run_full_update_modules(config, args.full_update_module)
        if not success:
            print("[-] Update failed")
        else:
            print("[+] Update successful")

    # Collect queries
    queries = list(args.queries or [])
    if args.query_file:
        queries.extend(_read_query_file(args.query_file))

    if not queries and not args.interactive:
        return

    # Select backend and build search kwargs
    config = _load_config(args.config)
    backend = select_backend(args, config)

    search_kwargs = {
        "ignore_general_product_vulns": args.ignore_general_product_vulns,
        "include_single_version_vulns": args.include_single_version_vulns,
        "include_patched": args.include_patched,
        "use_created_product_ids": args.use_created_product_ids,
    }

    fmt = args.format
    if not fmt:
        # default format "ansi" in interactive, "txt" otherwise
        fmt = "ansi" if args.interactive else "txt"
    fmt = fmt.lower()

    md_cols = parse_md_cols(args.md_cols or "id,cvss,description")

    # Interactive mode
    if args.interactive:

        def render_result(query, sv_result):
            if args.vuln_count is not None:
                sv_result.vulns = sort_and_cap_vulns(sv_result.vulns, args.vuln_count)
            if fmt == "ansi":
                print(format_ansi(query, sv_result))
            elif fmt == "md":
                print(format_md(sv_result, md_cols))
            elif fmt == "txt":
                all_product_ids = sv_result.product_ids.get_all()
                printit("[+] %s (" % query, color=BRIGHT_BLUE, end="")
                printit("/".join(all_product_ids) + ")", color=BRIGHT_BLUE)
                print_vulns(sv_result.vulns)
            elif fmt == "json":
                print(json.dumps({query: sv_result.model_dump(exclude_none=True)}))

        run_interactive_loop(
            backend,
            seed_queries=queries or None,
            render_result=render_result,
            search_kwargs=search_kwargs,
        )
        return

    # Batch mode
    all_vulns = {}
    out_string = ""
    md_blocks = []

    for query in queries:
        query = query.strip()

        if fmt == "txt":
            if not args.output:
                printit("[+] %s (" % query, color=BRIGHT_BLUE, end="")
            else:
                out_string += "[+] %s (" % query

        is_good_result, sv_result = backend.search(query, **search_kwargs)
        all_product_ids = sv_result.product_ids.get_all()

        if not is_good_result:
            if fmt == "txt":
                if not args.output:
                    printit(")", color=BRIGHT_BLUE)
                    printit("Warning: Could not find matching software for query", color=RED)
                    printit()
                else:
                    out_string += ")\nWarning: Could not find matching software for query\n\n"
            elif fmt == "json":
                all_vulns[query] = "Warning: Could not find matching software for query"
            continue

        if fmt == "txt":
            if not args.output:
                printit("/".join(all_product_ids) + ")", color=BRIGHT_BLUE)
            else:
                out_string += "/".join(all_product_ids) + ")\n"

        # Apply vuln-count capping
        if args.vuln_count is not None:
            sv_result.vulns = sort_and_cap_vulns(sv_result.vulns, args.vuln_count)

        # Sort vulns by CVSS for txt/json (preserves original behavior)
        if fmt in ("txt", "json") and sv_result.vulns:
            vuln_ids_sorted = sorted(
                list(sv_result.vulns),
                key=lambda vuln_id: sv_result.vulns[vuln_id].get_cvss_score(),
                reverse=True,
            )
            sv_result.vulns = {vid: sv_result.vulns[vid] for vid in vuln_ids_sorted}

        if fmt == "txt":
            if not args.output:
                print_vulns(sv_result.vulns)
            else:
                out_string += print_vulns(sv_result.vulns, to_string=True) or ""
        elif fmt == "ansi":
            block = format_ansi(query, sv_result)
            if not args.output:
                print(block)
            else:
                out_string += strip_ansi(block) + "\n"
        elif fmt == "md":
            md_blocks.append(format_md(sv_result, md_cols))

        all_vulns[query] = sv_result

    # Final output
    if fmt == "json":
        json_str = format_json_batch(all_vulns)
        if args.output:
            with open(args.output, "w") as f:
                f.write(json_str)
        else:
            print(json_str)
    elif fmt == "md":
        md_output = "\n\n".join(md_blocks)
        if args.output:
            with open(args.output, "w") as f:
                f.write(md_output)
        else:
            print(md_output)
    elif args.output:
        with open(args.output, "w") as f:
            f.write(out_string)


if __name__ == "__main__":
    main()
