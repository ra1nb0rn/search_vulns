"""Interactive REPL: suggest -> pick -> search -> render loop"""

import sys
from typing import Callable

from ..models.SearchVulnsResult import SearchVulnsResult
from .backend import SearchBackend
from .formatters import BOLD, CYAN, DIM, GREEN, RED, SANE, score_bar

_QUIT_WORDS = {"q", "quit", "exit"}


# ------------------------------------------------ helpers
def _prompt(text: str) -> str:
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "q"


def _gather_suggestions(sv_result: SearchVulnsResult) -> list:
    items, collected_pids = [], set()
    # gather all potential IDs, which may include matched IDs
    for cpe, score in sv_result.pot_product_ids.cpe:
        if cpe not in collected_pids:
            items.append((cpe, abs(score), "cpe"))
            collected_pids.add(cpe)
    for purl, score in sv_result.pot_product_ids.purl:
        if purl not in collected_pids:
            items.append((purl, abs(score), "purl"))
            collected_pids.add(purl)
    for raw, score in sv_result.pot_product_ids.raw:
        if raw not in collected_pids:
            items.append((raw, abs(score), "raw"))
            collected_pids.add(raw)

    # add matched IDs not already collected
    for cpe in sv_result.product_ids.cpe:
        if cpe not in collected_pids:
            items.append((cpe, 1.0, "cpe"))
            collected_pids.add(cpe)
    for purl in sv_result.product_ids.purl:
        if purl not in collected_pids:
            items.append((purl, 1.0, "purl"))
            collected_pids.add(cpe)
    for raw in sv_result.product_ids.raw:
        if raw not in collected_pids:
            items.append((raw, 1.0, "raw"))
            collected_pids.add(cpe)

    items.sort(key=lambda x: x[1], reverse=True)
    return items


def _pick_from_menu(items: list) -> str | None:
    if not items:
        return None

    print(f"\n{BOLD}{CYAN}── Product IDs ──{SANE}\n")

    for idx, (identifier, score, kind) in enumerate(items, 1):
        print(f"  {BOLD}{idx:>3}{SANE})  {score_bar(score)}  [{kind}] {identifier}")

    print(f"\n  {DIM}  0)  ← skip / new query{SANE}")
    print()

    while True:
        raw = _prompt(f"{BOLD}Select [0–{len(items)}]:{SANE} ")
        if raw.lower() in _QUIT_WORDS:
            return None
        if not raw:
            continue
        try:
            choice = int(raw)
        except ValueError:
            print(f"  {RED}Please enter a number.{SANE}")
            continue
        if choice == 0:
            return None
        if 1 <= choice <= len(items):
            selected = items[choice - 1][0]
            print(f"\n{GREEN}Selected:{SANE} {BOLD}{selected}{SANE}\n")
            return selected
        print(f"  {RED}Out of range.{SANE}")


# ------------------------------------------------ main loop
def run_interactive_loop(
    backend: SearchBackend,
    *,
    seed_queries: list | None = None,
    render_result: Callable[[str, SearchVulnsResult], None],
    search_kwargs: dict,
):
    pending = list(seed_queries or [])

    while True:
        if pending:
            query = pending.pop(0)
            print(f"\n{DIM}Query:{SANE} {BOLD}{query}{SANE}")
        else:
            query = _prompt(f"\n{BOLD}Enter query{SANE} ({DIM}q to quit{SANE}): ")
            if query.lower() in _QUIT_WORDS:
                break
            if not query:
                continue

        print(f"{DIM}Searching suggestions...{SANE}", file=sys.stderr)
        sv_suggest = backend.suggest(query)
        items = _gather_suggestions(sv_suggest)

        if not items:
            print(f"{RED}No product IDs found for '{query}'.{SANE}")
            continue

        selected = _pick_from_menu(items)
        if selected is None:
            continue

        print(f"{DIM}Searching vulnerabilities...{SANE}", file=sys.stderr)
        is_good, sv_result = backend.search(selected, is_good_product_id=True, **search_kwargs)

        if not is_good:
            print(f"{RED}No results for '{selected}'.{SANE}")
            continue

        render_result(query, sv_result)
