"""Provides txt, ansi, md, and json output formats"""

import json
import re
from typing import Dict, Optional

from .models.SearchVulnsResult import SearchVulnsResult
from .models.Vulnerability import Vulnerability

SANE = "\033[0m"
GREEN = "\033[32m"
BRIGHT_GREEN = "\033[32;1m"
RED = "\033[31m"
YELLOW = "\033[33m"
BRIGHT_BLUE = "\033[34;1m"
MAGENTA = "\033[35m"
BRIGHT_CYAN = "\033[36;1m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"

DEDUP_LINEBREAKS_RE_1 = re.compile(r"(\r\n)+")
DEDUP_LINEBREAKS_RE_2 = re.compile(r"\n+")

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

ALLOWED_MD_COLS = ("id", "cvss", "description", "epss", "cwe", "exploits")
DEFAULT_MD_COLS = ("id", "cvss", "description")

_MD_COL_HEADERS = {
    "id": "Vuln ID",
    "cvss": "CVSS",
    "description": "Description",
    "epss": "EPSS",
    "cwe": "CWE",
    "exploits": "Exploits",
}

_MD_COL_ALIGN = {
    "id": ":---:",
    "cvss": ":---:",
    "description": ":---",
    "epss": ":---:",
    "cwe": ":---:",
    "exploits": ":---:",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ------------------------------------------------ helpers
def printit(text: str = "", end: str = "\n", color=SANE):
    """Small print wrapper with ANSI colour support."""
    import sys

    print(color, end="")
    print(text, end=end)
    if color != SANE:
        print(SANE, end="")
    sys.stdout.flush()


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _cvss_color(severity: str, color: bool = True) -> str:
    if not color:
        return ""
    return {
        "CRITICAL": RED,
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": GREEN,
    }.get(severity, DIM)


def _ansi(value: str, color: bool) -> str:
    if color:
        return value
    return ""


def _md_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\").replace("|", "\\|").replace("\r\n", " ").replace("\n", " ")
    )


def _parse_cpe(cpe: str) -> tuple:
    parts = cpe.split(":")
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    version = parts[5] if len(parts) > 5 else ""
    product = product.replace("_", " ").title()
    vendor = vendor.replace("_", " ").title()
    return vendor, product, version


def parse_md_cols(raw: str) -> list:
    cols = []
    for col in raw.split(","):
        col = col.strip().lower()
        if not col:
            continue
        if col not in ALLOWED_MD_COLS:
            raise ValueError(
                f"Unknown markdown column '{col}'. Allowed: {', '.join(ALLOWED_MD_COLS)}"
            )
        if col not in cols:
            cols.append(col)
    if not cols:
        return list(DEFAULT_MD_COLS)
    return cols


def sort_and_cap_vulns(
    vulns: Dict[str, Vulnerability], max_count: Optional[int]
) -> Dict[str, Vulnerability]:
    if not vulns:
        return {}

    def sort_key(vuln_id):
        v = vulns[vuln_id]
        cvss = float(v.get_cvss_score())
        epss_raw = v.get_epss_score()
        epss = float(epss_raw) if epss_raw not in (None, "-1") else 0.0
        return (-cvss, -epss, vuln_id)

    sorted_ids = sorted(vulns.keys(), key=sort_key)

    if max_count is not None:
        sorted_ids = sorted_ids[:max_count]

    return {vid: vulns[vid] for vid in sorted_ids}


def score_bar(score: float, width: int = 12) -> str:
    score = abs(score)
    normalised = min(score, 1.0)
    filled = round(normalised * width)
    if score >= 0.6:
        colour = GREEN
    elif score >= 0.2:
        colour = YELLOW
    else:
        colour = RED
    bar = f"{colour}{'█' * filled}{DIM}{'░' * (width - filled)}{SANE}"
    return f"{bar} {colour}{score:+.2f}{SANE}"


# ------------------------------------------------ txt
def print_vulns(vulns: Dict[str, Vulnerability], to_string: bool = False) -> Optional[str]:
    out_string = ""
    vuln_ids_sorted = sorted(
        list(vulns), key=lambda vid: vulns[vid].get_cvss_score(), reverse=True
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
                + str(vuln_node.get_cvss_version())
                + "/"
                + str(vuln_node.get_cvss_score())
                + SANE
                + ")"
            )
            if vuln_node.cisa_kev:
                print_str += " (" + RED + "Actively exploited" + SANE + ")"
        else:
            print_str = vuln_node.id
            print_str += (
                " ("
                "CVSSv"
                + vuln_node.get_cvss_version()
                + "/"
                + str(vuln_node.get_cvss_score())
                + ")"
            )
            if vuln_node.cisa_kev:
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
        if vuln_node.published:
            print_str += ", " + vuln_node.published.strftime("%Y-%m-%d")
        if not to_string:
            printit(print_str)
        else:
            out_string += print_str + "\n"

    if to_string:
        return out_string


# ------------------------------------------------ ansi
def _format_version_status(version_status, color: bool = True) -> str:
    if not version_status or not version_status.status:
        return ""

    status = (
        version_status.status.value
        if hasattr(version_status.status, "value")
        else str(version_status.status)
    )
    if status == "N/A":
        return ""

    status_color = {
        "EOL": YELLOW,
        "OUTDATED": YELLOW,
        "CURRENT": GREEN,
    }.get(status, DIM)

    parts = [
        f"{_ansi(BOLD, color)}Status:{_ansi(SANE, color)} {_ansi(status_color, color)}{status}{_ansi(SANE, color)}"
    ]
    if version_status.latest:
        parts.append(f"{_ansi(BOLD, color)}Latest:{_ansi(SANE, color)} {version_status.latest}")
    if version_status.reference:
        parts.append(f"{_ansi(DIM, color)}{version_status.reference}{_ansi(SANE, color)}")

    return f"\n  {'  |  '.join(parts)}\n"


def _format_vuln_table(vulns: Dict[str, Vulnerability], color: bool = True) -> str:
    if not vulns:
        return f"  {_ansi(GREEN, color)}No vulnerabilities found.{_ansi(SANE, color)}\n"

    rows = []
    for vid, vuln in vulns.items():
        cvss = float(vuln.get_cvss_score())
        epss_raw = vuln.get_epss_score()
        epss = float(epss_raw) if epss_raw not in (None, "-1") else 0.0
        severity = _cvss_severity(cvss)
        sev_order = _SEVERITY_ORDER.get(severity, 99)

        cvss_str = f"{cvss:.1f}"
        cvss_ver = vuln.get_cvss_version()
        if cvss_ver and str(cvss_ver) != "-1":
            cvss_str += f"v{cvss_ver}"

        epss_str = f"{epss:.2f}" if epss > 0 else "-"
        published = vuln.published.strftime("%Y-%m-%d") if vuln.published else ""
        desc = vuln.description or ""
        if len(desc) > 60:
            desc = desc[:57] + "..."

        badges = ""
        if vuln.cisa_kev:
            badges += f" {_ansi(RED, color)}KEV{_ansi(SANE, color)}"
        if vuln.exploits:
            badges += f" {_ansi(MAGENTA, color)}EXP x{len(vuln.exploits)}{_ansi(SANE, color)}"

        sev_color = _cvss_color(severity, color)
        sane = _ansi(SANE, color)
        line = (
            f"  {sev_color}{vid:<20}{sane} "
            f"{sev_color}{cvss_str:>7}{sane}  "
            f"{epss_str:>5}  {published:<10}  {desc}{badges}"
        )
        rows.append((sev_order, -cvss, vid, line))

    rows.sort(key=lambda r: (r[0], r[1], r[2]))

    bold = _ansi(BOLD, color)
    sane = _ansi(SANE, color)
    lines = [
        f"  {bold}{'ID':<20} {'CVSS':>7}  {'EPSS':>5}  {'Published':<10}  Description{sane}",
        f"  {'─' * 78}",
    ]

    sev_names = {v: k for k, v in _SEVERITY_ORDER.items()}
    current_sev = -1
    for sev_order, _, _, line in rows:
        if sev_order != current_sev:
            current_sev = sev_order
            label = sev_names.get(sev_order, "OTHER")
            lines.append(f"\n  {bold}{_cvss_color(label, color)}── {label} ──{sane}")
        lines.append(line)

    lines.append("")
    return "\n".join(lines)


def format_ansi(query: str, sv_result: SearchVulnsResult, color: bool = True) -> str:
    bold = _ansi(BOLD, color)
    bright_blue = _ansi(BRIGHT_BLUE, color)
    sane = _ansi(SANE, color)

    parts = []

    all_pids = sv_result.product_ids.get_all()
    pid_str = "/".join(all_pids) if all_pids else "no product IDs"
    parts.append(f"{bright_blue}[+] {query} ({pid_str}){sane}")

    vs_str = _format_version_status(sv_result.version_status, color)
    if vs_str:
        parts.append(vs_str)

    n = len(sv_result.vulns)
    parts.append(f"\n  {bold}{n} vulnerabilit{'y' if n == 1 else 'ies'} found{sane}\n")
    parts.append(_format_vuln_table(sv_result.vulns, color))

    return "\n".join(parts)


# ------------------------------------------------ md
def _md_frontmatter(sv_result: SearchVulnsResult) -> str:
    cpes = sv_result.product_ids.cpe
    if cpes:
        cpe = cpes[0]
        _, product, version = _parse_cpe(cpe)
    else:
        cpe = ""
        product = ""
        version = ""

    lines = [
        "---",
        f'cpe: "{cpe}"',
        f'product: "{product}"',
        f'version: "{version}"',
        "---",
        "",
    ]
    return "\n".join(lines)


def _md_cell(vuln: Vulnerability, col: str) -> str:
    if col == "id":
        ref = vuln.aliases.get(vuln.id, "")
        if ref:
            return f"[{_md_escape(vuln.id)}]({ref})"
        return _md_escape(vuln.id)

    if col == "cvss":
        cvss = float(vuln.get_cvss_score())
        if cvss < 0:
            return "-"
        ver = vuln.get_cvss_version()
        if ver and str(ver) != "-1":
            return f"{cvss} (v{ver})"
        return str(cvss)

    if col == "description":
        return _md_escape(vuln.description or "")

    if col == "epss":
        epss_raw = vuln.get_epss_score()
        epss = float(epss_raw) if epss_raw not in (None, "-1") else 0.0
        if epss > 0:
            return f"{epss:.2f}"
        return "-"

    if col == "cwe":
        if vuln.cwe_ids:
            return ", ".join(sorted(vuln.cwe_ids))
        return "-"

    if col == "exploits":
        if vuln.exploits:
            return str(len(vuln.exploits))
        return "-"

    return "-"


def format_md(sv_result: SearchVulnsResult, cols: list) -> str:
    parts = [_md_frontmatter(sv_result)]

    headers = [_MD_COL_HEADERS.get(c, c) for c in cols]
    aligns = [_MD_COL_ALIGN.get(c, ":---") for c in cols]

    parts.append("| " + " | ".join(headers) + " |")
    parts.append("| " + " | ".join(aligns) + " |")

    sorted_vulns = sort_and_cap_vulns(sv_result.vulns, None)
    for vid in sorted_vulns:
        vuln = sorted_vulns[vid]
        cells = [_md_cell(vuln, c) for c in cols]
        parts.append("| " + " | ".join(cells) + " |")

    return "\n".join(parts)


# ------------------------------------------------ json
def format_json_batch(all_results: dict) -> str:
    serializable = {}
    for query, result in all_results.items():
        if isinstance(result, SearchVulnsResult):
            serializable[query] = result.model_dump(exclude_none=True)
        else:
            serializable[query] = result
    return json.dumps(serializable)
