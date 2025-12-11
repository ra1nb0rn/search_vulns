import re
from typing import List

from search_vulns.cpe_version import CPEVersion

# implement update procedures in separate file
from search_vulns.modules.ghsa.build import REQUIRES_BUILT_MODULES, full_update
from search_vulns.modules.utils import search_vulns_by_cpes_simple
from search_vulns.vulnerability import MatchReason, Vulnerability

MATCH_GHSA_IDS_RE = re.compile(
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})"
)  # Source: https://github.com/github/advisory-database#ghsa-ids


def get_detailed_vulns(vulns, vuln_db_cursor):
    detailed_vulns = {}
    for vuln_info in vulns:
        vuln_id, match_reason = vuln_info
        if vuln_id in detailed_vulns:
            # update match reason, e.g. if better match happened with another CPE
            if match_reason > detailed_vulns[vuln_id].match_reason:
                detailed_vulns[vuln_id].match_reason = match_reason
            continue

        query = "SELECT aliases, description, published, last_modified, cvss_version, base_score, vector FROM ghsa WHERE ghsa_id = ?"
        vuln_db_cursor.execute(query, (vuln_id,))
        queried_info = vuln_db_cursor.fetchone()
        if queried_info:
            aliases, descr, publ, last_mod, cvss_ver, score, vector = queried_info
        else:
            aliases, publ, last_mod, cvss_ver, vector = [], "", "", "", ""
            score, descr = "-1.0", "NOT FOUND"
            match_reason = MatchReason.N_A
        if cvss_ver:
            cvss_ver = str(float(cvss_ver))
        href = "https://github.com/advisories/" + vuln_id

        if aliases:
            if "," in aliases:
                aliases = aliases.split(",")
            else:
                aliases = [aliases]
            aliases_full = {}
            for alias in aliases:
                if alias.startswith("CVE-"):
                    aliases_full[alias] = "https://nvd.nist.gov/vuln/detail/" + alias
                else:
                    aliases_full[alias] = ""
            aliases = aliases_full
        else:
            aliases = {}
        aliases[vuln_id] = href

        vuln = Vulnerability(
            vuln_id,
            match_reason,
            match_sources=["ghsa"],
            description=descr,
            published=str(publ),
            modified=str(last_mod),
            cvss_ver=cvss_ver,
            cvss=str(float(score)),
            cvss_vec=vector,
            aliases=aliases,
            tracked_by=["ghsa"],
        )
        detailed_vulns[vuln_id] = vuln

    return detailed_vulns


def preprocess_query(query, product_ids, vuln_db_cursor, product_db_cursor, config):
    # extract GHSA-IDs from query and save them for later
    vuln_ids = MATCH_GHSA_IDS_RE.findall(query)
    new_query = query
    for vuln_id in vuln_ids:
        new_query = new_query.replace(vuln_id, "")
    vuln_ids = list(vuln_ids) if vuln_ids else []
    return new_query.strip(), {"ghsa_ids": vuln_ids}


def search_vulns(query, product_ids, vuln_db_cursor, config, extra_params):
    vulns = []
    if product_ids.get("cpe", []):
        # first, get vulns via CPE matching
        vulns = search_vulns_by_cpes_simple(
            product_ids["cpe"], vuln_db_cursor, "ghsa_id", "ghsa_cpe"
        )

    # also get all vulns whose IDs were directly included in the user's query originally
    if "ghsa_ids" in extra_params:
        for vuln_id in extra_params["ghsa_ids"]:
            vulns.append((vuln_id.strip(), MatchReason.VULN_ID))

    # retrieve details for vulns, like description, cvss and more
    if vulns:
        return get_detailed_vulns(vulns, vuln_db_cursor)

    return {}


def add_extra_vuln_info(vulns: List[Vulnerability], vuln_db_cursor, config, extra_params):
    # Add GHSA aliases to vulnerabilities having CVE identifiers
    for vuln_id, vuln in vulns.items():
        if vuln_id.startswith("CVE-") and not any("GHSA-" in alias for alias in vuln.aliases):
            vuln_db_cursor.execute(
                "SELECT ghsa_id FROM ghsa WHERE aliases = ? OR aliases LIKE ?",
                (vuln_id, "%%" + vuln_id + ",%%"),
            )
            for alias in vuln_db_cursor.fetchall():
                alias = alias[0]
                href = "https://github.com/advisories/" + alias
                if alias not in vuln.aliases:
                    vuln.add_alias(alias, href, "ghsa")


def postprocess_results(
    results, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    if "ghsa_ids" in extra_params and extra_params["ghsa_ids"]:
        results["pot_product_ids"] = []
