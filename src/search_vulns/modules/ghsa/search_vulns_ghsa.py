import re
from datetime import datetime
from typing import Dict, Tuple

from search_vulns.models.SearchVulnsResult import (
    PotProductIDsResult,
    ProductIDsResult,
    SearchVulnsResult,
)
from search_vulns.models.Severity import SeverityCVSS
from search_vulns.models.Vulnerability import DataSource, MatchReason, Vulnerability

# implement update procedures in separate file
from search_vulns.modules.ghsa.build import REQUIRES_BUILT_MODULES, full_update
from search_vulns.modules.utils import (
    search_vulns_by_cpes_simple,
    select_from_where_in_to_map,
)

MATCH_GHSA_IDS_RE = re.compile(
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})"
)  # Source: https://github.com/github/advisory-database#ghsa-ids
VULN_TRACK_BASE_URL = "https://github.com/advisories/"
ALIAS_SEARCH_BATCH_SIZE = 999


def get_detailed_vulns(vulns: Dict[str, Vulnerability], vuln_db_cursor):
    detailed_vulns = {}
    ghsa_ids = [vuln[0] for vuln in vulns]
    ghsa_data_map = select_from_where_in_to_map(
        vuln_db_cursor,
        "ghsa_id",
        [
            "description",
            "published",
            "last_modified",
            "cvss_version",
            "base_score",
            "vector",
            "cwe_ids",
        ],
        "ghsa",
        "ghsa_id",
        ghsa_ids,
    )
    ghsa_aliases = select_from_where_in_to_map(
        vuln_db_cursor, "ghsa_id", "alias", "ghsa_aliases", "ghsa_id", ghsa_ids
    )

    for vuln_info in vulns:
        vuln_id, match_reason = vuln_info
        if vuln_id in detailed_vulns:
            # update match reason, e.g. if better match happened with another CPE
            if match_reason > detailed_vulns[vuln_id].match_reason:
                detailed_vulns[vuln_id].match_reason = match_reason
            continue

        # complete vuln data
        queried_info = next(iter(ghsa_data_map[vuln_id]))
        if queried_info:
            descr, publ, last_mod, cvss_ver, score, vector, cwe_ids = queried_info
        else:
            publ, last_mod, cvss_ver, vector, cwe_ids = [], "", "", "", "", ""
            score, descr = "-1.0", "NOT FOUND"
            match_reason = MatchReason.N_A
        if cvss_ver:
            cvss_ver = str(float(cvss_ver))
        href = VULN_TRACK_BASE_URL + vuln_id

        if publ and not isinstance(publ, datetime):
            # sqlite returns a simple string instead of a datetime object
            publ = datetime.strptime(publ, "%Y-%m-%d %H:%M:%S")
        if last_mod and not isinstance(last_mod, datetime):
            last_mod = datetime.strptime(last_mod, "%Y-%m-%d %H:%M:%S")
        if cwe_ids:
            cwe_ids = cwe_ids.split(",")
        else:
            cwe_ids = []

        # complete aliases
        aliases_full = {vuln_id: href}
        for alias in ghsa_aliases.get(vuln_id, []):
            if alias.startswith("CVE-"):
                aliases_full[alias] = "https://nvd.nist.gov/vuln/detail/" + alias
            else:
                aliases_full[alias] = ""
        aliases = aliases_full

        # create detailed vuln from data above
        if float(score) < 0:
            severity = None
        else:
            severity = SeverityCVSS(score=str(float(score)), version=cvss_ver, vector=vector)
        vuln = Vulnerability.from_vuln_match_complete(
            vuln_id,
            match_reason,
            DataSource.GHSA,
            href,
            href,
            descr,
            publ,
            last_mod,
            severity,
            cwe_ids,
            False,
            [],
        )
        vuln.set_aliases(aliases)
        detailed_vulns[vuln_id] = vuln

    return detailed_vulns


def preprocess_query(
    query, product_ids: ProductIDsResult, vuln_db_cursor, product_db_cursor, config
) -> Tuple[str, Dict]:
    # extract GHSA-IDs from query and save them for later
    vuln_ids = MATCH_GHSA_IDS_RE.findall(query)
    new_query = query
    for vuln_id in vuln_ids:
        new_query = new_query.replace(vuln_id, "")
    vuln_ids = list(vuln_ids) if vuln_ids else []
    return new_query.strip(), {"ghsa_ids": vuln_ids}


def search_vulns(
    query, product_ids: ProductIDsResult, vuln_db_cursor, config, extra_params
) -> Dict[str, Vulnerability]:
    vulns = []
    if product_ids.cpe:
        # first, get vulns via CPE matching
        vulns = search_vulns_by_cpes_simple(
            product_ids.cpe, vuln_db_cursor, "ghsa_id", "ghsa_cpe"
        )

    # also get all vulns whose IDs were directly included in the user's query originally
    if "ghsa_ids" in extra_params:
        for vuln_id in extra_params["ghsa_ids"]:
            vulns.append((vuln_id.strip(), MatchReason.VULN_ID))

    # retrieve details for vulns, like description, cvss and more
    if vulns:
        return get_detailed_vulns(vulns, vuln_db_cursor)

    return {}


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # Add GHSA aliases to vulnerabilities having CVE identifiers

    # gather all cve_ids
    all_cve_ids = set()
    for vuln in vulns.values():
        all_cve_ids |= vuln.get_all_cve_ids()

    # create cve_id --> ghsa_id map
    cve_ghsa_map = select_from_where_in_to_map(
        vuln_db_cursor, "alias", "ghsa_id", "ghsa_aliases", "alias", all_cve_ids
    )

    # add GHSA aliases
    for vuln_id, vuln in vulns.items():
        for alias in vuln.aliases | {vuln.id: ""}:
            for ghsa_id in cve_ghsa_map.get(alias, []):
                if ghsa_id not in vuln.aliases:
                    href = VULN_TRACK_BASE_URL + ghsa_id
                    vuln.add_tracked_by_with_alias(DataSource.GHSA, href, ghsa_id)


def postprocess_results(
    results: SearchVulnsResult, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    if "ghsa_ids" in extra_params and extra_params["ghsa_ids"]:
        results.pot_product_ids = PotProductIDsResult()
