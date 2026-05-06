from typing import Dict

from search_vulns.models.Vulnerability import Vulnerability
from search_vulns.modules.poc_in_github.build import full_update
from search_vulns.modules.utils import (
    extract_all_cve_ids_from_vulns,
    select_from_where_in_to_map,
)


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # Add PoC-in-GitHub exploits

    all_cve_ids = extract_all_cve_ids_from_vulns(vulns)
    cve_exploits_map = select_from_where_in_to_map(
        vuln_db_cursor, "cve_id", "reference", "poc_in_github", "cve_id", all_cve_ids
    )

    for vuln in vulns.values():
        exploits = set()
        for cve_id in vuln.get_all_cve_ids():
            exploits |= cve_exploits_map.get(cve_id, set())
        vuln.add_exploits(exploits)
