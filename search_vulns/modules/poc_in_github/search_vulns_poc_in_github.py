from typing import List

from search_vulns.modules.poc_in_github.build import full_update
from search_vulns.vulnerability import Vulnerability


def add_extra_vuln_info(vulns: List[Vulnerability], vuln_db_cursor, config, extra_params):
    for vuln_id, vuln in vulns.items():
        vuln_cve_ids = set()
        if vuln_id.startswith("CVE-"):
            vuln_cve_ids.add(vuln_id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                vuln_cve_ids.add(alias)

        exploits = set()
        for cve_id in vuln_cve_ids:
            vuln_db_cursor.execute(
                "SELECT reference FROM poc_in_github WHERE cve_id = ?", (cve_id,)
            )
            if vuln_db_cursor:
                poc_in_github_refs = [ref[0] for ref in vuln_db_cursor.fetchall()]
                exploits |= set(poc_in_github_refs)
        vuln.add_exploits(exploits)
