from typing import Dict

from search_vulns.models.SearchVulnsResult import ProductIDsResult
from search_vulns.models.Vulnerability import DataSource, Match, Vulnerability
from search_vulns.modules.nvd.search_vulns_nvd import get_detailed_vulns
from search_vulns.modules.utils import search_vulns_by_cpes_simple
from search_vulns.modules.vulncheck.build import REQUIRES_BUILT_MODULES, full_update

VULN_TRACK_BASE_URL = "https://api.vulncheck.com/v3/index/nist-nvd2?cve="


def search_vulns(
    query, product_ids: ProductIDsResult, vuln_db_cursor, config, extra_params
) -> Dict[str, Vulnerability]:

    if product_ids.cpe:
        # get vulns via CPE matching
        vulns = search_vulns_by_cpes_simple(
            product_ids.cpe, vuln_db_cursor, "cve_id", "vulncheck_nvd_cpe"
        )

        # retrieve details for vulns, like description, cvss and more
        detailed_vulns = get_detailed_vulns(vulns, vuln_db_cursor)
        for cve_id in detailed_vulns:
            detailed_vulns[cve_id].remove_matched_by(DataSource.NVD)
            detailed_vulns[cve_id].remove_tracked_by(DataSource.NVD)
            vuln_match = Match(match_reason=detailed_vulns[cve_id].match_reason, confidence=1)
            detailed_vulns[cve_id].add_matched_by(DataSource.NVDPP, vuln_match)
            detailed_vulns[cve_id].add_tracked_by(
                DataSource.NVDPP, VULN_TRACK_BASE_URL + cve_id
            )

        return detailed_vulns
    else:
        return {}


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    # check and append tracking information
    for vuln_id, vuln in vulns.items():
        # get all CVE IDs
        vuln_cve_ids = set()
        if vuln_id.startswith("CVE-"):
            vuln_cve_ids.add(vuln_id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                vuln_cve_ids.add(alias)

        in_str = ""
        for cve_id in vuln_cve_ids:
            in_str += "%s," % cve_id
        in_str = in_str[:-1]  # remove last comma

        if DataSource.NVDPP not in vuln.tracked_by and in_str:
            vuln_db_cursor.execute(
                "SELECT COUNT(*) FROM vulncheck_nvd_cpe WHERE cve_id IN (?)", (in_str,)
            )
            count = vuln_db_cursor.fetchone()
            if count and int(count[0]) > 0:
                # add track reference
                vuln.add_tracked_by(DataSource.NVDPP, VULN_TRACK_BASE_URL + vuln_id)
