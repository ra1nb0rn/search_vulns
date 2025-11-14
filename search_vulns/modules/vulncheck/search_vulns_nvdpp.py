from search_vulns.modules.nvd.search_vulns_nvd import get_detailed_vulns
from search_vulns.modules.utils import search_vulns_by_cpes_simple
from search_vulns.modules.vulncheck.build import REQUIRES_BUILT_MODULES, full_update


def search_vulns(query, product_ids, vuln_db_cursor, config, extra_params):

    if product_ids.get("cpe", []):
        # first, get vulns via CPE matching
        vulns = search_vulns_by_cpes_simple(
            product_ids["cpe"], vuln_db_cursor, "cve_id", "vulncheck_nvd_cpe"
        )

        # retrieve details for vulns, like description, cvss and more
        detailed_vulns = get_detailed_vulns(vulns, vuln_db_cursor)
        for cve_id in detailed_vulns:
            detailed_vulns[cve_id].match_sources = ["nvdpp"]
            detailed_vulns[cve_id].tracked_by = ["nvdpp"]

        return detailed_vulns
    else:
        return {}
