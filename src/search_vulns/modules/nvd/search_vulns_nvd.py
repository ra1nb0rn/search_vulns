import re
from typing import List

from search_vulns.cpe_version import CPEVersion

# implement update procedures in separate file
from search_vulns.modules.nvd.build import REQUIRES_BUILT_MODULES, full_update, install
from search_vulns.modules.utils import search_vulns_by_cpes_simple
from search_vulns.vulnerability import MatchReason, Vulnerability

MATCH_CVE_IDS_RE = re.compile(
    r"(CVE-[0-9]{4}-[0-9]{4,19})"
)  # Source: https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_cveMetadata_cveId
DESCR_VERSION_MATCH_RE = re.compile(r"\d\.[\d\w\.]+")


def get_detailed_vulns(vulns, vuln_db_cursor):
    detailed_vulns = {}
    for vuln_info in vulns:
        vuln_id, match_reason = vuln_info
        if vuln_id in detailed_vulns:
            # update match reason, e.g. if better match happened with another CPE
            if match_reason > detailed_vulns[vuln_id].match_reason:
                detailed_vulns[vuln_id].match_reason = match_reason
            continue

        query = "SELECT description, published, last_modified, cvss_version, base_score, vector, cisa_known_exploited FROM nvd WHERE cve_id = ?"
        vuln_db_cursor.execute(query, (vuln_id,))
        queried_info = vuln_db_cursor.fetchone()
        if queried_info:
            descr, publ, last_mod, cvss_ver, score, vector, cisa_known_exploited = queried_info
        else:
            publ, last_mod, cvss_ver, vector, cisa_known_exploited = "", "", "", "", False
            score, descr = "-1.0", "NOT FOUND"
            match_reason = MatchReason.N_A
        if cvss_ver:
            cvss_ver = str(float(cvss_ver))
        href = "https://nvd.nist.gov/vuln/detail/" + vuln_id

        vuln = Vulnerability(
            vuln_id,
            match_reason,
            match_sources=["nvd"],
            description=descr,
            published=str(publ),
            modified=str(last_mod),
            cvss_ver=cvss_ver,
            cvss=str(float(score)),
            cvss_vec=vector,
            cisa_known_exploited=bool(cisa_known_exploited),
            aliases={vuln_id: href},
            tracked_by=["nvd"],
        )
        detailed_vulns[vuln_id] = vuln

    return detailed_vulns


def preprocess_query(query, product_ids, vuln_db_cursor, product_db_cursor, config):
    # extract CVE-IDs from query and save them for later
    vuln_ids = MATCH_CVE_IDS_RE.findall(query)
    new_query = query
    for vuln_id in vuln_ids:
        new_query = new_query.replace(vuln_id, "")
    vuln_ids = list(vuln_ids) if vuln_ids else []
    return new_query.strip(), {"cve_ids": vuln_ids}


def search_vulns(query, product_ids, vuln_db_cursor, config, extra_params):

    vulns = []
    if product_ids.get("cpe", []):
        # first, get vulns via CPE matching
        vulns = search_vulns_by_cpes_simple(
            product_ids["cpe"], vuln_db_cursor, "cve_id", "nvd_cpe"
        )

        # second, try basic text comparison with NVD descriptions to alleviate
        # problem with missing CPEs in newer CVEs
        for cpe in product_ids["cpe"]:
            cpe_parts = cpe.split(":")
            cpe_version = CPEVersion(cpe_parts[5])
            # limit for performance reasons and because the result already has a lot of vulns anyways
            if cpe_version and len(vulns) < 500:
                product = cpe_parts[4]
                descr_beginnings = [
                    "%s before %%" % product,
                    "in %s before %%" % product,
                    "%s through %%" % product,
                    "in %s through %%" % product,
                    "%s %% and earlier %%" % product,
                ]
                descr_beginnings_where = " OR description LIKE ?" * (len(descr_beginnings) - 1)
                vuln_db_cursor.execute(
                    'SELECT cve_id, description FROM nvd WHERE (cve_id LIKE "CVE-202%%") '
                    + "AND (description LIKE ?%s )" % descr_beginnings_where,
                    descr_beginnings,
                )
                pot_cves = vuln_db_cursor.fetchall()
                for cve_id, descr in pot_cves:
                    version = None
                    version_beginning = re.search(
                        r"^(in )? *" + product + r" +(before|through) (\d\.?[\da-z\.]*)",
                        descr,
                        re.IGNORECASE,
                    )
                    if version_beginning:
                        version = version_beginning.group(3)
                    if not version_beginning:
                        version_beginning = re.search(
                            r"^" + product + r" +(\d\.?[\da-z\.]*) and earlier",
                            descr,
                            re.IGNORECASE,
                        )
                        if version_beginning:
                            version = version_beginning.group(1)
                    if version and DESCR_VERSION_MATCH_RE.match(version):
                        if cpe_version < CPEVersion(version):
                            vulns.append((cve_id, MatchReason.DESCRIPTION_MATCH))

    # also get all vulns whose IDs were directly included in the user's query originally
    if "cve_ids" in extra_params:
        for vuln_id in extra_params["cve_ids"]:
            vulns.append((vuln_id.strip(), MatchReason.VULN_ID))

    # retrieve details for vulns, like description, cvss and more
    if vulns:
        return get_detailed_vulns(vulns, vuln_db_cursor)

    return {}


def add_extra_vuln_info(vulns: List[Vulnerability], vuln_db_cursor, config, extra_params):
    for vuln_id, vuln in vulns.items():
        vuln_cve_ids = set()
        if vuln_id.startswith("CVE-"):
            vuln_cve_ids.add(vuln_id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                vuln_cve_ids.add(alias)

        for cve_id in vuln_cve_ids:
            query = "SELECT exploit_ref FROM nvd_exploits_refs_view WHERE cve_id = ?"
            nvd_exploit_refs = ""
            vuln_db_cursor.execute(query, (cve_id,))
            if vuln_db_cursor:
                nvd_exploit_refs = vuln_db_cursor.fetchall()
            vuln.add_exploits([exploit[0] for exploit in nvd_exploit_refs])


def postprocess_results(
    results, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    if "cve_ids" in extra_params and extra_params["cve_ids"]:
        results["pot_product_ids"] = []
