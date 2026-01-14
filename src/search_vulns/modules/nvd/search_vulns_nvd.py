import re
from datetime import datetime
from typing import Dict, Tuple

from search_vulns.models.CPEVersion import CPEVersion
from search_vulns.models.SearchVulnsResult import (
    PotProductIDsResult,
    ProductIDsResult,
    SearchVulnsResult,
)
from search_vulns.models.Severity import SeverityCVSS
from search_vulns.models.Vulnerability import DataSource, MatchReason, Vulnerability

# implement update procedures in separate file
from search_vulns.modules.nvd.build import REQUIRES_BUILT_MODULES, full_update, install
from search_vulns.modules.utils import search_vulns_by_cpes_simple

MATCH_CVE_IDS_RE = re.compile(
    r"(CVE-[0-9]{4}-[0-9]{4,19})"
)  # Source: https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_cveMetadata_cveId
DESCR_VERSION_MATCH_RE = re.compile(r"\d\.[\d\w\.]+")
VULN_TRACK_BASE_URL = "https://nvd.nist.gov/vuln/detail/"


def get_detailed_vuln_data(vuln_id, vuln_db_cursor):
    query = "SELECT description, published, last_modified, cvss_version, base_score, vector, cwe_ids, cisa_known_exploited FROM nvd WHERE cve_id = ?"
    vuln_db_cursor.execute(query, (vuln_id,))
    queried_info = vuln_db_cursor.fetchone()
    if queried_info:
        descr, publ, last_mod, cvss_ver, score, vector, cwe_ids, cisa_known_exploited = (
            queried_info
        )
    else:
        publ, last_mod, cvss_ver, vector, cwe_ids, cisa_known_exploited = (
            "",
            "",
            "",
            "",
            "",
            False,
        )
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

    if float(score) < 0:
        severity = None
    else:
        severity = SeverityCVSS(score=str(float(score)), version=cvss_ver, vector=vector)
    cisa_known_exploited = bool(cisa_known_exploited)

    return descr, publ, last_mod, severity, cwe_ids, cisa_known_exploited, href


def get_detailed_vulns(vulns, vuln_db_cursor) -> Dict[str, Vulnerability]:
    detailed_vulns = {}
    for vuln_info in vulns:
        vuln_id, match_reason = vuln_info
        if vuln_id in detailed_vulns:
            # update match reason, e.g. if better match happened with another CPE
            if match_reason > detailed_vulns[vuln_id].match_reason:
                detailed_vulns[vuln_id].match_reason = match_reason
            continue

        descr, publ, last_mod, severity, cwe_ids, cisa_known_exploited, href = (
            get_detailed_vuln_data(vuln_id, vuln_db_cursor)
        )
        vuln = Vulnerability.from_vuln_match_complete(
            vuln_id,
            match_reason,
            DataSource.NVD,
            href,
            href,
            descr,
            publ,
            last_mod,
            severity,
            cwe_ids,
            cisa_known_exploited,
            [],
        )
        detailed_vulns[vuln_id] = vuln

    return detailed_vulns


def preprocess_query(
    query, product_ids: ProductIDsResult, vuln_db_cursor, product_db_cursor, config
) -> Tuple[str, Dict]:
    # extract CVE-IDs from query and save them for later
    vuln_ids = MATCH_CVE_IDS_RE.findall(query)
    new_query = query
    for vuln_id in vuln_ids:
        new_query = new_query.replace(vuln_id, "")
    vuln_ids = list(vuln_ids) if vuln_ids else []
    return new_query.strip(), {"cve_ids": vuln_ids}


def search_vulns(
    query, product_ids: ProductIDsResult, vuln_db_cursor, config, extra_params
) -> Dict[str, Vulnerability]:
    vulns = []
    if product_ids.cpe:
        # first, get vulns via CPE matching
        vulns = search_vulns_by_cpes_simple(
            product_ids.cpe, vuln_db_cursor, "cve_id", "nvd_cpe"
        )

        # second, try basic text comparison with NVD descriptions to alleviate
        # problem with missing CPEs in newer CVEs
        for cpe in product_ids.cpe:
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


def add_extra_vuln_info(vulns: Dict[str, Vulnerability], vuln_db_cursor, config, extra_params):
    for vuln_id, vuln in vulns.items():
        # get all CVE IDs
        vuln_cve_ids = set()
        if vuln_id.startswith("CVE-"):
            vuln_cve_ids.add(vuln_id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                vuln_cve_ids.add(alias)

        # add exploits and check tracking information
        in_str = ""
        for cve_id in vuln_cve_ids:
            query = "SELECT exploit_ref FROM nvd_exploits_refs_view WHERE cve_id = ?"
            nvd_exploit_refs = ""
            vuln_db_cursor.execute(query, (cve_id,))
            if vuln_db_cursor:
                nvd_exploit_refs = vuln_db_cursor.fetchall()
            vuln.add_exploits([exploit[0] for exploit in nvd_exploit_refs])
            in_str += "%s," % cve_id
        in_str = in_str[:-1]  # remove last comma or opening parenthesis

        if DataSource.NVD not in vuln.tracked_by and in_str:
            vuln_db_cursor.execute(
                "SELECT COUNT(*) FROM nvd_cpe WHERE cve_id IN (?)", (in_str,)
            )
            count = vuln_db_cursor.fetchone()
            if count and int(count[0]) > 0:
                # add track reference
                vuln.add_tracked_by(
                    DataSource.NVD, VULN_TRACK_BASE_URL + next(iter(vuln_cve_ids))
                )

        # add general vuln info if not present
        for cve_id in vuln_cve_ids:
            query = "SELECT description, published, last_modified, cvss_version, base_score, vector, cwe_ids, cisa_known_exploited FROM nvd WHERE cve_id = ?"
            vuln_db_cursor.execute(query, (vuln_id,))
            queried_info = vuln_db_cursor.fetchone()

            if queried_info:
                description, published, modified, severity, cwe_ids, cisa_kev, href = (
                    get_detailed_vuln_data(cve_id, vuln_db_cursor)
                )

                for attr in ("description", "published", "modified", "cwe_ids", "cisa_kev"):
                    if not (getattr(vuln, attr)):
                        setattr(vuln, attr, locals()[attr])

                if severity and severity.type not in vuln.severity:
                    vuln.add_severity(severity)

            if cve_id not in vuln.aliases:
                vuln.add_alias(cve_id, href)


def postprocess_results(
    results: SearchVulnsResult, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    if "cve_ids" in extra_params and extra_params["cve_ids"]:
        results.pot_product_ids = PotProductIDsResult()
