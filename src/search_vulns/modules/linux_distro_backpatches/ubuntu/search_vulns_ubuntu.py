import re
from threading import Lock

from cpe_search.cpe_search import MATCH_CPE_23_RE
from univers.versions import DebianVersion

from search_vulns.modules.linux_distro_backpatches.ubuntu.build import (
    REQUIRES_BUILT_MODULES,
    full_update,
)
from search_vulns.modules.linux_distro_backpatches.utils import (
    SPLIT_QUERY_TERMS_RE,
    extract_vendor_version,
    strip_epoch_from_version,
)
from search_vulns.modules.utils import get_cpe_product_prefix, split_cpe

CODENAME_RELEASE_NUMBER_MAP = {}
UBUNTU_RELEASE_NUMBERS = []
UBUNTU_FULL_VERSION_EXTRACT_RE = re.compile(r"(\d\S*[._:\+~\-]\S+)|(-\S+)")
REMOVE_UBUNTU_BETWEEN_VERSIONS_IN_QUERY_RE = re.compile(r"(\d) +ubuntu +(\d)")
REMOVE_UBUNTU_IN_QUERY_RE = re.compile(r"[\(\[\s]*ubuntu[\)\]\s]*")
UBUNTU_VERSION_BEFORE_SOFTWARE_RE = re.compile(r"^([\d\.]+)[- +_](\w+)(.*)")
INIT_LOCK = Lock()


############################################################################################
### Created with help of original connector to Ubuntu API by https://github.com/MRuppDev ###
############################################################################################


def init(vulndb_cursor):
    INIT_LOCK.acquire()
    if not CODENAME_RELEASE_NUMBER_MAP:
        vulndb_cursor.execute("SELECT version, codename FROM ubuntu_codename_version_mapping;")
        release_infos = vulndb_cursor.fetchall()
        for version, codename in release_infos:
            CODENAME_RELEASE_NUMBER_MAP[codename] = version
            UBUNTU_RELEASE_NUMBERS.append(version)
    UBUNTU_RELEASE_NUMBERS.sort(key=lambda version: float(version), reverse=True)
    INIT_LOCK.release()


def preprocess_query(query, product_ids, vuln_db_cursor, product_db_cursor, config):

    # set up Ubuntu codenames and release numbers
    init(vuln_db_cursor)

    query_lower = query.lower()
    query_no_ubuntu = None
    extra_params = {}
    is_ubuntu_query = False
    ubuntu_release = ""
    ubuntu_full_package_version = ""

    if query_lower and not MATCH_CPE_23_RE.match(query_lower):
        # check if ubuntu keywords are in the query, store them for later and
        # remove them from the query

        if "ubuntu" in query_lower:
            # special cases for version strings, e.g. SSH-2.0-OpenSSH_10.0p2 Ubuntu-5ubuntu5
            if query_lower.startswith("ssh-2.0-"):
                query_lower = query_lower[8:]
            if "openssh" in query_lower:
                query_lower = query_lower.replace("_", " ")

            # e.g. MariaDB banner "10.6.22-MariaDB-0ubuntu0.22.04.1"
            version_before_software_match = UBUNTU_VERSION_BEFORE_SOFTWARE_RE.match(query_lower)
            if version_before_software_match:
                query_lower = (
                    version_before_software_match.group(2)
                    + " "
                    + version_before_software_match.group(1)
                    + version_before_software_match.group(3)
                )

            for ubuntu_codename in CODENAME_RELEASE_NUMBER_MAP:
                if ubuntu_codename in query_lower:
                    ubuntu_release = ubuntu_codename
                    break
            if not ubuntu_release:
                for ubuntu_release_version in UBUNTU_RELEASE_NUMBERS:
                    if ubuntu_release_version in query_lower:
                        ubuntu_release = ubuntu_release_version
                        break

            # strip release and codename out of query initially
            query_no_ubuntu_between_versions = query_lower.replace(ubuntu_codename, "").replace(
                ubuntu_release, ""
            )

            # if release was part of ubuntu version, put it back
            if query_no_ubuntu_between_versions.find(
                ".."
            ) > query_no_ubuntu_between_versions.find("ubuntu"):
                query_no_ubuntu_between_versions = query_no_ubuntu_between_versions.replace(
                    "..", f".{ubuntu_release}.", 1
                )

            query_no_ubuntu_between_versions = REMOVE_UBUNTU_BETWEEN_VERSIONS_IN_QUERY_RE.sub(
                r"\1-\2", query_no_ubuntu_between_versions
            )
            ubuntu_full_version_parts = UBUNTU_FULL_VERSION_EXTRACT_RE.findall(
                query_no_ubuntu_between_versions
            )
            if ubuntu_full_version_parts:
                is_ubuntu_query = True

        # figure out full Ubuntu version string and vendor version and clean query from Ubuntu-specifics
        if is_ubuntu_query:
            query_no_ubuntu = query_no_ubuntu_between_versions
            vendor_version = ""
            if len(ubuntu_full_version_parts) == 1:
                ubuntu_full_package_version = ubuntu_full_version_parts[0][0]
                vendor_version = extract_vendor_version(ubuntu_full_package_version)
                query_no_ubuntu = query_no_ubuntu.replace(
                    ubuntu_full_version_parts[0][0], vendor_version
                )
            elif len(ubuntu_full_version_parts) == 2:
                ubuntu_full_package_version = (
                    ubuntu_full_version_parts[0][0] + ubuntu_full_version_parts[1][1]
                )
                vendor_version = extract_vendor_version(ubuntu_full_package_version)
                query_no_ubuntu = query_no_ubuntu.replace(
                    ubuntu_full_version_parts[0][0], vendor_version
                )
                query_no_ubuntu = query_no_ubuntu.replace(ubuntu_full_version_parts[1][1], "")
            query_no_ubuntu = REMOVE_UBUNTU_IN_QUERY_RE.sub("", query_no_ubuntu)
            if ubuntu_release:
                query_no_ubuntu = query_no_ubuntu.replace(ubuntu_release, "")

            extra_params["ubuntu_orig_query"] = query
            query = query_no_ubuntu
    elif query or (product_ids and product_ids.get("cpe", [])):
        # retrieve Ubuntu information from CPEs if available
        # for simplicity, assume the same product version and Ubuntu release across all CPEs
        cpes, new_cpes = [], []
        if query:
            cpes.append(query)
        if product_ids and product_ids.get("cpe", []):
            cpes += product_ids["cpe"]

        for cpe in cpes:
            cpe_parts = split_cpe(cpe)
            if len(cpe_parts) < 13 or "ubuntu" not in cpe_parts[12]:
                new_cpes.append(cpe)
                continue

            is_ubuntu_query, ubuntu_full_package_version, ubuntu_release = True, "", ""

            # strip leading identifier indicating an ubuntu query
            ubuntu_details = cpe_parts[12][len("ubuntu") :].split("_")
            for part in ubuntu_details:
                if part in CODENAME_RELEASE_NUMBER_MAP or part in UBUNTU_RELEASE_NUMBERS:
                    ubuntu_release = part
                elif part:
                    ubuntu_full_package_version = part

            cpe_parts[12] = "*"
            new_cpes.append(":".join(cpe_parts))
        if query:
            extra_params["ubuntu_orig_query"] = query
            query = new_cpes[0]
            del new_cpes[0]
        if new_cpes:
            product_ids["cpe"] = new_cpes

    # store Ubuntu specifics for postprocess and return adapted query
    if is_ubuntu_query:
        extra_params["ubuntu_release"] = ubuntu_release
        extra_params["ubuntu_full_version"] = ubuntu_full_package_version
        return query, extra_params

    return None, {}


def postprocess_results(
    results, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    # only run if query was an Ubuntu query
    if "ubuntu_orig_query" not in extra_params:
        return

    ubuntu_full_package_version = extra_params["ubuntu_full_version"]
    # for simplicity, strip epoch
    ubuntu_full_package_version = strip_epoch_from_version(ubuntu_full_package_version)
    ubuntu_release = extra_params["ubuntu_release"]
    if ubuntu_release.lower() in CODENAME_RELEASE_NUMBER_MAP:
        ubuntu_release = CODENAME_RELEASE_NUMBER_MAP[ubuntu_release]
    elif ubuntu_release not in UBUNTU_RELEASE_NUMBERS:
        ubuntu_release = UBUNTU_RELEASE_NUMBERS[1]  # choose latest available, but not upstream
    ubuntu_release = float(ubuntu_release)

    # go over vulnerabilities and mark them as patched if that is the case
    if "product_ids" in results and results["product_ids"].get("cpe", []):
        for vuln_id, vuln in results["vulns"].items():
            cve_ids = set()
            if vuln_id.startswith("CVE-"):
                cve_ids.add(vuln_id)
            for alias_id in vuln.aliases:
                if alias_id.startswith("CVE-"):
                    cve_ids.add(alias_id)

            is_patched = False
            for cve_id in cve_ids:
                # assumption: all product IDs have same version
                for cpe in results["product_ids"]["cpe"]:
                    cpe_prefix = get_cpe_product_prefix(cpe)
                    vuln_db_cursor.execute(
                        "SELECT ubuntu_release_version, version_start, version_fixed FROM ubuntu_backpatches JOIN ubuntu_pkg_cpes ON ubuntu_backpatches.cpe_prefix_id = ubuntu_pkg_cpes.cpe_prefix_id WHERE cve_id = ? AND cpe_prefix = ?",
                        (cve_id, cpe_prefix),
                    )
                    backpatch_info = vuln_db_cursor.fetchall()

                    # filter out backpatches that do not apply to the given ubuntu product version
                    backpatch_info = [
                        bp
                        for bp in backpatch_info
                        if not bp[1] or ubuntu_full_package_version.startswith(bp[1])
                    ]

                    # sort by ubuntu release
                    backpatch_info.sort(key=lambda bp_info: float(bp_info[0]))

                    last_fixed_version = None if not backpatch_info else backpatch_info[0][2]
                    for i in range(len(backpatch_info)):
                        bp_ubuntu_release, bp_start_version, bp_fixed_version = backpatch_info[
                            i
                        ]
                        if ubuntu_release < float(bp_ubuntu_release):
                            break
                        last_fixed_version = bp_fixed_version

                    # for simplicity, strip epoch
                    if last_fixed_version:
                        last_fixed_version = strip_epoch_from_version(last_fixed_version)
                        if last_fixed_version == "-1" or DebianVersion(
                            ubuntu_full_package_version
                        ) >= DebianVersion(last_fixed_version):
                            is_patched = True
                        break

            if is_patched:
                vuln.set_patched("ubuntu")

    # modify product IDs and potential product IDs in result to use original Ubuntu information
    for pid_type in ("product_ids", "pot_product_ids"):
        if pid_type in results and "cpe" in results[pid_type]:
            new_cpes = []
            for cpe_info in results[pid_type]["cpe"]:
                # insert ubuntu details into last field of CPE
                if isinstance(cpe_info, tuple):
                    cpe, match_score = cpe_info
                else:
                    cpe, match_score = cpe_info, None
                cpe_parts = split_cpe(cpe)
                last_cpe_field = "ubuntu"

                # insert ubuntu codename or version
                if extra_params.get("ubuntu_release", ""):
                    last_cpe_field += "_" + extra_params["ubuntu_release"]

                # insert package patch information
                if "ubuntu_full_version" in extra_params and any(
                    part in extra_params["ubuntu_full_version"]
                    for part in SPLIT_QUERY_TERMS_RE.split(cpe_parts[5])
                ):
                    last_cpe_field += "_" + extra_params["ubuntu_full_version"]

                cpe_parts[12] = last_cpe_field
                new_cpe = ":".join(cpe_parts)
                if match_score is not None:
                    new_cpes.append((new_cpe, match_score))
                else:
                    new_cpes.append(new_cpe)

            if new_cpes:
                results[pid_type]["cpe"] = new_cpes
