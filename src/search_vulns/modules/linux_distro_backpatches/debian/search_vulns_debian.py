import re
from threading import Lock

from cpe_search.cpe_search import MATCH_CPE_23_RE
from univers.versions import DebianVersion

from search_vulns.cpe_version import CPEVersion
from search_vulns.modules.linux_distro_backpatches.debian.build import (
    REQUIRES_BUILT_MODULES,
    full_update,
)
from search_vulns.modules.linux_distro_backpatches.utils import (
    SPLIT_QUERY_TERMS_RE,
    get_clean_version,
    strip_epoch_from_version,
)
from search_vulns.modules.utils import get_cpe_product_prefix, split_cpe

CODENAME_RELEASE_NUMBER_MAP = {}
RELEASE_NUMBER_CODENAME_MAP = {}
LATEST_DEBIAN_RELEASE = -1
DEBIAN_QUERY_MATCH_RE = re.compile(r"[\(\[\s]?debian[\)\]\s]?|deb\d+u\d+")
DEBIAN_SHORT_RELEASE_NUMBER_RE = re.compile(r"deb(\d+)u\d+")
DEBIAN_VERSION_RE = re.compile(
    r"\b((\d\:)?\d[\w\.\-]+[+~](\d+|dfsg(\.\d)*|ds(\.\d)*|deb\d+u+\d+|git[a-fA-F\d]+)(-[\d+\.]+)?)"
)
SIMPLE_VERSION_RE = re.compile(r"\b(\d[\w\.\-]+(-[\d\.]+)?)")
SUBVERSION_RE = re.compile(r".*(-[\d\.]+)?$")
DEBIAN_VERSION_BEFORE_SOFTWARE_RE = re.compile(r"^([\d\.]+)[- +_](\w+)(.*)")
DEBIAN_VERSION_BETWEEN_SUBVERSION_RE = re.compile(r"((\d[\da-z\.]*)[- +_]debian-)")
INIT_LOCK = Lock()


############################################################################################
### Created with help of original connector to Debian API by https://github.com/MRuppDev ###
############################################################################################


def init(vulndb_cursor):
    INIT_LOCK.acquire()
    if not CODENAME_RELEASE_NUMBER_MAP:
        vulndb_cursor.execute("SELECT version, codename FROM debian_codename_version_mapping;")
        release_infos = vulndb_cursor.fetchall()
        for version, codename in release_infos:
            CODENAME_RELEASE_NUMBER_MAP[codename] = version
            RELEASE_NUMBER_CODENAME_MAP[version] = codename
    LATEST_DEBIAN_RELEASE = sorted(list(RELEASE_NUMBER_CODENAME_MAP), reverse=True)[0]
    INIT_LOCK.release()


def preprocess_query(query, product_ids, vuln_db_cursor, product_db_cursor, config):

    # setup Debian codes names and release numbers
    init(vuln_db_cursor)

    query_lower = query.lower()
    query_no_debian = None
    extra_params = {}

    if query and not MATCH_CPE_23_RE.match(query):
        # check if debian keywords are in the query, store them for later and
        # remove them from the query
        debian_query_match = DEBIAN_QUERY_MATCH_RE.findall(query_lower)
        debian_version = ""

        if not debian_query_match:
            return None, {}

        # special cases for version strings, e.g. SSH-2.0-OpenSSH_10.0p2 Ubuntu-5ubuntu5
        if query_lower.startswith("ssh-2.0-"):
            query_lower = query_lower[8:]
        if "openssh" in query_lower:
            query_lower = query_lower.replace("_", " ")

        # e.g. SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
        debian_between_subversion_matches = DEBIAN_VERSION_BETWEEN_SUBVERSION_RE.findall(
            query_lower
        )
        if debian_between_subversion_matches:
            query_lower = (
                query_lower.replace(
                    debian_between_subversion_matches[0][0],
                    debian_between_subversion_matches[0][1] + "-",
                )
                + " debian"
            )

        # e.g. MariaDB banner "10.6.22-MariaDB-0ubuntu0.22.04.1"
        version_before_software_match = DEBIAN_VERSION_BEFORE_SOFTWARE_RE.match(query_lower)
        if version_before_software_match:
            query_lower = (
                version_before_software_match.group(2)
                + " "
                + version_before_software_match.group(1)
                + version_before_software_match.group(3)
            )

        # first, extract debian code name or release number
        query_no_debian = query_lower
        for debian_match in debian_query_match:
            if "debian" in debian_match:  # skip just 'deb', since it's part of version number
                query_no_debian = query_no_debian.replace(debian_match, " ")
            else:
                extra_params["debian_short_release"] = debian_match
                if "+" + debian_match in query_no_debian:
                    query_no_debian = query_no_debian.replace("+" + debian_match, " ")
                else:
                    query_no_debian = query_no_debian.replace(debian_match, " ")

        extra_params["debian_orig_query"] = query
        for codename, release_number in CODENAME_RELEASE_NUMBER_MAP.items():
            # accept codename and release number at the same time, if identical release referenced
            found_release = False
            if " " + codename + " " in query_no_debian:
                extra_params["debian_codename"] = codename
                query_no_debian = query_no_debian.replace(" " + codename + " ", " ")
                found_release = True
            if query_no_debian.endswith(" " + codename):
                extra_params["debian_codename"] = codename
                query_no_debian = query_no_debian.replace(" " + codename, "")
                found_release = True
            if " " + release_number + " " in query_no_debian:
                extra_params["debian_release_number"] = release_number
                query_no_debian = query_no_debian.replace(" " + release_number + " ", " ")
                found_release = True
            if query_no_debian.endswith(" " + release_number):
                extra_params["debian_release_number"] = release_number
                query_no_debian = query_no_debian.replace(" " + release_number, "")
                found_release = True

            if found_release:
                break

        # try to extract the query's product version
        # first check if a full Debian version is present, e.g. 1.14.2+ds-7+deb10u1
        debian_version_in_query = DEBIAN_VERSION_RE.findall(query_no_debian)
        if debian_version_in_query:
            debian_version = debian_version_in_query[0][0]
            # for simplicity, strip epoch
            debian_version = strip_epoch_from_version(debian_version)
        # otherwise check for a simple version
        if not debian_version:
            version_in_query = SIMPLE_VERSION_RE.findall(query_no_debian)
            if version_in_query:
                debian_version = version_in_query[0][0]

        # clean up the query's product version from Debian-related specifics
        # this should ensure the query runs as normal first and its general
        # results are 'corrected' by backpatch information
        if debian_version:
            extra_params["debian_full_version"] = debian_version
            clean_version = get_clean_version(debian_version)
            subversion_match = SUBVERSION_RE.match(clean_version)
            if subversion_match:
                extra_params["debian_subversion"] = clean_version
                if "-" in clean_version:
                    clean_version = clean_version[: clean_version.rfind("-")]
            extra_params["debian_upstream_version"] = clean_version
            query_no_debian = query_no_debian.replace(debian_version, clean_version)

        # return modified query if Debian-related, otherwise do nothing
        if extra_params:
            return query_no_debian, extra_params

    elif query or (product_ids and product_ids.get("cpe", [])):
        cpes, new_cpes = [], []
        if query:
            cpes.append(query)
        if product_ids and product_ids.get("cpe", []):
            cpes += product_ids["cpe"]

        for cpe in cpes:
            cpe_parts = split_cpe(cpe)
            if len(cpe_parts) < 13 or "debian" not in cpe_parts[12]:
                new_cpes.append(cpe)
                continue

            # extract info and replace release keywords in last field of CPE
            extra_params["debian_orig_query"] = query
            debian_str_start = cpe_parts[12].find("debian")
            debian_str = cpe_parts[12][debian_str_start + len("debian") :]
            found_release = False
            codenames_len_sorted = sorted(
                CODENAME_RELEASE_NUMBER_MAP, reverse=True, key=lambda c: len(c)
            )
            for codename in codenames_len_sorted:
                release_number = CODENAME_RELEASE_NUMBER_MAP[codename]
                if "_" + codename in debian_str:
                    extra_params["debian_codename"] = codename
                    found_release = True
                if not found_release and (
                    "_" + release_number + "_" in debian_str
                    or debian_str.endswith("_" + release_number)
                ):
                    extra_params["debian_release_number"] = release_number
                    found_release = True
                if found_release:
                    break

            deb_short_release = DEBIAN_QUERY_MATCH_RE.findall(debian_str)
            if deb_short_release:
                extra_params["debian_short_release"] = deb_short_release[0]

            if debian_str_start > 1:
                cpe_parts[12] = cpe_parts[12][: debian_str_start - 1]
            else:
                cpe_parts[12] = "*"

            # extract info about version and replace it with non-debian version
            if found_release and debian_str.count("_") < 2:
                extra_params["debian_full_version"] = cpe_parts[5]
                extra_params["debian_subversion"] = cpe_parts[5]
                extra_params["debian_upstream_version"] = cpe_parts[5]
            else:
                extra_params["debian_full_version"] = debian_str.rsplit("_", maxsplit=1)[1]
                clean_version = get_clean_version(extra_params["debian_full_version"])
                subversion_match = SUBVERSION_RE.match(clean_version)
                if subversion_match:
                    extra_params["debian_subversion"] = clean_version
                    if "-" in clean_version:
                        clean_version = clean_version[: clean_version.rfind("-")]
                cpe_parts[5] = clean_version
                extra_params["debian_upstream_version"] = clean_version
            new_cpes.append(":".join(cpe_parts))

        if query:
            query = new_cpes[0]
            del new_cpes[0]
        if new_cpes:
            product_ids["cpe"] = new_cpes

        return query, extra_params

    return None, {}


def postprocess_results(
    results, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    # only run if query was a Debian query
    if "debian_orig_query" not in extra_params:
        return

    # determine which codename to use for patching information
    debian_release = ""
    if "debian_codename" in extra_params:
        debian_release = CODENAME_RELEASE_NUMBER_MAP[extra_params["debian_codename"]]
    elif "debian_release_number" in extra_params:
        debian_release = extra_params["debian_release_number"]
    elif "debian_short_release" in extra_params:
        short_release = extra_params["debian_short_release"]
        short_release_match = DEBIAN_SHORT_RELEASE_NUMBER_RE.match(short_release)
        if short_release_match:
            debian_release = short_release_match.group(1)
    if not debian_release:
        debian_release = LATEST_DEBIAN_RELEASE
    debian_release = float(debian_release)
    debian_subversion = extra_params.get("debian_subversion", "")

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
                        "SELECT debian_release_version, version_start, version_fixed FROM debian_backpatches JOIN debian_pkg_cpes ON debian_backpatches.cpe_prefix_id = debian_pkg_cpes.cpe_prefix_id WHERE cve_id = ? AND cpe_prefix = ?",
                        (cve_id, cpe_prefix),
                    )
                    backpatch_info = vuln_db_cursor.fetchall()

                    # filter out backpatches that do not apply to the given debian product version
                    backpatch_info = [
                        bp
                        for bp in backpatch_info
                        if not bp[1] or debian_subversion.startswith(bp[1])
                    ]

                    # sort by debian release
                    backpatch_info.sort(key=lambda bp_info: float(bp_info[0]))

                    last_fixed_version = None if not backpatch_info else backpatch_info[0][2]
                    for i in range(len(backpatch_info)):
                        bp_debian_release, bp_start_version, bp_fixed_version = backpatch_info[
                            i
                        ]
                        if debian_release < float(bp_debian_release):
                            break
                        last_fixed_version = bp_fixed_version

                    # for simplicity, strip epoch
                    if last_fixed_version:
                        last_fixed_version = strip_epoch_from_version(last_fixed_version)
                        last_fixed_version = get_clean_version(last_fixed_version)
                        if last_fixed_version == "-1" or DebianVersion(
                            debian_subversion
                        ) >= DebianVersion(last_fixed_version):
                            is_patched = True
                        break

                if is_patched:
                    break

            if is_patched:
                vuln.set_patched("debian")

    # modify product IDs and potential product IDs in result to use original Debian information
    for pid_type in ("product_ids", "pot_product_ids"):
        if pid_type in results and "cpe" in results[pid_type]:
            new_cpes = []
            for cpe_info in results[pid_type]["cpe"]:
                # insert debian patch version into CPE
                if isinstance(cpe_info, tuple):
                    cpe, match_score = cpe_info
                else:
                    cpe, match_score = cpe_info, None

                cpe_parts = split_cpe(cpe)
                last_cpe_field = "debian"

                # insert debian codename or version into CPE
                if extra_params.get("debian_codename", ""):
                    last_cpe_field += "_" + extra_params["debian_codename"]
                if extra_params.get("debian_release_number", ""):
                    last_cpe_field += "_" + extra_params["debian_release_number"]
                if extra_params.get("debian_short_release", ""):
                    last_cpe_field += "_" + extra_params["debian_short_release"]

                # insert package patch information
                if "debian_full_version" in extra_params and any(
                    part in extra_params["debian_full_version"]
                    for part in SPLIT_QUERY_TERMS_RE.split(cpe_parts[5])
                ):
                    last_cpe_field += "_" + extra_params["debian_full_version"]

                cpe_parts[12] = last_cpe_field
                new_cpe = ":".join(cpe_parts)
                if match_score is not None:
                    new_cpes.append((new_cpe, match_score))
                else:
                    new_cpes.append(new_cpe)

            if new_cpes:
                results[pid_type]["cpe"] = new_cpes

    # remove outdated and EoL information
    if "version_status" in results:
        del results["version_status"]

    # set outdated information
    if vuln_db_cursor and "product_ids" in results and results["product_ids"].get("cpe", []):
        cpes = results["product_ids"].get("cpe", [])
        cpes_prefixes = [get_cpe_product_prefix(cpe) for cpe in cpes]

        # query information
        cpe_placeholders = ", ".join(
            ["?"] * len(cpes_prefixes)
        )  # Create a placeholder string for the number of product IDs
        cpes_prefixes_str = tuple(cpes_prefixes)
        vuln_db_cursor.execute(
            f"SELECT pkg, debian_release_version, version_start, latest_version FROM debian_latest_pkg_versions JOIN debian_pkg_cpes ON debian_latest_pkg_versions.cpe_prefix_id = debian_pkg_cpes.cpe_prefix_id WHERE cpe_prefix IN ({cpe_placeholders})",
            cpes_prefixes_str,
        )
        latest_pkg_versions = vuln_db_cursor.fetchall()

        # filter out information that does not apply to the given debian product version
        latest_pkg_versions = [
            lpv
            for lpv in latest_pkg_versions
            if not lpv[2] or debian_subversion.startswith(lpv[2])
        ]

        # sort by debian release
        latest_pkg_versions.sort(key=lambda lpv_info: float(lpv_info[1]))

        latest = None
        for i in range(len(latest_pkg_versions)):
            if debian_release < float(latest_pkg_versions[i][1]):
                break
            latest = latest_pkg_versions[i]

        if latest:
            pkg, version_start, latest_version = latest[0], latest[2], latest[3]

            # clean version
            latest_version = strip_epoch_from_version(latest_version)
            latest_version = get_clean_version(latest_version)

            # craft version_status json
            eol_ref = f"https://security-tracker.debian.org/tracker/source-package/{pkg}{version_start}"
            version_status = None
            if not debian_subversion:
                version_status = {
                    "status": "N/A",
                    "latest": str(latest_version),
                    "ref": eol_ref,
                }
            else:
                if DebianVersion(debian_subversion) < DebianVersion(latest_version):
                    version_status = {
                        "status": "outdated",
                        "latest": str(latest_version),
                        "ref": eol_ref,
                    }
                else:
                    version_status = {
                        "status": "current",
                        "latest": str(latest_version),
                        "ref": eol_ref,
                    }
            results["version_status"] = version_status
