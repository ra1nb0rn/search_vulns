import re
from threading import Lock

from cpe_version import CPEVersion
from modules.cpe_search.cpe_search.cpe_search import MATCH_CPE_23_RE
from modules.linux_distro_backpatches.debian.build import (
    REQUIRES_BUILT_MODULES,
    full_update,
)
from modules.linux_distro_backpatches.utils import get_clean_version

CODENAME_RELEASE_NUMBER_MAP = {}
RELEASE_NUMBER_CODENAME_MAP = {}
DEBIAN_QUERY_MATCH_RE = re.compile(r"[\(\[\s]?debian[\)\]\s]?|deb\d+u\d+")
DEBIAN_SHORT_RELEASE_NUMBER_RE = re.compile(r"deb(\d+)u\d+")
DEBIAN_VERSION_RE = re.compile(
    r"\b(\d[\w\.\-]+[+~](\d+|dfsg(\.\d)*|ds(\.\d)*|deb\d+u+\d+|git[a-fA-F\d]+)(-[\d+\.]+)?)"
)
SIMPLE_VERSION_RE = re.compile(r"\b(\d[\w\.\-]+(-[\d\.]+)?)")
SUBVERSION_RE = re.compile(r".*(-[\d\.]+)$")
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
            simple_version = get_clean_version(debian_version)
            subversion_match = SUBVERSION_RE.match(simple_version)
            if subversion_match:
                extra_params["debian_subversion"] = simple_version
                simple_version = simple_version[: simple_version.rfind("-")]
            extra_params["debian_provided_version"] = simple_version
            query_no_debian = query_no_debian.replace(debian_version, simple_version)

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
            cpe_parts = cpe.split(":")
            if "debian" not in cpe_parts[12]:
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
                if "_" + release_number in debian_str:
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
            extra_params["debian_subversion"] = cpe_parts[5]
            subversion_match = SUBVERSION_RE.match(cpe_parts[5])
            if subversion_match:
                cpe_parts[5] = cpe_parts[5][: cpe_parts[5].rfind("-")]
            extra_params["debian_provided_version"] = cpe_parts[5]
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
    codename = ""
    if "debian_codename" in extra_params:
        codename = extra_params["debian_codename"]
    elif "debian_release_number" in extra_params:
        codename = RELEASE_NUMBER_CODENAME_MAP[extra_params["debian_release_number"]]
    elif "debian_short_release" in extra_params:
        short_release = extra_params["debian_short_release"]
        short_release_match = DEBIAN_SHORT_RELEASE_NUMBER_RE.match(short_release)
        if short_release_match:
            codename = RELEASE_NUMBER_CODENAME_MAP.get(short_release_match.group(1), "")

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
                    cpe_parts = cpe.split(":")
                    like_base_cpe = ":".join(cpe_parts[:5]) + ":" + "%%"
                    vuln_db_cursor.execute(
                        "SELECT codename, fixed_version FROM debian_backpatches WHERE cve_id = ? AND cpe LIKE ?",
                        (cve_id, like_base_cpe),
                    )
                    fixed_version_info = vuln_db_cursor.fetchall()
                    fixed_version, fixed_latest_release_number = "", -1
                    for fixed_codename, cur_fixed_version in fixed_version_info:
                        if fixed_codename not in CODENAME_RELEASE_NUMBER_MAP:
                            continue
                        fixed_release_number = CODENAME_RELEASE_NUMBER_MAP[fixed_codename]
                        if (
                            not codename
                            and float(fixed_release_number) > fixed_latest_release_number
                        ):
                            fixed_latest_release_number = float(fixed_release_number)
                            fixed_version = cur_fixed_version
                        elif codename and codename == fixed_codename:
                            fixed_version = cur_fixed_version
                            break

                    if fixed_version:
                        if CPEVersion(extra_params["debian_subversion"]) >= CPEVersion(
                            fixed_version
                        ):
                            is_patched = True
                            break
                    if fixed_version_info:
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

                cpe_parts = cpe.split(":")
                if (
                    "debian_subversion" in extra_params
                    and cpe_parts[5] in extra_params["debian_subversion"]
                ):
                    cpe_parts[5] = extra_params["debian_subversion"]

                # insert debian codename or version into CPE
                debian_os_string = "debian"
                if CPEVersion(cpe_parts[12]):
                    debian_os_string = cpe_parts[12] + "_" + debian_os_string
                if "debian_codename" in extra_params:
                    debian_os_string += "_" + extra_params["debian_codename"]
                if "debian_release_number" in extra_params:
                    debian_os_string += "_" + extra_params["debian_release_number"]
                if "debian_short_release" in extra_params:
                    debian_os_string += "_" + extra_params["debian_short_release"]

                cpe_parts[12] = debian_os_string
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
