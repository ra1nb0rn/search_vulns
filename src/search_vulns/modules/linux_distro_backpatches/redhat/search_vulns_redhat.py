import re
from threading import Lock

from cpe_search.cpe_search import MATCH_CPE_23_RE
from univers.versions import RpmVersion

from search_vulns.modules.linux_distro_backpatches.redhat.build import (
    REQUIRES_BUILT_MODULES,
    full_update,
)
from search_vulns.modules.linux_distro_backpatches.utils import strip_epoch_from_version
from search_vulns.modules.utils import get_cpe_product_prefix, split_cpe

INIT_LOCK = Lock()
MATCH_REDHAT_QUERY_RE = re.compile(
    r"(\(?(Red\s*hat\s*enterprise\s*linux|\.?redhat|red\s*hat|\.el|\.?rhel)\)?)\s*([\d_\.]{0,3})|(\.rpm$)",
    re.IGNORECASE,
)
MATCH_REDHAT_RELEASE_NR_RE = re.compile(r"\d([_\.]\d)?")
SPLIT_REDHAT_SUBVERSION_RE = re.compile(r"(\d[.\d)]+-?)")
DEDUP_VERSION_ZEROES_RE = re.compile(r"0+(\d)")


#############################################################################################
### Created with help of original connector to Red Hat API by https://github.com/MRuppDev ###
#############################################################################################


def preprocess_query(query, product_ids, vuln_db_cursor, product_db_cursor, config):
    query_lower = query.lower()
    query_no_redhat = None
    extra_params = {}
    is_redhat_query = False
    redhat_release = ""
    redhat_full_version = ""

    if query_lower and not MATCH_CPE_23_RE.match(query_lower):
        # check if redhat keywords are in the query, store them for later and
        # remove them from the query
        query_no_redhat = query_lower
        redhat_matches = MATCH_REDHAT_QUERY_RE.findall(query_lower)
        if redhat_matches:
            for match in redhat_matches[0]:
                match = str(match)
                if match:
                    is_redhat_query = True
                    query_no_redhat = query_no_redhat.replace(match, "")
                if MATCH_REDHAT_RELEASE_NR_RE.match(match):
                    redhat_release = match.replace("_", ".")
                    break

        # figure out full Red Hat version string and vendor version and clean query from Redhat-specifics
        if is_redhat_query:
            query_version_split = SPLIT_REDHAT_SUBVERSION_RE.split(query_no_redhat, maxsplit=1)
            query_no_redhat = "".join(query_version_split[0:2])
            if query_no_redhat.endswith("-"):
                query_no_redhat = query_no_redhat[:-1]
            redhat_full_version = "".join(query_version_split[1:])

            if (
                "--" in redhat_full_version
            ):  # e.g. '9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.16' as input version
                redhat_full_version = redhat_full_version[redhat_full_version.find("--") + 2 :]

            redhat_full_version = DEDUP_VERSION_ZEROES_RE.sub(
                r"\1", redhat_full_version
            )  # e.g. Keycloak 26.2.10.redhat-00002

    elif query or (product_ids and product_ids.get("cpe", [])):
        # retrieve Redhat information from CPEs if available
        # for simplicity, assume the same product version and Redhat release across all CPEs
        cpes, new_cpes = [], []
        if query:
            cpes.append(query)
        if product_ids and product_ids.get("cpe", []):
            cpes += product_ids["cpe"]

        for cpe in cpes:
            cpe_parts = split_cpe(cpe)
            if len(cpe_parts) < 13 or "rhel" not in cpe_parts[12]:
                new_cpes.append(cpe)
                continue

            is_redhat_query, redhat_release, redhat_full_version = True, "", ""

            # strip leading identifier indicating an redhat query
            redhat_details = cpe_parts[12].split("_", maxsplit=2)
            redhat_release = redhat_details[1]
            redhat_full_version = redhat_details[2]
            cpe_parts[12] = "*"
            new_cpes.append(":".join(cpe_parts))

        if query:
            extra_params["redhat_orig_query"] = query
            query_no_redhat = new_cpes[0]
            del new_cpes[0]
        if new_cpes:
            product_ids["cpe"] = new_cpes

    # store Red Hat specifics for postprocess and return adapted query
    if is_redhat_query:
        # for simplicity, strip epoch
        redhat_full_version = strip_epoch_from_version(redhat_full_version)
        extra_params["redhat_orig_query"] = query
        extra_params["redhat_release"] = redhat_release
        extra_params["redhat_full_version"] = redhat_full_version
        query = query_no_redhat
        return query, extra_params

    return None, {}


def postprocess_results(
    results, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    # only run if query was a Redhat query
    if "redhat_orig_query" not in extra_params:
        return

    redhat_full_version = extra_params["redhat_full_version"]
    # for simplicity, strip epoch
    redhat_full_version = strip_epoch_from_version(redhat_full_version)
    redhat_release = extra_params["redhat_release"]
    if not redhat_release:
        redhat_release = "999"

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
                        "SELECT redhat_release_version, version_start, version_fixed FROM redhat_backpatches JOIN redhat_pkg_cpes ON redhat_backpatches.cpe_prefix_id = redhat_pkg_cpes.cpe_prefix_id WHERE cve_id = ? AND cpe_prefix = ?",
                        (cve_id, cpe_prefix),
                    )
                    backpatch_info = vuln_db_cursor.fetchall()

                    # filter out backpatches that do not apply to the given redhat product version
                    backpatch_info = [
                        bp
                        for bp in backpatch_info
                        if not bp[1] or redhat_full_version.startswith(bp[1])
                    ]

                    # sort by redhat release
                    backpatch_info.sort(key=lambda bp_info: float(bp_info[0]))

                    last_fixed_version = None if not backpatch_info else backpatch_info[0][2]
                    for i in range(len(backpatch_info)):
                        bp_redhat_release, bp_start_version, bp_fixed_version = backpatch_info[
                            i
                        ]

                        # break if backpatch for higher OS version was found,
                        # but not if a broad major release was supplied, e.g. supplied:9 and backpatch:9.2
                        if float(redhat_release) < float(
                            bp_redhat_release
                        ) and not bp_redhat_release.startswith(redhat_release):
                            break
                        last_fixed_version = bp_fixed_version

                        # always break after updating fixed_version if a fully matching release was found
                        if float(redhat_release) == float(bp_redhat_release):
                            break

                    if last_fixed_version:
                        # for simplicity, strip epoch
                        last_fixed_version = strip_epoch_from_version(last_fixed_version)

                        if last_fixed_version and (
                            last_fixed_version == "-1"
                            or RpmVersion(redhat_full_version) >= RpmVersion(last_fixed_version)
                        ):
                            is_patched = True
                        break

            if is_patched:
                vuln.set_patched("redhat")

    # modify product IDs and potential product IDs in result to use original Redhat information
    for pid_type in ("product_ids", "pot_product_ids"):
        if pid_type in results and "cpe" in results[pid_type]:
            new_cpes = []
            for cpe_info in results[pid_type]["cpe"]:
                # insert redhat details into last field of CPE
                if isinstance(cpe_info, tuple):
                    cpe, match_score = cpe_info
                else:
                    cpe, match_score = cpe_info, None
                cpe_parts = split_cpe(cpe)
                last_cpe_field = "rhel_"

                # insert redhat codename or version
                if extra_params.get("redhat_release", ""):
                    last_cpe_field += extra_params["redhat_release"]

                # insert package patch information
                last_cpe_field += "_"
                if (
                    "redhat_full_version" in extra_params
                    and cpe_parts[5] in extra_params["redhat_full_version"]
                ):
                    last_cpe_field += extra_params["redhat_full_version"]

                cpe_parts[12] = last_cpe_field
                new_cpe = ":".join(cpe_parts)
                if match_score is not None:
                    new_cpes.append((new_cpe, match_score))
                else:
                    new_cpes.append(new_cpe)

            if new_cpes:
                results[pid_type]["cpe"] = new_cpes
