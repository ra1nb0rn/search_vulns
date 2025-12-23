import datetime

from search_vulns.cpe_version import CPEVersion
from search_vulns.modules.end_of_life_date.build import (
    REQUIRES_BUILT_MODULES,
    full_update,
)


def postprocess_results(
    results, query, vuln_db_cursor, product_db_cursor, config, extra_params
):
    """Retrieve information from endoflife.date whether the provided version is eol or outdated"""

    product_ids = results.get("product_ids")
    if not product_ids or not vuln_db_cursor:
        return
    # skip if another module has already provided a version status
    if "version_status" in results:
        return

    version_status = {}
    for cpe in product_ids["cpe"]:
        if version_status:
            break
        cpe_split = cpe.split(":")
        cpe_prefix, query_version = ":".join(cpe_split[:5]) + ":", CPEVersion(cpe_split[5])
        eol_releases = []
        vuln_db_cursor.execute(
            "SELECT eold_id, version_start, version_latest, eol_info FROM eol_date_data WHERE cpe_prefix = ? ORDER BY release_id DESC",
            (cpe_prefix,),
        )
        if vuln_db_cursor:
            eol_releases = vuln_db_cursor.fetchall()

        # find release branch matching query version
        queried_release_branch_idx = 0 if eol_releases else None
        is_queried_release_eol, is_lower_release_eol = None, None
        for i, release in enumerate(eol_releases):
            release_end = CPEVersion(release[2])
            release_eol, now = release[3].lower(), datetime.datetime.now()
            is_lower_release_eol = False
            if release_eol not in ("true", "false"):
                release_eol = datetime.datetime.strptime(release_eol, "%Y-%m-%d")
                is_lower_release_eol = now >= release_eol
            elif release_eol == "true":
                is_lower_release_eol = True

            if is_queried_release_eol is None:
                is_queried_release_eol = is_lower_release_eol

            # break if release branch was found
            if not query_version or query_version > release_end:
                break
            else:
                queried_release_branch_idx = i
                is_queried_release_eol = is_lower_release_eol

        # determine query version status
        if queried_release_branch_idx is not None:
            latest_release = eol_releases[0][2]
            release = eol_releases[queried_release_branch_idx]
            release_start, release_end = CPEVersion(release[1]), CPEVersion(release[2])
            eol_ref = "https://endoflife.date/" + release[0]
            if not query_version:  # no query version --> return general information
                if is_queried_release_eol:
                    version_status = {
                        "status": "eol",
                        "latest": str(release_end),
                        "ref": eol_ref,
                    }
                else:
                    version_status = {
                        "status": "N/A",
                        "latest": str(release_end),
                        "ref": eol_ref,
                    }
            else:  # determine version status of query version
                if (
                    str(release_end).startswith(str(release_start))
                    and query_version < release_start
                ):
                    if is_lower_release_eol:
                        version_status = {
                            "status": "eol",
                            "latest": latest_release,
                            "ref": eol_ref,
                        }
                    else:
                        if queried_release_branch_idx + 1 < len(eol_releases):
                            release_end = CPEVersion(eol_releases[i + 1][2])
                        version_status = {
                            "status": "current",
                            "latest": str(release_end),
                            "ref": eol_ref,
                        }
                else:
                    if query_version >= release_end:
                        if is_queried_release_eol:
                            version_status = {
                                "status": "eol",
                                "latest": latest_release,
                                "ref": eol_ref,
                            }
                        else:
                            version_status = {
                                "status": "current",
                                "latest": str(release_end),
                                "ref": eol_ref,
                            }
                    elif query_version < release_end:
                        if is_queried_release_eol:
                            version_status = {
                                "status": "eol",
                                "latest": latest_release,
                                "ref": eol_ref,
                            }
                        else:
                            version_status = {
                                "status": "outdated",
                                "latest": str(release_end),
                                "ref": eol_ref,
                            }

    results["version_status"] = version_status
