import datetime

from search_vulns.cpe_version import CPEVersion
from search_vulns.modules.end_of_life_date.build import REQUIRES_BUILT_MODULES, full_update


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

        latest = ""
        for i, release in enumerate(eol_releases):
            # set up release information
            eol_ref = "https://endoflife.date/" + release[0]
            release_start, release_end = CPEVersion(release[1]), CPEVersion(release[2])
            release_eol, now = release[3], datetime.datetime.now()
            if release_eol not in ("true", "false"):
                release_eol = datetime.datetime.strptime(release_eol, "%Y-%m-%d")
            elif release_eol != "true":
                release_eol = False

            # set latest version in first iteration
            if not latest:
                latest = release_end

            if not query_version:
                if release_eol and now >= release_eol:
                    version_status = {"status": "eol", "latest": str(latest), "ref": eol_ref}
                else:
                    version_status = {"status": "N/A", "latest": str(latest), "ref": eol_ref}
            else:
                # check query version status
                if query_version >= release_end:
                    if release_eol and (release_eol == "true" or now >= release_eol):
                        version_status = {
                            "status": "eol",
                            "latest": str(latest),
                            "ref": eol_ref,
                        }
                    else:
                        version_status = {
                            "status": "current",
                            "latest": str(latest),
                            "ref": eol_ref,
                        }
                elif (release_start <= query_version < release_end) or (
                    i == len(eol_releases) - 1 and query_version <= release_start
                ):
                    if release_eol and (release_eol == "true" or now >= release_eol):
                        version_status = {
                            "status": "eol",
                            "latest": str(latest),
                            "ref": eol_ref,
                        }
                    else:
                        version_status = {
                            "status": "outdated",
                            "latest": str(latest),
                            "ref": eol_ref,
                        }

            if version_status:
                break

    results["version_status"] = version_status
