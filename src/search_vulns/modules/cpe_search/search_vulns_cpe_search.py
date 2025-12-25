from threading import Lock

import ujson
from cpe_search.cpe_search import (
    MATCH_CPE_23_RE,
    is_cpe_equal,
    search_cpes,
)
from cpe_search.database_wrapper_functions import *

from search_vulns.cpe_version import CPEVersion

# implement update procedures in separate file
from search_vulns.modules.cpe_search.build import full_update, update

MODULE_RESOURCE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "resources")
DEBIAN_EQUIV_CPES_FILE = os.path.join(MODULE_RESOURCE_DIR, "debian_equiv_cpes.json")
DEPRECATED_CPES_FILE = os.path.join(MODULE_RESOURCE_DIR, "deprecated-cpes.json")
MAN_EQUIVALENT_CPES_FILE = os.path.join(MODULE_RESOURCE_DIR, "man_equiv_cpes.json")
LOAD_EQUIVALENT_CPES_MUTEX = Lock()
EQUIVALENT_CPES = {}
FULL_DEPRECATION_THRESHOLD = 0.16


def load_equivalent_cpes(product_db_cursor):
    """Load dictionary containing CPE equivalences"""

    LOAD_EQUIVALENT_CPES_MUTEX.acquire()
    if not EQUIVALENT_CPES:
        equivalent_cpes_dicts_list, deprecated_cpes = [], {}
        deprecations_for_product = {}

        # first add official deprecation information from the NVD
        with open(DEPRECATED_CPES_FILE, "r") as f:
            cpe_deprecations_raw = ujson.loads(f.read())
            for cpe, deprecations in cpe_deprecations_raw.items():
                product_cpe_prefix = ":".join(cpe.split(":")[:5]) + ":"

                if product_cpe_prefix not in deprecations_for_product:
                    deprecations_for_product[product_cpe_prefix] = {}
                deprecations_for_product[product_cpe_prefix][cpe] = deprecations

        for product_cpe, deprecations in deprecations_for_product.items():
            product_cpe_prefix = ":".join(product_cpe.split(":")[:5]) + ":"
            product_db_cursor.execute(
                "SELECT count FROM product_cpe_counts where product_cpe_prefix=?",
                (product_cpe_prefix,),
            )
            product_cpe_count = product_db_cursor.fetchall()

            # complete deprecation of product
            full_deprecation = False
            if product_cpe_count and product_cpe[0]:
                product_cpe_count = product_cpe_count[0][0]
                if len(deprecations) >= product_cpe_count * FULL_DEPRECATION_THRESHOLD:
                    deprecations_prefixes = []
                    for deprecatedby_cpe_list in deprecations.values():
                        for deprecatedby_cpe in deprecatedby_cpe_list:
                            deprecatedby_cpe_prefix = (
                                ":".join(deprecatedby_cpe.split(":")[:5]) + ":"
                            )
                            if product_cpe_prefix != deprecatedby_cpe_prefix:
                                if deprecatedby_cpe_prefix not in deprecations_prefixes:
                                    deprecations_prefixes.append(deprecatedby_cpe_prefix)

                    if product_cpe_prefix not in deprecated_cpes:
                        deprecated_cpes[product_cpe_prefix] = deprecations_prefixes
                    else:
                        deprecated_cpes[product_cpe_prefix] = list(
                            set(deprecated_cpes[product_cpe_prefix] + deprecations_prefixes)
                        )

                    for deprecatedby_cpe_short in deprecations_prefixes:
                        if deprecatedby_cpe_short not in deprecated_cpes:
                            deprecated_cpes[deprecatedby_cpe_short] = [product_cpe_prefix]
                        elif product_cpe_prefix not in deprecated_cpes[deprecatedby_cpe_short]:
                            deprecated_cpes[deprecatedby_cpe_short].append(product_cpe_prefix)
                    full_deprecation = True

            # only certain versions are deprecated
            if not full_deprecation:
                for full_product_cpe, deprecatedby_cpe_list in deprecations.items():
                    for deprecatedby_cpe in deprecatedby_cpe_list:
                        if not is_cpe_equal(full_product_cpe, deprecatedby_cpe):
                            if full_product_cpe not in deprecated_cpes:
                                deprecated_cpes[full_product_cpe] = [deprecatedby_cpe]
                            elif deprecatedby_cpe not in deprecated_cpes[full_product_cpe]:
                                deprecated_cpes[full_product_cpe].append(deprecatedby_cpe)

                            if deprecatedby_cpe not in deprecated_cpes:
                                deprecated_cpes[deprecatedby_cpe] = [full_product_cpe]
                            elif full_product_cpe not in deprecated_cpes[deprecatedby_cpe]:
                                deprecated_cpes[deprecatedby_cpe].append(full_product_cpe)

        equivalent_cpes_dicts_list.append(deprecated_cpes)

        # then manually add further information
        with open(MAN_EQUIVALENT_CPES_FILE) as f:
            manual_equivalent_cpes = ujson.loads(f.read())
        equivalent_cpes_dicts_list.append(manual_equivalent_cpes)

        # finally add further information from https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/master/data/CPE/aliases
        with open(DEBIAN_EQUIV_CPES_FILE) as f:
            debian_equivalent_cpes = ujson.loads(f.read())
        equivalent_cpes_dicts_list.append(debian_equivalent_cpes)

        # unite the infos from the different sources
        for equivalent_cpes_dict in equivalent_cpes_dicts_list:
            for equiv_cpe, other_equiv_cpes in equivalent_cpes_dict.items():
                if equiv_cpe not in EQUIVALENT_CPES:
                    EQUIVALENT_CPES[equiv_cpe] = other_equiv_cpes
                else:
                    EQUIVALENT_CPES[equiv_cpe].extend(other_equiv_cpes)

        # ensure that each entry and its equivalents are properly linked in both directions
        for equiv_cpe in list(EQUIVALENT_CPES):
            other_equiv_cpes = list(EQUIVALENT_CPES[equiv_cpe])
            for other_equiv_cpe in other_equiv_cpes:
                other_relevant_equiv_cpes = [
                    equiv_cpe if cpe == other_equiv_cpe else cpe for cpe in other_equiv_cpes
                ]
                if other_equiv_cpe not in EQUIVALENT_CPES:
                    EQUIVALENT_CPES[other_equiv_cpe] = other_relevant_equiv_cpes
                elif equiv_cpe not in EQUIVALENT_CPES[other_equiv_cpe]:
                    EQUIVALENT_CPES[other_equiv_cpe].extend(other_relevant_equiv_cpes)

    LOAD_EQUIVALENT_CPES_MUTEX.release()


def get_equivalent_cpes(cpe, product_db_cursor):
    # make sure equivalent CPEs are loaded
    load_equivalent_cpes(product_db_cursor)

    cpes = [cpe]
    cpe_split = cpe.split(":")
    cpe_prefix = ":".join(cpe_split[:5]) + ":"
    cpe_version, cpe_subversion = "*", "*"
    if len(cpe_split) > 5:
        cpe_version = cpe_split[5]
    if len(cpe_split) > 6:
        cpe_subversion = cpe_split[6]

    # if version part consists of more than one version parts, split into two CPE fields
    cpe_version_sections = CPEVersion(cpe_version).get_version_sections()
    if len(cpe_version_sections) > 1 and cpe_subversion in ("*", "", "-"):
        cpe_split[5] = cpe_version_sections[0]
        cpe_split[6] = "".join(cpe_version_sections[1:])
        cpes.append(":".join(cpe_split))

    # if CPE has subversion, create equivalent query with main version and subversion combined in one CPE field
    if cpe_subversion not in ("*", "", "-"):
        cpe_split[5] = cpe_version + "-" + cpe_subversion
        cpe_split[6] = "*"
        cpes.append(":".join(cpe_split))
        cpe_split[5] = cpe_version + cpe_subversion
        cpe_split[6] = "*"
        cpes.append(":".join(cpe_split))

    # get raw equivalent cpe prefixes, including transitively
    raw_equiv_cpe_prefixes = set()

    def get_additional_equiv_cpes(cpe_prefix):
        if cpe_prefix not in EQUIVALENT_CPES:
            return set()
        if cpe_prefix in raw_equiv_cpe_prefixes:
            return set()
        raw_equiv_cpe_prefixes.add(cpe_prefix)

        additional_cpe_prefixes = set()
        for other_cpe_prefix in EQUIVALENT_CPES[cpe_prefix]:
            if other_cpe_prefix not in raw_equiv_cpe_prefixes:
                additional_cpe_prefixes.add(other_cpe_prefix)
                additional_cpe_prefixes |= get_additional_equiv_cpes(other_cpe_prefix)
                raw_equiv_cpe_prefixes.add(other_cpe_prefix)

        return additional_cpe_prefixes

    for equivalent_cpe_prefix in EQUIVALENT_CPES.get(cpe_prefix, []):
        if equivalent_cpe_prefix not in raw_equiv_cpe_prefixes:
            raw_equiv_cpe_prefixes |= get_additional_equiv_cpes(equivalent_cpe_prefix)

    # generate proper equivalent CPEs with version info
    equiv_cpes = cpes.copy()
    for cur_cpe in cpes:
        cur_cpe_split = cur_cpe.split(":")
        for equivalent_cpe in raw_equiv_cpe_prefixes:
            equivalent_cpe_prefix = ":".join(equivalent_cpe.split(":")[:5]) + ":"
            if equivalent_cpe != cpe_prefix:
                equiv_cpes.append(equivalent_cpe_prefix + ":".join(cur_cpe_split[5:]))

    # lastly, add CPE equivalences of full CPEs including version
    add_equiv_cpes = []
    for cur_cpe in equiv_cpes:
        if cur_cpe in EQUIVALENT_CPES:
            add_equiv_cpes += EQUIVALENT_CPES[cur_cpe]
    equiv_cpes += add_equiv_cpes

    return equiv_cpes


def search_product_ids(
    query, product_db_cursor, current_product_ids, is_product_id_query, config, extra_params
):
    # if given query is not already a CPE, try to retrieve a CPE that matches
    # the query or create alternative CPEs that could match the query

    query = query.strip()
    if not query:
        return {"cpe": []}, {"cpe": []}

    # if CPEs were already provided as product IDs, do not run
    if current_product_ids.get("cpe", []):
        return {}, {}

    # perform CPE search if needed
    cpe, pot_cpes, cpe_search_results = None, [], []
    if not MATCH_CPE_23_RE.match(query):
        cpe_search_results = search_cpes(query, db_cursor=product_db_cursor, config=config)
        if cpe_search_results["cpes"]:
            cpes = cpe_search_results["cpes"]
            if cpes:
                cpe = cpes[0][0]
        pot_cpes = cpe_search_results.get("pot_cpes", [])
    else:
        cpe = query
        cpe_parts = cpe.split(":")
        if len(cpe_parts) < 13:
            cpe = cpe + (13 - len(cpe_parts)) * ":*"
        pot_cpes = [(cpe, 1)]

    # get equivalent CPEs
    all_product_ids, equivalent_cpes = {}, []
    if cpe:
        if is_product_id_query:
            equivalent_cpes = [cpe]  # only use provided CPE
        else:
            equivalent_cpes = get_equivalent_cpes(
                cpe, product_db_cursor
            )  # also search and use equivalent CPEs
        all_product_ids["cpe"] = equivalent_cpes

    if not all_product_ids:
        all_product_ids = {"cpe": []}

    return all_product_ids, {"cpe": pot_cpes}
