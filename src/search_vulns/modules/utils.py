import math
import re
import shlex
import subprocess
from collections import Counter

import requests

# import and provide these functionalities from this module for simplicity
from cpe_search.database_wrapper_functions import (
    get_database_connection,
    is_safe_db_name,
)
from tqdm import tqdm

from ..cpe_version import CPEVersion
from ..vulnerability import MatchReason

CPE_COMPARISON_STOP_CHARS_RE = re.compile(r"[\+\-\_\~]")
NUMERIC_VERSION_RE = re.compile(r"[\d\.]+")
NON_ALPHANUMERIC_SPLIT_RE = re.compile(r"[^a-zA-Z]")
SQLITE_TIMEOUT = 300
VULN_ID_RE = re.compile(r"((?:(?<=^)|(?<=\s))([A-Za-z]+(?:[-_]\w+){2,})(?=\s|$))")


def _is_cpe_version_start_end_matching(
    cpe_parts, version_start, version_start_incl, version_end, version_end_incl
):
    """Return boolean whether the provided CPE version lies within the provided range modifiers"""

    version_start = CPEVersion(version_start)
    version_end = CPEVersion(version_end)

    # combine version and subversion if NVD merged both for version_end as well
    cpe_product = cpe_parts[4]
    cpe_version, cpe_subversion = CPEVersion("*"), CPEVersion("*")
    # check that CPE is not short/incomplete
    if len(cpe_parts) > 5:
        cpe_version = CPEVersion(cpe_parts[5])
    if len(cpe_parts) > 6:
        cpe_subversion = CPEVersion(cpe_parts[6])

    # try to merge version and subversion if needed
    if version_end:
        version_end_sections = version_end.get_version_sections()
        cpe_version_subsections = cpe_version.get_version_sections()
        if len(version_end_sections) > len(cpe_version_subsections):
            # if queried CPE has a subversion / patch-level, merge this with the base version
            if cpe_subversion:
                cpe_version = cpe_version + cpe_subversion
                cpe_version_sections = cpe_version.get_version_sections()
                if len(cpe_version_sections) != len(version_end_sections):
                    # try to adjust cpe_version, such that it ideally has the same number of sections as version_end
                    final_cpe_version_sections = []
                    i, j = 0, 0
                    while i < len(cpe_version_sections) and j < len(version_end_sections):
                        # if same version type (numeric or alphanumeric), use version field, otherwise leave it out
                        cpe_version_section_numeric_match = NUMERIC_VERSION_RE.match(
                            cpe_version_sections[i]
                        )
                        version_end_section_numeric_match = NUMERIC_VERSION_RE.match(
                            version_end_sections[j]
                        )

                        if (
                            cpe_version_section_numeric_match
                            and version_end_section_numeric_match
                        ):
                            final_cpe_version_sections.append(cpe_version_sections[i])
                            j += 1
                        elif (
                            not cpe_version_section_numeric_match
                            and not version_end_section_numeric_match
                        ):
                            final_cpe_version_sections.append(cpe_version_sections[i])
                            j += 1
                        i += 1
                    cpe_version = CPEVersion(" ".join(final_cpe_version_sections))
            else:
                # check if the version_end string starts with the product name
                # (e.g. 'esxi70u1c-17325551' from https://nvd.nist.gov/vuln/detail/CVE-2020-3999)
                product_parts = [
                    word.strip() for word in NON_ALPHANUMERIC_SPLIT_RE.split(cpe_product)
                ]
                cpe_version_sections = cpe_version.get_version_sections()
                for part in product_parts:
                    # ... if it does, prefix cpe_version with the CPE product name
                    if str(version_end).startswith(part):
                        if "." not in str(version_end):
                            cpe_version = CPEVersion(str(cpe_version).replace(".", ""))
                        cpe_version = CPEVersion(part) + cpe_version
                        break

        # fallback if subversion merging did not work
        if not cpe_version:
            cpe_version = CPEVersion(cpe_parts[5])
    else:
        # set a max version if end is not given explicitly
        version_end = CPEVersion("z" * 256)

    # check if version start or end matches exactly, otherwise return if in range
    if version_start_incl and cpe_version == version_start:
        return True
    if version_end_incl and cpe_version == version_end:
        return True
    return version_start < cpe_version < version_end


def _is_cpe_included_from_field(cpe1, cpe2, field=6):
    """Return True if cpe1 is included in cpe2 starting from the provided field"""

    cpe1_remainder_fields = cpe1.split(":")[field:]
    cpe2_remainder_fields = cpe2.split(":")[field:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        # CPE wildcards
        if cpe1_remainder_fields[i] in ("*", "-"):
            continue
        if cpe2_remainder_fields[i] in ("*", "-"):
            continue

        # remove irrelevant chars
        cpe1_remainder_fields[i] = CPE_COMPARISON_STOP_CHARS_RE.sub(
            "", cpe1_remainder_fields[i]
        )
        cpe2_remainder_fields[i] = CPE_COMPARISON_STOP_CHARS_RE.sub(
            "", cpe2_remainder_fields[i]
        )

        # alpha and beta version abbreviations
        if cpe1_remainder_fields[i] == "alpha" and cpe2_remainder_fields[i] == "a":
            continue
        if cpe2_remainder_fields[i] == "alpha" and cpe1_remainder_fields[i] == "a":
            continue
        if cpe1_remainder_fields[i] == "beta" and cpe2_remainder_fields[i] == "b":
            continue
        if cpe2_remainder_fields[i] == "beta" and cpe1_remainder_fields[i] == "b":
            continue

        if field + i == 5 or field + i == 6:  # CPE version or subversion field
            if CPEVersion(cpe1_remainder_fields[i]) == CPEVersion(cpe2_remainder_fields[i]):
                continue

        if cpe1_remainder_fields[i] != cpe2_remainder_fields[i]:
            return False

    return True


def split_cpe(cpe):
    """Split a CPE by ':' into its individual fields, preserving escaped colons"""

    parts = []
    current = []
    escape = False

    for char in cpe:
        if char == ":" and not escape:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        escape = char == "\\"
    parts.append("".join(current))

    return parts


def get_cpe_product_prefix(cpe):
    """Return CPE product prefix, e.g. cpe:2.3:a:apache:tomcat:"""

    return ":".join(split_cpe(cpe)[:5]) + ":"


def _is_more_specific_cpe_contained(vuln_cpe, vuln_entry_cpes):
    """
    Return boolean whether a more specific CPE than vuln_cpe
    is contained in the databases list of affected CPEs.
    """

    for vuln_other_cpe in vuln_entry_cpes:
        if vuln_cpe != vuln_other_cpe:
            if _is_cpe_included_from_field(vuln_cpe, vuln_other_cpe, 5):
                # assume the number of fields is the same for both, since they're official NVD CPEs
                vuln_cpe_fields, vuln_other_cpe_fields = split_cpe(vuln_cpe), split_cpe(
                    vuln_other_cpe
                )
                for i in range(len(vuln_other_cpe_fields) - 1, -1, -1):
                    vuln_cpe_field_version = CPEVersion(vuln_cpe_fields[i])
                    vuln_other_cpe_field_version = CPEVersion(vuln_other_cpe_fields[i])
                    if (not vuln_cpe_field_version) and (not vuln_other_cpe_field_version):
                        continue
                    elif (not vuln_cpe_field_version) and vuln_other_cpe_field_version:
                        return True
                    else:
                        break
    return False


def _has_cpe_lower_versions(cpe1, cpe2):
    """Return True if cpe1 is considered to have a lower product version than cpe2"""

    cpe1_remainder_fields = cpe1.split(":")[5:]
    cpe2_remainder_fields = cpe2.split(":")[5:]

    for i in range(min(len(cpe1_remainder_fields), len(cpe2_remainder_fields))):
        if cpe1_remainder_fields[i] in ("*", "-"):
            continue
        if cpe2_remainder_fields[i] in ("*", "-"):
            continue

        if CPEVersion(cpe1_remainder_fields[i]) > CPEVersion(cpe2_remainder_fields[i]):
            return False
    return True


def _is_cpe_included_after_version(cpe1, cpe2):
    """Return True if cpe1 is included in cpe2 starting after the version"""

    return _is_cpe_included_from_field(cpe1, cpe2)


def search_vulns_by_cpes_simple(cpes, vuln_db_cursor, vuln_id_column, db_name):
    """Search vulns in a simple (cve_id, cpe, cpe_version_start,
    is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including)
    table schema."""

    # retrieve vulnerabilities via CPEs and formal applicability statements
    vulns = []
    for cpe in cpes:
        cpe_parts = cpe.split(":")
        cpe_version = CPEVersion(cpe_parts[5])

        general_cpe_prefix_query = ":".join(cpe.split(":")[:5]) + ":"
        if "mariadb" in str(type(vuln_db_cursor)):  # backslashes have to be escaped for MariaDB
            general_cpe_prefix_query = general_cpe_prefix_query.replace("\\", "\\\\")

        if (not vuln_id_column.isidentifier()) or (not db_name.isidentifier()):
            raise ValueError("vuln_id_column or db_name is not a valid identifier")

        query = (
            f"SELECT {vuln_id_column}, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end, "
            + f"is_cpe_version_end_including FROM {db_name} WHERE cpe LIKE ?"
        )

        vuln_db_cursor.execute(query, (general_cpe_prefix_query + "%%",))
        general_cpe_vuln_data = set()
        if vuln_db_cursor:
            general_cpe_vuln_data = set(vuln_db_cursor.fetchall())
        general_cpe_vuln_data_structered = {}

        for vuln_cpe_entry in general_cpe_vuln_data:
            if vuln_cpe_entry[0] not in general_cpe_vuln_data_structered:
                general_cpe_vuln_data_structered[vuln_cpe_entry[0]] = []
            general_cpe_vuln_data_structered[vuln_cpe_entry[0]].append(vuln_cpe_entry)

        for vuln_id, vuln_cpe_data in general_cpe_vuln_data_structered.items():
            vuln_cpe_entries = [vuln_cpe_entry[1] for vuln_cpe_entry in vuln_cpe_data]
            for vuln_cpe_entry in vuln_cpe_data:
                vuln_cpe = vuln_cpe_entry[1]
                version_start, version_start_incl = vuln_cpe_entry[2:4]
                version_end, version_end_incl = vuln_cpe_entry[4:]

                is_cpe_vuln, bad_nvd_entry = False, False
                match_reason = ""
                is_cpe_vuln = _is_cpe_included_from_field(cpe, vuln_cpe, 5)
                if is_cpe_vuln:
                    match_reason = MatchReason.PRODUCT_MATCH

                if cpe_version and (version_start or version_end):
                    # additionally check if version matches range
                    is_cpe_vuln = _is_cpe_version_start_end_matching(
                        cpe_parts,
                        version_start,
                        version_start_incl,
                        version_end,
                        version_end_incl,
                    )
                    match_reason = MatchReason.VERSION_IN_RANGE
                elif is_cpe_vuln:
                    # check if the NVD's affected products entry for the CPE is considered faulty
                    bad_nvd_entry = _is_more_specific_cpe_contained(vuln_cpe, vuln_cpe_entries)

                    # check for general CPE vuln match
                    if not CPEVersion(vuln_cpe.split(":")[5]):
                        if not cpe_version:
                            match_reason = MatchReason.GENERAL_PRODUCT_OK
                        else:
                            match_reason = MatchReason.GENERAL_PRODUCT_UNCERTAIN
                elif len(vuln_cpe_entries) == 1 and _has_cpe_lower_versions(cpe, vuln_cpe):
                    is_cpe_vuln = True
                    match_reason = MatchReason.SINGLE_HIGHER_VERSION

                # final check that everything after the version field matches in the vuln's CPE
                if is_cpe_vuln:
                    if cpe.count(":") > 5 and vuln_cpe.count(":") > 5:
                        if not _is_cpe_included_after_version(cpe, vuln_cpe):
                            is_cpe_vuln = False

                if is_cpe_vuln and not bad_nvd_entry:
                    vulns.append((vuln_id, match_reason))
                    break

    return vulns


def compute_cosine_similarity(text_1: str, text_2: str, text_vector_regex=r"[a-zA-Z0-9\.]+"):
    """
    Compute the cosine similarity of two text strings.
    :param text_1: the first text
    :param text_2: the second text
    :return: the cosine similarity of the two text strings
    """

    def text_to_vector(text: str):
        """
        Get the vector representation of a text. It stores the word frequency
        of every word contained in the given text.
        :return: a Counter object that stores the word frequencies in a dict
                 with the respective word as key
        """
        word = re.compile(text_vector_regex)
        words = word.findall(text)
        return Counter(words)

    text_vector_1, text_vector_2 = text_to_vector(text_1), text_to_vector(text_2)

    intersecting_words = set(text_vector_1.keys()) & set(text_vector_2.keys())
    inner_product = sum([text_vector_1[w] * text_vector_2[w] for w in intersecting_words])

    abs_1 = math.sqrt(sum([cnt**2 for cnt in text_vector_1.values()]))
    abs_2 = math.sqrt(sum([cnt**2 for cnt in text_vector_2.values()]))
    normalization_factor = abs_1 * abs_2

    if not normalization_factor:  # avoid divison by 0
        return 0.0
    return float(inner_product) / float(normalization_factor)


def get_versionless_cpes_of_nvd_cves(cve_ids, vulndb_cursor):
    """Return all CPEs affected by the given cve_ids with their version removed"""
    if not isinstance(cve_ids, list):
        cve_ids = [cve_ids]

    all_nvd_cpes = set()
    for cve_id in cve_ids:
        vulndb_cursor.execute("SELECT cpe FROM nvd_cpe WHERE cve_id = ?", (cve_id,))
        nvd_cpes = vulndb_cursor.fetchall()
        if nvd_cpes:  # MariaDB returns None and SQLite an empty list
            for cpe in nvd_cpes:
                cpe_split = cpe[0].split(":")
                cpe_version_wildcarded = (
                    ":".join(cpe_split[:5]) + ":*:*:" + ":".join(cpe_split[7:])
                )
                all_nvd_cpes.add(cpe_version_wildcarded)

    return list(all_nvd_cpes)


def download_file(src, dest, show_progressbar=False):
    """Download file from src to dest and optionally show a progress bar."""

    # Adapted from: https://stackoverflow.com/a/37573701

    response = requests.get(src, stream=True)
    if response.status_code != 200:
        raise RuntimeError("Could not download file %s, bad status code" % src)
    total_size = int(response.headers.get("content-length", 0))
    received_size = 0
    block_size = 8192
    filename = src.split("/")[-1]

    with tqdm(
        total=total_size, unit="B", unit_scale=True, desc=filename, disable=not show_progressbar
    ) as progress_bar:
        with open(dest, "wb") as file:
            for data in response.iter_content(block_size):
                progress_bar.update(len(data))
                file.write(data)
                received_size += len(data)

    if total_size != 0 and received_size != total_size:
        raise RuntimeError("Could not download file %s" % src)

    return True


def download_github_folder(repo_url, repo_folder, dest):
    """
    Download the given folder from the given URL to the given destination
    on the local filesystem. Returns True on success, False on failure.
    """

    repo_url_esc = shlex.quote(repo_url)
    repo_folder_esc = shlex.quote(repo_folder)
    dest_esc = shlex.quote(dest)

    if repo_url != repo_url_esc or repo_folder != repo_folder_esc or dest != dest_esc:
        return False

    return_code = subprocess.call(
        "git clone -n --depth=1 --filter=tree:0 '%s' '%s' && " % (repo_url_esc, dest_esc)
        + "cd '%s' && " % dest_esc
        + "git sparse-checkout set --no-cone '%s' && " % repo_folder_esc
        + "git checkout",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if return_code != 0:
        return False
    return True
