import os
import re

import ujson

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DEB_PKG_CPE_MAP_FILE = os.path.join(SCRIPT_DIR, "deb_pkg_cpe_map.json")
HARDCODED_PKG_CPE_MATCHES_FILE = os.path.join(SCRIPT_DIR, "hardcoded_pkg_cpe_map.json")
UNNECESSARY_INFO_RE = re.compile(
    r"([+~]+(\d+|dfsg(\.\d)*|ds(\.\d)*|deb\d+u+\d+|debian\d+|git\+?[a-fA-F\d]+|r\d+|rc\d+|build[\w\.]+|esm\d|cs[\d\.]+))|(ubuntu[\d\.\~]+)|build[\w\.]+|\.STABLE\d+|\+stable[\w\~\-]+|pkg[\d\.]+|esm\d"
)
DECIMAL_COLON_START_RE = re.compile(r"^\d+:")
SPLIT_QUERY_TERMS_RE = re.compile(r"[ _\-\.]")
MATCH_VERSION_EPOCH_RE = re.compile(r"^\d+:")


def get_clean_version(version, codenames=None):
    """
    Get clean, simple version from complex distribution version,
    e.g., 1:115.0.2+dfsg~ubuntu16.04 -> 115.0.2
    """

    if not codenames:
        codenames = []

    clean_version = DECIMAL_COLON_START_RE.sub("", version)
    clean_version = UNNECESSARY_INFO_RE.sub("", clean_version)
    clean_version = clean_version.replace("~rc", "-rc")
    for codename in codenames:
        if codename in clean_version:
            clean_version = clean_version.split(codename)[0]
            break
    if clean_version and clean_version[-1] in ("~", "-", "+"):
        clean_version = clean_version[:-1]
    if not any(char.isdigit() for char in clean_version):
        clean_version = ""

    return clean_version


def extract_vendor_version(version: str) -> str:
    # 1. Perform general cleaning of unwanted strings
    version = get_clean_version(version)

    # 2. Remove Debian/Ubuntu revision (everything after last dash)
    if "-" in version:
        version = version.rsplit("-", 1)[0]

    # 3. Remove epoch if present (everything before first colon)
    if ":" in version:
        version = version.split(":", 1)[1]

    # 4. Remove remaining common Debian repack markers (+dfsg, +ds1, +repack, +really, etc.)
    version = re.sub(r"\+(dfsg|ds\d*|repack|really).*$", "", version)

    # Strip any accidental whitespace
    return version.strip()


def summarize_distro_backpatch(backpatch_info):
    """
    Summarize backpatch information, i.e. if the same version patches the
    vulnerability on different releases. Backpatch info is a tuple like
    (release_number, version_start, version_fixed)
    """
    if not backpatch_info:
        return []

    backpatch_info = sorted(backpatch_info, key=lambda bp: float(bp[0]))
    summarized_backpatch_info = []
    cur_version_end = None
    for i in range(len(backpatch_info)):
        if backpatch_info[i][2] != cur_version_end:
            summarized_backpatch_info.append(backpatch_info[i])
            cur_version_end = backpatch_info[i][2]

    return summarized_backpatch_info


def strip_epoch_from_version(version):
    return MATCH_VERSION_EPOCH_RE.sub("", version)


def get_hardcoded_pkg_cpe_matches():
    with open(HARDCODED_PKG_CPE_MATCHES_FILE) as f:
        return ujson.loads(f.read())


def split_deb_pkg_name(pkg):
    return SPLIT_QUERY_TERMS_RE.split(pkg)


def save_deb_pkg_cpe_map_to_file(pkg_cpe_map):
    with open(DEB_PKG_CPE_MAP_FILE, "w") as f:
        f.write(ujson.dumps(pkg_cpe_map))


def load_deb_pkg_cpe_map_from_file():
    with open(DEB_PKG_CPE_MAP_FILE) as f:
        return ujson.loads(f.read())


def del_deb_pkg_cpe_map_file():
    if os.path.isfile(DEB_PKG_CPE_MAP_FILE):
        os.remove(DEB_PKG_CPE_MAP_FILE)
