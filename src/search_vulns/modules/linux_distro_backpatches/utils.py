import os
import re

import ujson

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PKG_CPE_MAP_FILE = os.path.join(SCRIPT_DIR, "pkg_cpe_map.json")
UNNECESSARY_INFO_RE = re.compile(
    r"([+~](\d+|dfsg(\.\d)*|ds(\.\d)*|deb\d+u+\d+|git[a-fA-F\d]+|build\w+))|(ubuntu[\d\.\~]+)|build\w+|\.STABLE\d+|\+stable[\w\~\-]+|pkg[\d\.]+"
)
DECIMAL_COLON_START_RE = re.compile(r"^\d+:")


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


def save_pkg_cpe_map_to_file(pkg_cpe_map):
    with open(PKG_CPE_MAP_FILE, "w") as f:
        f.write(ujson.dumps(pkg_cpe_map))


def load_pkg_cpe_map_from_file():
    with open(PKG_CPE_MAP_FILE) as f:
        return ujson.loads(f.read())


def del_pkg_cpe_map_file():
    if os.path.isfile(PKG_CPE_MAP_FILE):
        os.remove(PKG_CPE_MAP_FILE)
