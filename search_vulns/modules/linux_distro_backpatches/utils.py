import re

UNNECESSARY_INFO_RE = re.compile(r"[+~](\d+|dfsg(\.\d)*|ds(\.\d)*|deb\d+u+\d+|git[a-fA-F\d]+)")
DECIMAL_COLON_START_RE = re.compile(r"^\d+:")


def get_clean_version(version):
    """
    Get clean, simple version from complex distribution version,
    e.g., 1:115.0.2+dfsg~ubuntu16.04 -> 115.0.2
    """

    clean_version = DECIMAL_COLON_START_RE.sub("", version)
    return UNNECESSARY_INFO_RE.sub("", clean_version)
