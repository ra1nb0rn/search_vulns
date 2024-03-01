import re
import string

VERSION_PART_SEP_RE = re.compile(r'[^\da-zA-Z]')

class CPEVersion:

    def __init__(self, ver_str):
        self.version_str = ver_str

    def get_version_parts(self):
        re_version_parts = VERSION_PART_SEP_RE.split(self.version_str)
        return [part.lstrip('0') for part in re_version_parts]  # strip leading '0' from every part

    def __eq__(self, other):
        parts, other_parts = self.get_version_parts(), other.get_version_parts()
        if parts == other_parts:
            return True
        if (parts and not other_parts) or (not parts and other_parts):
            return False

        # check for equality if one version has trailing ".0"
        same_prefix = True
        for part_idx in range(min(len(parts), len(other_parts))):
            part, other_part = parts[part_idx], other_parts[part_idx]
            if part.lower() != other_part.lower():
                same_prefix = False

        if same_prefix:
            if len(parts) > len(other_parts) and all(x == "0" for x in parts[part_idx+1:]):
                return True
            if len(other_parts) > len(parts) and all(x == "0" for x in other_parts[part_idx+1:]):
                return True

    def __gt__(self, other):
        return not (self <= other)

    def __ge__(self, other):
        return self == other or self > other

    def __lt__(self, other):
        parts, other_parts = self.get_version_parts(), other.get_version_parts()

        min_part_count = min(len(parts), len(other_parts))
        for part_idx in range(min_part_count):
            part, other_part = parts[part_idx], other_parts[part_idx]

            # right-pad with '0' to make both parts the same length
            if len(part) < len(other_part):
                part = part.rjust(len(other_part), '0')
            if len(other_part) < len(part):
                other_part = other_part.rjust(len(part), '0')

            # if both parts are empty / were zeroes
            if (not part) and (not other_part):
                # continue if not in last step and return False otherwise
                if part_idx < len(parts)-1 and part_idx < len(other_parts)-1:
                    continue
                return False

            # if the comparison is not in the last step and the current parts are equal
            if part_idx < len(parts)-1 and part_idx < len(other_parts)-1:
                if part.lower() == other_part.lower():
                    continue

            # compare parts char by char
            for i in range(len(part)):
                if ord(part[i].lower()) < ord(other_part[i].lower()):
                    return True
                if ord(part[i].lower()) > ord(other_part[i].lower()):
                    return False

                # very last part of the comparison and both parts are equal
                if (i == len(part) - 1 and part_idx == min_part_count - 1 and
                    len(parts) == len(other_parts) and
                    len(part) == len(other_part) and
                    ord(part[i].lower()) == ord(other_part[i].lower())):
                    return False

        if len(parts) > len(other_parts):
            return False

        return True

    def __le__(self, other):
        return self == other or self < other

    def __str__(self):
        return self.version_str

    def __bool__(self):
        return str(self) not in ('-', '*') or not str(self)
