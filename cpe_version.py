import re
import string

VERSION_PART_SEP_RE = re.compile(r'[^\da-zA-Z]')
SUBVERSION_PART_SEP_RE = re.compile(r'([a-zA-Z]+|[\d]+)')
SUBVERSION_PART_SEP_WITH_DOTS_RE = re.compile(r'([a-zA-Z\.]+|[\d\.]+)')
UPDATE_VERSION_FORMAT_RE = re.compile(r'((update(\d+))|(u(\d+)))')
CONSIDER_SUBVERSION_VERSION_RE = re.compile(r'^.*-[0-9]+$')

class CPEVersion:

    def __init__(self, ver_str: str):
        self.version_str = ver_str

    def get_version_parts(self):
        split_version_parts = VERSION_PART_SEP_RE.split(self.version_str)
        version_parts = []

        for split_part in split_version_parts:
            subversions = SUBVERSION_PART_SEP_RE.findall(split_part)
            version_parts += subversions

        return [part.lstrip('0') for part in version_parts]  # strip leading '0' from every part

    def get_version_sections(self):
        return SUBVERSION_PART_SEP_WITH_DOTS_RE.findall(str(self))

    def __eq__(self, other):
        parts, other_parts = self.get_version_parts(), other.get_version_parts()
        if parts == other_parts:
            return True
        if (parts and not other_parts) or (not parts and other_parts):
            return False

        # check if versions are in form 'update123' or 'u123' (e.g. cpe:2.3:a:trendmicro:deep_security_agent:20.0:update1559:)
        if parts[0] == 'u' and other_parts[0] == 'update':
            other_parts[0] = 'u'
        elif parts[0] == 'update' and other_parts[0] == 'u':
            parts[0] = 'u'

        # check for equality if one version has trailing ".0"
        same_prefix = True
        for part_idx in range(min(len(parts), len(other_parts))):
            part, other_part = parts[part_idx], other_parts[part_idx]
            if part.lower() != other_part.lower():
                same_prefix = False

        if same_prefix:
            if len(parts) > len(other_parts) and all(not x or x == "0" for x in parts[part_idx+1:]):
                return True
            if len(other_parts) > len(parts) and all(not x or x == "0" for x in other_parts[part_idx+1:]):
                return True
            if len(parts) == len(other_parts):
                for i in range(len(parts)):
                    if parts[i] != other_parts[i]:
                        return False
                return True
        return False

    def __gt__(self, other):
        return not (self <= other)

    def __ge__(self, other):
        return self == other or self > other

    def __lt__(self, other):
        parts, other_parts = self.get_version_parts(), other.get_version_parts()

        # check if versions are in form 'update123' or 'u123' (e.g. cpe:2.3:a:trendmicro:deep_security_agent:20.0:update1559:)
        if parts and parts[0] == 'u' and other_parts and other_parts[0] == 'update':
            other_parts[0] = 'u'
        elif parts and parts[0] == 'update' and other_parts and other_parts[0] == 'u':
            parts[0] = 'u'

        min_part_count = min(len(parts), len(other_parts))
        for part_idx in range(min_part_count):
            part, other_part = parts[part_idx], other_parts[part_idx]

            # if parts are empty / were zeroes
            if (not part) and (not other_part):
                # continue if not in last step and return False otherwise
                if part_idx < len(parts)-1 and part_idx < len(other_parts)-1:
                    continue
                return False
            if not other_part:
                return False
            if not part:
                return True

            # right-pad with '0' to make both parts the same length
            if len(part) < len(other_part) and part[0] in string.digits:
                part = part.rjust(len(other_part), '0')
            if len(other_part) < len(part) and other_part[0] in string.digits:
                other_part = other_part.rjust(len(part), '0')

            # if the comparison is not in the last step and the current parts are equal
            if part_idx < len(parts)-1 and part_idx < len(other_parts)-1:
                if part.lower() == other_part.lower():
                    continue

            # compare parts char by char
            for i in range(len(part)):
                if i > len(part)-1:  # part is shorter
                    return True
                if i > len(other_part)-1:  # other_part is shorter
                    return False

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
        return str(self) not in ('-', '*', '')

    def __add__(self, other):
        if not self:
            return other
        if not other:
            return self

        return CPEVersion(str(self) + str(other))

    def considered_equal(self, other):
        '''
        Evaluate if a version from the distro is considered equal to a version from the database
        consider e.g. 1.1.1 and 1.1.1-5 as equal, b/c you mean with 1.1.1 the highest 
        subversion of 1.1.1 and this subversion is <= 1.1.1-5
        But 1.1.1 and 1.1 are not considered equal, b/c you probably meant 1.1.0 with 1.1
        '''

        parts, other_parts = self.get_version_parts(), other.get_version_parts()

        # do not consider emtpy string and version as equal
        if len(parts) == 0 or len(other_parts) == 0:
            return False
 
        if len(parts) == len(other_parts) +1 and \
            CONSIDER_SUBVERSION_VERSION_RE.match(other.version_str):
            return other_parts[:len(parts)] == parts
        elif len(parts) == len(other_parts) +1 and \
            CONSIDER_SUBVERSION_VERSION_RE.match(self.version_str):
            return parts[:len(other_parts)] == other_parts
        return self == other