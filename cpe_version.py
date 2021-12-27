import string

from requests.models import iter_slices

class CPEVersion:

    def __init__(self, ver_str):
        self.version_str = ver_str

    def get_version_parts(self):
        parts = []
        cur_part = ''
        cur_char_class = string.digits
        is_leading_zeroes = False
        for char in self.version_str:
            if char not in cur_char_class:
                if cur_part:
                    parts.append(cur_part)
                cur_part = ''
                is_leading_zeroes = False
                if char in string.digits:
                    cur_char_class = string.digits
                    if char == '0':
                        is_leading_zeroes = True
                elif char in string.ascii_letters:
                    cur_char_class = string.ascii_letters
                else:
                    cur_char_class = string.punctuation

            if char not in string.punctuation:
                if is_leading_zeroes and char == '0':
                    continue
                is_leading_zeroes = False
                cur_part += char

        if cur_part:
            parts.append(cur_part)

        return parts

    def __eq__(self, other):
        parts, other_parts = self.get_version_parts(), other.get_version_parts()
        return parts == other_parts

    def __gt__(self, other):
        return not (self <= other)

    def __ge__(self, other):
        return self == other or self > other

    def __lt__(self, other):
        parts, other_parts = self.get_version_parts(), other.get_version_parts()

        for part_idx in range(min(len(parts), len(other_parts))):
            part, other_part = parts[part_idx], other_parts[part_idx]
            if part_idx < len(parts)-1 and part_idx < len(other_parts)-1:
                if part.lower() == other_part.lower():
                    continue

            val_part, val_part_other = 0, 0

            # Variant 1: full "value" of version part matters
            # for i, char in enumerate(part):
            #     if char in string.digits:
            #         val_part += int(char) * 10**(len(part)-i)
            #     else:
            #         val_part += (string.ascii_lowercase.find(char.lower())+1) * 36**(len(part)-i)

            # for i, char in enumerate(other_part):
            #     if char in string.digits:
            #         val_part_other += int(char) * 10**(len(other_part)-i)
            #     else:
            #         val_part_other += (string.ascii_lowercase.find(char.lower())+1) * 36**(len(other_part)-i)

            # if val_part >= val_part_other:
            #     return False
            # return True  # if version part in front is smaller, the entire version is already smaller

            # Variant 2: with version numbers made up of letters, the letters are compared step by step
            if part[0].lower() in string.ascii_lowercase and other_part[0] in string.digits:
                return False
            elif part[0].lower() in string.digits and other_part[0] in string.ascii_lowercase:
                return True
            elif part[0] in string.ascii_letters:
                iter_max = min(len(part), len(other_part))
                for i in range(iter_max):
                    if ord(part[i].lower()) > ord(other_part[i].lower()):
                        return False
                    if i == iter_max - 1 and ord(part[i].lower()) == ord(other_part[i].lower()):
                        return False
            else:
                for i, char in enumerate(part):
                    val_part += int(char) * 10**(len(part)-i)

                for i, char in enumerate(other_part):
                    val_part_other += int(char) * 10**(len(other_part)-i)

                if val_part >= val_part_other:
                    return False
                return True  # if version part in front is smaller, the entire version is already smaller

        return True

    def __le__(self, other):
        return self == other or self < other

    def __str__(self):
        return self.version_str
