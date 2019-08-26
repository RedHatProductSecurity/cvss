import re

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .exceptions import CVSSError


def parse_cvss_from_text(text):
    """
    Parses CVSS2 and CVSS3 vectors from arbitrary text and returns a list of CVSS objects.

    Parses text for substrings that look similar to CVSS vector
    and feeds these matches to CVSS constructor.

    Args:
        text (str): arbitrary text
    Returns:
        A list of CVSS objects.
    """
    # Looks for substrings which resemble CVSS2 or CVSS3 vectors.
    # CVSS3 vector starts with 'CVSS:3.x/' prefix - matched by non-capturing group.
    # Minimum vector length is 26.
    matches = re.compile(r'(?:CVSS:3\.\d/)?[A-Za-z:/]{26,}').findall(text)

    cvsss = set()
    for match in matches:
        try:
            if match.startswith('CVSS:3.'):
                cvss = CVSS3(match)
            else:
                cvss = CVSS2(match)

            cvsss.add(cvss)
        except (CVSSError, KeyError):
            pass

    return list(cvsss)
