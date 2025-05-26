import re

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError


def parse_cvss_from_text(text):
    """
    Parses CVSS2, CVSS3, and CVSS4 vectors from arbitrary text and returns a list of CVSS objects.

    Parses text for substrings that look similar to CVSS vector
    and feeds these matches to CVSS constructor.

    Args:
        text (str): arbitrary text
    Returns:
        A list of CVSS objects.
    """
    # Looks for substrings that resemble CVSS2, CVSS3, or CVSS4 vectors.
    # CVSS3 and CVSS4 vectors start with a 'CVSS:x.x/' prefix and are matched by the optional
    # non-capturing group.
    # CVSS2 vectors do not include a prefix and are matched by raw vector pattern only.
    # Minimum total match length is 26 characters to reduce false positives.
    matches = re.compile(r"(?:CVSS:[3-4]\.\d/)?[A-Za-z:/]{26,}").findall(text)

    cvsss = set()
    for match in matches:
        try:
            if match.startswith("CVSS:4."):
                cvss = CVSS4(match)
            elif match.startswith("CVSS:3."):
                cvss = CVSS3(match)
            else:
                cvss = CVSS2(match)

            cvsss.add(cvss)
        except (CVSSError, KeyError):
            pass

    return list(cvsss)
