import re

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError


def parse_cvss_from_text(text):
    matches = re.compile(r'(CVSS:3.0/[A-Z:/]+)').findall(text)

    cvss3s = []
    for match in matches:
        try:
            cvss3 = CVSS3(match)
            cvss3s.append(cvss3)
        except (CVSS3MalformedError, KeyError):
            pass

    return cvss3s
