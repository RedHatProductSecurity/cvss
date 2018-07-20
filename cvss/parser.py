import re

from cvss import CVSS3, CVSS2
from cvss.exceptions import CVSSError


def parse_cvss_from_text(text):
    # :? at the beginning of paren () -> grouping is not extracted
    matches = re.compile(r'((?:CVSS:3\.0)?[A-Za-z:/]+)').findall(text)

    cvsss = []
    for match in matches:
        try:
            if match.startswith('CVSS:3.0'):
                cvss = CVSS3(match)
            else:
                cvss = CVSS2(match)

            cvsss.append(cvss)
        except (CVSSError, KeyError):
            pass

    return cvsss
