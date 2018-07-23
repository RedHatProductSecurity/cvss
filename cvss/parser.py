import re

from cvss import CVSS3, CVSS2
from cvss.exceptions import CVSSError


def parse_cvss_from_text(text):
    # :? at the beginning of paren () -> grouping is not extracted
    # Match may start with 'CVSS:3.0/'
    # Followed by CV
    matches = re.compile(r'((?:CVSS:3\.0/)?[A-Z][A-Za-z:/]+[A-Z])').findall(text)

    min_vector_length = 26
    cvsss = []
    for match in matches:
        if len(match) >= min_vector_length:
            try:
                if match.startswith('CVSS:3.0'):
                    cvss = CVSS3(match)
                else:
                    cvss = CVSS2(match)

                cvsss.append(cvss)
            except (CVSSError, KeyError):
                pass

    return cvsss
