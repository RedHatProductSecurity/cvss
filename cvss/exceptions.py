# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: GPLv3+

"""
All exceptions needed by CVSS library.
"""


class CVSSError(Exception):
    """
    General CVSS exception.
    """
    pass


class CVSS2Error(CVSSError):
    """
    General CVSS2 exception.
    """
    pass


class CVSS2MalformedError(CVSS2Error):
    """
    Exception for malformed input CVSS2 vectors.
    """
    pass


class CVSS2MandatoryError(CVSS2Error):
    """
    Exception for missing mandatory fields.
    """
    pass


class CVSS3Error(CVSSError):
    """
    General CVSS3 exception.
    """
    pass


class CVSS3MalformedError(CVSS3Error):
    """
    Exception for malformed input CVSS3 vectors.
    """
    pass


class CVSS3MandatoryError(CVSS3Error):
    """
    Exception for missing mandatory fields.
    """
    pass