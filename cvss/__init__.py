# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .exceptions import CVSSError, CVSS2Error, CVSS3Error
from .interactive import ask_interactively


__version__ = '2.2'
