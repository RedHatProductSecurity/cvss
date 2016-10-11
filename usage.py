"""
Usage examples for CVSS library.
"""

from __future__ import print_function, unicode_literals

from cvss import CVSS2, CVSS3


vector = 'AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M'
c = CVSS2(vector)
print(vector)
print(c.clean_vector())
print(c.scores())

print()

vector = 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'
c = CVSS3(vector)
print(vector)
print(c.clean_vector())
print(c.scores())
print(c.severities())
