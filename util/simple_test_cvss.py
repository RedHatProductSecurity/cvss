"""
This is a simple test against cvsslib from https://pypi.python.org/pypi/cvsslib .
Runs only with Python 3 because cvsslib does not support Python 2.
"""

import cvss
import cvsslib


vector_string = 'AV:L/AC:M/Au:N/C:N/I:N/A:N/E:F/RL:W/RC:C/TD:L/CR:H/IR:ND'
result = cvss.CVSS2(vector_string).scores()
expected = cvsslib.vector.calculate_vector(vector_string, module=cvsslib.cvss2)
print('CVSS2')
print(expected)
print(result)

print()

vector_string = 'AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H'
result = cvss.CVSS2(vector_string).scores()
expected = cvsslib.vector.calculate_vector(vector_string, module=cvsslib.cvss2)
print('CVSS2')
print(expected)
print(result)

print()

vector_string = 'AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:W/CR:X/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:N/MA:X'
result = cvss.CVSS3(vector_string).scores()
expected = cvsslib.vector.calculate_vector(vector_string, module=cvsslib.cvss3)
print('CVSS3')
print(expected)
print(result)
