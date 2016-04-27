"""
Generates test vectors for testing of CVSS library. All of them are created using cvsslib
from https://pypi.python.org/pypi/cvsslib .

Simple vectors are all vector combinations without any optional values.
Random vectors are 100,000 randomly generated vectors.
Runs only with Python 3 because cvsslib does not support Python 2.
"""

from itertools import product
from random import choice

import cvsslib

from generate_constants import build_constants, METRICS, NAMES, VALUES


NR_OF_VECTORS = 100000


for cvss_version in range(2):
    # CVSS version selections
    if cvss_version == 0:
        cvsslib_module = cvsslib.cvss2
        cvss_name = '2'
        not_defined = 'ND'
        prefix = ''
    else:
        cvsslib_module = cvsslib.cvss3
        cvss_name = '3'
        not_defined = 'X'
        prefix = 'CVSS:3.0/'

    # Generate constants
    constants = build_constants(METRICS[cvss_version], NAMES[cvss_version], VALUES[cvss_version])
    metrics_abbreviations, metrics_mandatory, metrics_values, metrics_value_names = constants

    # Generate all simple vectors
    list_of_iterables = []
    for metric in metrics_mandatory:
        metric_options = [metric + ':' + value for value in metrics_values[metric]]
        list_of_iterables.append(metric_options)

    with open('vectors_simple{}'.format(cvss_name), 'w') as f:
        for combo in product(*list_of_iterables):
            combo = [a for a in combo if a != '']
            vector = '/'.join(combo)
            v = cvsslib.vector.calculate_vector(vector, module=cvsslib_module)
            print('{}{} - {}'.format(prefix, vector, v), file=f)

    # Generate random complex vectors
    list_of_iterables = []
    for metric in metrics_abbreviations:
        metric_options = [metric + ':' + value for value in metrics_values[metric]]
        if not_defined in metrics_values[metric]:  # not defined value can also be missing
            metric_options.append('')
        list_of_iterables.append(metric_options)

    with open('vectors_random{}'.format(cvss_name), 'w') as f:
        i = 0
        while i < NR_OF_VECTORS:
            combo = [choice(a) for a in list_of_iterables]
            combo = [a for a in combo if a != '']
            vector = '/'.join(combo)
            try:
                v = cvsslib.vector.calculate_vector(vector, module=cvsslib_module)
            except TypeError:
                pass
            else:
                print('{}{} - {}'.format(prefix, vector, v), file=f)
                i += 1
