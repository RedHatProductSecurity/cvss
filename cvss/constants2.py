# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Constants for CVSS2 computations and checks. Generated using util/generate_constants.py.
"""

from __future__ import unicode_literals

from decimal import Decimal as D

try:
    from collections import OrderedDict
except ImportError:
    # noinspection PyUnresolvedReferences
    from ordereddict import OrderedDict


METRICS_ABBREVIATIONS = OrderedDict([('AV', 'Access Vector'),
                                     ('AC', 'Access Complexity'),
                                     ('Au', 'Authentication'),
                                     ('C', 'Confidentiality Impact'),
                                     ('I', 'Integrity Impact'),
                                     ('A', 'Availability Impact'),
                                     ('E', 'Exploitability'),
                                     ('RL', 'Remediation Level'),
                                     ('RC', 'Report Confidence'),
                                     ('CDP', 'Collateral Damage Potential'),
                                     ('TD', 'Target Distribution'),
                                     ('CR', 'Confidentiality Requirement'),
                                     ('IR', 'Integrity Requirement'),
                                     ('AR', 'Availability Requirement'),
                                     ])

METRICS_MANDATORY = ['AV', 'AC', 'Au', 'C', 'I', 'A']

METRICS_VALUES = {'AV': {'L': D('0.395'), 'A': D('0.646'), 'N': D('1')},
                  'AC': {'H': D('0.35'), 'M': D('0.61'), 'L': D('0.71')},
                  'Au': {'M': D('0.45'), 'S': D('0.56'), 'N': D('0.704')},
                  'C': {'N': D('0'), 'P': D('0.275'), 'C': D('0.660')},
                  'I': {'N': D('0'), 'P': D('0.275'), 'C': D('0.660')},
                  'A': {'N': D('0'), 'P': D('0.275'), 'C': D('0.660')},
                  'E': {'U': D('0.85'), 'POC': D('0.9'), 'F': D('0.95'), 'H': D('1'), 'ND': D('1')},
                  'RL': {'OF': D('0.87'), 'TF': D('0.90'), 'W': D('0.95'), 'U': D('1'), 'ND': D('1')},
                  'RC': {'UC': D('0.9'), 'UR': D('0.95'), 'C': D('1'), 'ND': D('1')},
                  'CDP': {'N': D('0'), 'L': D('0.1'), 'LM': D('0.3'), 'MH': D('0.4'), 'H': D('0.5'), 'ND': D('0')},
                  'TD': {'N': D('0'), 'L': D('0.25'), 'M': D('0.75'), 'H': D('1'), 'ND': D('1')},
                  'CR': {'L': D('0.5'), 'M': D('1'), 'H': D('1.51'), 'ND': D('1')},
                  'IR': {'L': D('0.5'), 'M': D('1'), 'H': D('1.51'), 'ND': D('1')},
                  'AR': {'L': D('0.5'), 'M': D('1'), 'H': D('1.51'), 'ND': D('1')},
                  }

METRICS_VALUE_NAMES = OrderedDict([('AV', OrderedDict([('L', 'Local'),
                                                       ('A', 'Adjacent Network'),
                                                       ('N', 'Network')])),
                                   ('AC', OrderedDict([('H', 'High'),
                                                       ('M', 'Medium'),
                                                       ('L', 'Low')])),
                                   ('Au', OrderedDict([('M', 'Multiple'),
                                                       ('S', 'Single'),
                                                       ('N', 'None')])),
                                   ('C', OrderedDict([('N', 'None'),
                                                      ('P', 'Partial'),
                                                      ('C', 'Complete')])),
                                   ('I', OrderedDict([('N', 'None'),
                                                      ('P', 'Partial'),
                                                      ('C', 'Complete')])),
                                   ('A', OrderedDict([('N', 'None'),
                                                      ('P', 'Partial'),
                                                      ('C', 'Complete')])),
                                   ('E', OrderedDict([('U', 'Unproven'),
                                                      ('POC', 'Proof-of-Concept'),
                                                      ('F', 'Functional'),
                                                      ('H', 'High'),
                                                      ('ND', 'Not Defined')])),
                                   ('RL', OrderedDict([('OF', 'Official Fix'),
                                                       ('TF', 'Temporary Fix'),
                                                       ('W', 'Workaround'),
                                                       ('U', 'Unavailable'),
                                                       ('ND', 'Not Defined')])),
                                   ('RC', OrderedDict([('UC', 'Unconfirmed'),
                                                       ('UR', 'Uncorroborated'),
                                                       ('C', 'Confirmed'),
                                                       ('ND', 'Not Defined')])),
                                   ('CDP', OrderedDict([('N', 'None'),
                                                        ('L', 'Low'),
                                                        ('LM', 'Low-Medium'),
                                                        ('MH', 'Medium-High'),
                                                        ('H', 'High'),
                                                        ('ND', 'Not Defined')])),
                                   ('TD', OrderedDict([('N', 'None'),
                                                       ('L', 'Low'),
                                                       ('M', 'Medium'),
                                                       ('H', 'High'),
                                                       ('ND', 'Not Defined')])),
                                   ('CR', OrderedDict([('L', 'Low'),
                                                       ('M', 'Medium'),
                                                       ('H', 'High'),
                                                       ('ND', 'Not Defined')])),
                                   ('IR', OrderedDict([('L', 'Low'),
                                                       ('M', 'Medium'),
                                                       ('H', 'High'),
                                                       ('ND', 'Not Defined')])),
                                   ('AR', OrderedDict([('L', 'Low'),
                                                       ('M', 'Medium'),
                                                       ('H', 'High'),
                                                       ('ND', 'Not Defined')])),
                                   ])
