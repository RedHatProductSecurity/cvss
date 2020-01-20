"""
This script generates constants for CVSS library using text from guide and text representation of
tables from specification located at:
https://www.first.org/cvss/v2/guide
https://www.first.org/cvss/specification-document
"""

from __future__ import print_function, unicode_literals

from collections import OrderedDict
import copy
from decimal import Decimal
import re


METRICS_2 = '''
Base                Access Vector, AV                    [L,A,N]                Yes
                    Access Complexity, AC                [H,M,L]                Yes
                    Authentication, Au                   [M,S,N]                Yes
                    Confidentiality Impact, C            [N,P,C]                Yes
                    Integrity Impact, I                  [N,P,C]                Yes
                    Availability Impact, A               [N,P,C]                Yes
Temporal            Exploitability, E                    [U,POC,F,H,ND]         No
                    Remediation Level, RL                [OF,TF,W,U,ND]         No
                    Report Confidence, RC                [UC,UR,C,ND]           No
Environmental       Collateral Damage Potential, CDP     [N,L,LM,MH,H,ND]       No
                    Target Distribution, TD              [N,L,M,H,ND]           No
                    Confidentiality Requirement, CR      [L,M,H,ND]             No
                    Integrity Requirement, IR            [L,M,H,ND]             No
                    Availability Requirement, AR         [L,M,H,ND]             No
'''

NAMES_2 = '''
AV                  [Local Access,Adjacent Network,Network Accessible]
AC                  [High,Medium,Low]
Au                  [Multiple,Single,None]
C                   [None,Partial,Complete]
I                   [None,Partial,Complete]
A                   [None,Partial,Complete]
E                   [Unproven,Proof-of-Concept,Functional,High,Not Defined]
RL                  [Official Fix,Temporary Fix,Workaround,Unavailable,Not Defined]
RC                  [Unconfirmed,Uncorroborated,Confirmed,Not Defined]
CDP                 [None,Low,Low-Medium,Medium-High,High,Not Defined]
TD                  [None,Low,Medium,High,Not Defined]
CR                  [Low,Medium,High,Not Defined]
IR                  [Low,Medium,High,Not Defined]
AR                  [Low,Medium,High,Not Defined]
'''

VALUES_2 = '''
AV                  [L=0.395,A=0.646,N=1]
AC                  [H=0.35,M=0.61,L=0.71]
Au                  [M=0.45,S=0.56,N=0.704]
C                   [N=0,P=0.275,C=0.660]
I                   [N=0,P=0.275,C=0.660]
A                   [N=0,P=0.275,C=0.660]
E                   [U=0.85,POC=0.9,F=0.95,H=1,ND=1]
RL                  [OF=0.87,TF=0.90,W=0.95,U=1,ND=1]
RC                  [UC=0.9,UR=0.95,C=1,ND=1]
CDP                 [N=0,L=0.1,LM=0.3,MH=0.4,H=0.5,ND=0]
TD                  [N=0,L=0.25,M=0.75,H=1,ND=1]
CR                  [L=0.5,M=1,H=1.51,ND=1]
IR                  [L=0.5,M=1,H=1.51,ND=1]
AR                  [L=0.5,M=1,H=1.51,ND=1]
'''

METRICS_3 = '''
Base                Attack Vector, AV                    [N,A,L,P]            Yes
                    Attack Complexity, AC                [L,H]                Yes
                    Privileges Required, PR              [N,L,H]              Yes
                    User Interaction, UI                 [N,R]                Yes
                    Scope, S                             [U,C]                Yes
                    Confidentiality, C                   [H,L,N]              Yes
                    Integrity, I                         [H,L,N]              Yes
                    Availability, A                      [H,L,N]              Yes
Temporal            Exploit Code Maturity, E             [X,H,F,P,U]          No
                    Remediation Level, RL                [X,U,W,T,O]          No
                    Report Confidence, RC                [X,C,R,U]            No
Environmental       Confidentiality Req., CR             [X,H,M,L]            No
                    Integrity Req., IR                   [X,H,M,L]            No
                    Availability Req., AR                [X,H,M,L]            No
                    Modified Attack Vector, MAV          [X,N,A,L,P]          No
                    Modified Attack Complexity, MAC      [X,L,H]              No
                    Modified Privileges Required, MPR    [X,N,L,H]            No
                    Modified User Interaction, MUI       [X,N,R]              No
                    Modified Scope, MS                   [X,U,C]              No
                    Modified Confidentiality, MC         [X,N,L,H]            No
                    Modified Integrity, MI               [X,N,L,H]            No
                    Modified Availability, MA            [X,N,L,H]            No
'''

NAMES_3 = '''
AV                  [Network,Adjacent,Local,Physical]
AC                  [Low,High]
PR                  [None,Low,High]
UI                  [None,Required]
S                   [Changed,Unchanged]
C                   [High,Low,None]
I                   [High,Low,None]
A                   [High,Low,None]
E                   [Not Defined,High,Functional,Proof-of-Concept,Unproven]
RL                  [Not Defined,Unavailable,Workaround,Temporary Fix,Official Fix]
RC                  [Not Defined,Confirmed,Reasonable,Unknown]
CR                  [Not Defined,High,Medium,Low]
IR                  [Not Defined,High,Medium,Low]
AR                  [Not Defined,High,Medium,Low]
MAV                 [Not Defined,Network,Adjacent,Local,Physical]
MAC                 [Not Defined,Low,High]
MPR                 [Not Defined,None,Low,High]
MUI                 [Not Defined,None,Required]
MS                  [Not Defined,Changed,Unchanged]
MC                  [Not Defined,High,Low,None]
MI                  [Not Defined,High,Low,None]
MA                  [Not Defined,High,Low,None]
'''

VALUES_3 = '''
AV                  [N=0.85,A=0.62,L=0.55,P=0.2]
AC                  [L=0.77,H=0.44]
PR                  [N=0.85,L=0.62,H=0.27]             (or 0.85, 0.68, 0.50 if Scope = C)
UI                  [N=0.85,R=0.62]
S                   [C,U]
C                   [H=0.56,L=0.22,N=0]
I                   [H=0.56,L=0.22,N=0]
A                   [H=0.56,L=0.22,N=0]
E                   [X=1,H=1,F=0.97,P=0.94,U=0.91]
RL                  [X=1,U=1,W=0.97,T=0.96,O=0.95]
RC                  [X=1,C=1,R=0.96,U=0.92]
CR                  [X=1,H=1.5,M=1,L=0.5]
IR                  [X=1,H=1.5,M=1,L=0.5]
AR                  [X=1,H=1.5,M=1,L=0.5]
MAV                 [X,N=0.85,A=0.62,L=0.55,P=0.2]
MAC                 [X,L=0.77,H=0.44]
MPR                 [X,N=0.85,L=0.62,H=0.27]           (or 0.85, 0.68, 0.50 if Modified Scope = C)
MUI                 [X,N=0.85,R=0.62]
MS                  [X,C,U]
MC                  [X,H=0.56,L=0.22,N=0]
MI                  [X,H=0.56,L=0.22,N=0]
MA                  [X,H=0.56,L=0.22,N=0]
'''

METRICS = (METRICS_2, METRICS_3)
NAMES = (NAMES_2, NAMES_3)
VALUES = (VALUES_2, VALUES_3)


def build_constants(metrics, names, values):
    """
    Creates constants from text representation.

    Returns:
        (tuple): Metrics Abbreviations, Mandatory Metrics, Metrics Values, Metrics Value Names
    """
    metrics_abbreviations = OrderedDict()
    metrics_mandatory = []
    metrics_values = OrderedDict()

    # Parse name, abbreviation, and mandatory
    for line in metrics.strip().split('\n'):
        r = re.search('.*[ ]{3,}(.*), (\S+)\s+\[(\S+)\]\s+(\S+)', line)
        if r:
            metrics_abbreviations[r.group(2)] = r.group(1)
            if r.group(4) == 'Yes':
                metrics_mandatory.append(r.group(2))
        else:
            raise RuntimeError('Malformated constant line "{0}"'.format(line))

    # Parse name and value numbers for abbreviated values
    for line in values.strip().split('\n'):
        r = re.search('(\S+)\s+\[(.*)\]', line)
        if r:
            values = OrderedDict()
            for one_value in r.group(2).split(','):
                if '=' in one_value:
                    key, value = one_value.split('=')
                    values[key] = Decimal(value)
                else:
                    values[one_value] = None
            metrics_values[r.group(1)] = values
        else:
            raise RuntimeError('Malformated constant line "{0}"'.format(line))

    # Parse full names for abbreviated values
    metrics_value_names = copy.deepcopy(metrics_values)
    for line in names.strip().split('\n'):
        r = re.search('(\S+)\s+\[(.*)\]', line)
        if r:
            metric = r.group(1)
            names = r.group(2).split(',')
            keys = list(metrics_value_names[metric].keys())
            for i, name in enumerate(names):
                metrics_value_names[metric][keys[i]] = name

    return metrics_abbreviations, metrics_mandatory, metrics_values, metrics_value_names


def print_constants(metrics, names, values):
    """
    Prints the constants build by 'build_constants' function formatted for Python code.
    """
    constants = build_constants(metrics, names, values)
    metrics_abbreviations, metrics_mandatory, metrics_values, metrics_value_names = constants

    header = 'METRICS_ABBREVIATIONS = OrderedDict(['
    MA = [header]
    for i, key in enumerate(metrics_abbreviations):
        if i == 0:
            MA[0] += "('{0}', '{1}'),".format(key, metrics_abbreviations[key])
        else:
            MA.append(' ' * len(header) + "('{0}', '{1}'),".format(key, metrics_abbreviations[key]))
    MA.append(' ' * len(header) + '])')
    print('\n'.join(MA))

    print()
    print('METRICS_MANDATORY =', repr(metrics_mandatory))

    print()
    header = 'METRICS_VALUES = {'
    MV = [header]
    for i, key in enumerate(metrics_values):
        values = []
        for possible_value in metrics_values[key]:
            if metrics_values[key][possible_value] is None:
                one_value = 'None'
            else:
                one_value = "D('{0}')".format(metrics_values[key][possible_value])
            values.append("'{0}': {1}".format(possible_value, one_value))
        values = ', '.join(values)
        if i == 0:
            MV[0] += "'{0}': {{{1}}},".format(key, values)
        else:
            MV.append(' ' * len(header) + "'{0}': {{{1}}},".format(key, values))
    MV.append(' ' * len(header) + '}')
    print('\n'.join(MV))

    print()
    header = 'METRICS_VALUE_NAMES = OrderedDict(['
    MVN = [header]
    for i, key in enumerate(metrics_value_names):
        values_dict_string = str(metrics_value_names[key]).replace('), ', '),\n' + ' ' * (len(header) + len(key) + 18))
        if i == 0:
            MVN[0] += "('{0}', {1}),".format(key, values_dict_string)
        else:
            MVN.append(' ' * len(header) + "('{0}', {1}),".format(key, values_dict_string))
    MVN.append(' ' * len(header) + '])')
    print('\n'.join(MVN))


if __name__ == '__main__':
    print('# CVSS2')
    print_constants(METRICS_2, NAMES_2, VALUES_2)
    print('\n\n# CVSS3')
    print_constants(METRICS_3, NAMES_3, VALUES_3)
