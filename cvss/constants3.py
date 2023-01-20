# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Constants for CVSS3 computations and checks. Generated using util/generate_constants.py.
"""

from __future__ import unicode_literals

from decimal import Decimal as D

try:
    from collections import OrderedDict
except ImportError:
    # noinspection PyUnresolvedReferences
    from ordereddict import OrderedDict


METRICS_ABBREVIATIONS = OrderedDict(
    [
        ("AV", "Attack Vector"),
        ("AC", "Attack Complexity"),
        ("PR", "Privileges Required"),
        ("UI", "User Interaction"),
        ("S", "Scope"),
        ("C", "Confidentiality"),
        ("I", "Integrity"),
        ("A", "Availability"),
        ("E", "Exploit Code Maturity"),
        ("RL", "Remediation Level"),
        ("RC", "Report Confidence"),
        ("CR", "Confidentiality Req."),
        ("IR", "Integrity Req."),
        ("AR", "Availability Req."),
        ("MAV", "Modified Attack Vector"),
        ("MAC", "Modified Attack Complexity"),
        ("MPR", "Modified Privileges Required"),
        ("MUI", "Modified User Interaction"),
        ("MS", "Modified Scope"),
        ("MC", "Modified Confidentiality"),
        ("MI", "Modified Integrity"),
        ("MA", "Modified Availability"),
    ]
)

# Metric names as they appear in the CVSS JSON schema (see CVSS3.as_json())
METRICS_ABBREVIATIONS_JSON = OrderedDict(
    [
        ("AV", "attackVector"),
        ("AC", "attackComplexity"),
        ("PR", "privilegesRequired"),
        ("UI", "userInteraction"),
        ("S", "scope"),
        ("C", "confidentialityImpact"),
        ("I", "integrityImpact"),
        ("A", "availabilityImpact"),
        ("E", "exploitCodeMaturity"),
        ("RL", "remediationLevel"),
        ("RC", "reportConfidence"),
        ("CR", "confidentialityRequirement"),
        ("IR", "integrityRequirement"),
        ("AR", "availabilityRequirement"),
        ("MAV", "modifiedAttackVector"),
        ("MAC", "modifiedAttackComplexity"),
        ("MPR", "modifiedPrivilegesRequired"),
        ("MUI", "modifiedUserInteraction"),
        ("MS", "modifiedScope"),
        ("MC", "modifiedConfidentialityImpact"),
        ("MI", "modifiedIntegrityImpact"),
        ("MA", "modifiedAvailabilityImpact"),
    ]
)

METRICS_MANDATORY = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
TEMPORAL_METRICS = ["E", "RL", "RC"]
ENVIRONMENTAL_METRICS = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MC", "MI", "MA"]

METRICS_VALUES = {
    "AV": {"N": D("0.85"), "A": D("0.62"), "L": D("0.55"), "P": D("0.2")},
    "AC": {"L": D("0.77"), "H": D("0.44")},
    "PR": {"N": D("0.85"), "L": D("0.62"), "H": D("0.27")},
    "UI": {"N": D("0.85"), "R": D("0.62")},
    "S": {"C": None, "U": None},
    "C": {"H": D("0.56"), "L": D("0.22"), "N": D("0")},
    "I": {"H": D("0.56"), "L": D("0.22"), "N": D("0")},
    "A": {"H": D("0.56"), "L": D("0.22"), "N": D("0")},
    "E": {"X": D("1"), "H": D("1"), "F": D("0.97"), "P": D("0.94"), "U": D("0.91")},
    "RL": {"X": D("1"), "U": D("1"), "W": D("0.97"), "T": D("0.96"), "O": D("0.95")},
    "RC": {"X": D("1"), "C": D("1"), "R": D("0.96"), "U": D("0.92")},
    "CR": {"X": D("1"), "H": D("1.5"), "M": D("1"), "L": D("0.5")},
    "IR": {"X": D("1"), "H": D("1.5"), "M": D("1"), "L": D("0.5")},
    "AR": {"X": D("1"), "H": D("1.5"), "M": D("1"), "L": D("0.5")},
    "MAV": {"X": None, "N": D("0.85"), "A": D("0.62"), "L": D("0.55"), "P": D("0.2")},
    "MAC": {"X": None, "L": D("0.77"), "H": D("0.44")},
    "MPR": {"X": None, "N": D("0.85"), "L": D("0.62"), "H": D("0.27")},
    "MUI": {"X": None, "N": D("0.85"), "R": D("0.62")},
    "MS": {"X": None, "C": None, "U": None},
    "MC": {"X": None, "H": D("0.56"), "L": D("0.22"), "N": D("0")},
    "MI": {"X": None, "H": D("0.56"), "L": D("0.22"), "N": D("0")},
    "MA": {"X": None, "H": D("0.56"), "L": D("0.22"), "N": D("0")},
}

METRICS_VALUE_NAMES = OrderedDict(
    [
        (
            "AV",
            OrderedDict([("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")]),
        ),
        ("AC", OrderedDict([("L", "Low"), ("H", "High")])),
        ("PR", OrderedDict([("N", "None"), ("L", "Low"), ("H", "High")])),
        ("UI", OrderedDict([("N", "None"), ("R", "Required")])),
        ("S", OrderedDict([("C", "Changed"), ("U", "Unchanged")])),
        ("C", OrderedDict([("H", "High"), ("L", "Low"), ("N", "None")])),
        ("I", OrderedDict([("H", "High"), ("L", "Low"), ("N", "None")])),
        ("A", OrderedDict([("H", "High"), ("L", "Low"), ("N", "None")])),
        (
            "E",
            OrderedDict(
                [
                    ("X", "Not Defined"),
                    ("H", "High"),
                    ("F", "Functional"),
                    ("P", "Proof-of-Concept"),
                    ("U", "Unproven"),
                ]
            ),
        ),
        (
            "RL",
            OrderedDict(
                [
                    ("X", "Not Defined"),
                    ("U", "Unavailable"),
                    ("W", "Workaround"),
                    ("T", "Temporary Fix"),
                    ("O", "Official Fix"),
                ]
            ),
        ),
        (
            "RC",
            OrderedDict(
                [("X", "Not Defined"), ("C", "Confirmed"), ("R", "Reasonable"), ("U", "Unknown")]
            ),
        ),
        ("CR", OrderedDict([("X", "Not Defined"), ("H", "High"), ("M", "Medium"), ("L", "Low")])),
        ("IR", OrderedDict([("X", "Not Defined"), ("H", "High"), ("M", "Medium"), ("L", "Low")])),
        ("AR", OrderedDict([("X", "Not Defined"), ("H", "High"), ("M", "Medium"), ("L", "Low")])),
        (
            "MAV",
            OrderedDict(
                [
                    ("X", "Not Defined"),
                    ("N", "Network"),
                    ("A", "Adjacent"),
                    ("L", "Local"),
                    ("P", "Physical"),
                ]
            ),
        ),
        ("MAC", OrderedDict([("X", "Not Defined"), ("L", "Low"), ("H", "High")])),
        ("MPR", OrderedDict([("X", "Not Defined"), ("N", "None"), ("L", "Low"), ("H", "High")])),
        ("MUI", OrderedDict([("X", "Not Defined"), ("N", "None"), ("R", "Required")])),
        ("MS", OrderedDict([("X", "Not Defined"), ("C", "Changed"), ("U", "Unchanged")])),
        ("MC", OrderedDict([("X", "Not Defined"), ("H", "High"), ("L", "Low"), ("N", "None")])),
        ("MI", OrderedDict([("X", "Not Defined"), ("H", "High"), ("L", "Low"), ("N", "None")])),
        ("MA", OrderedDict([("X", "Not Defined"), ("H", "High"), ("L", "Low"), ("N", "None")])),
    ]
)
