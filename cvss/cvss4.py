# The following licence only applies to this file:
# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
This class is a rewrite based on the JS implementation found here:
https://github.com/RedHatProductSecurity/cvss-v4-calculator

Implements class for CVSS4 specification as defined at
https://www.first.org/cvss/specification-document .

The library is compatible with both Python 2 and Python 3.
"""

from __future__ import unicode_literals

import copy
from decimal import ROUND_HALF_UP
from decimal import Decimal as D

from .constants4 import (
    CVSS_LOOKUP_GLOBAL,
    EPSILON,
    MAX_COMPOSED,
    MAX_SEVERITY,
    METRICS,
    METRICS_ABBREVIATIONS,
    METRICS_ABBREVIATIONS_JSON,
    METRICS_MANDATORY,
    METRICS_VALUE_NAMES,
    OrderedDict,
)
from .exceptions import (
    CVSS4MalformedError,
    CVSS4MandatoryError,
    CVSS4RHMalformedError,
    CVSS4RHScoreDoesNotMatch,
)


def final_rounding(x):
    """
    Round to one decimal place. Use Decimal because Python float rounding defaults to
    "round half to even". We actually want "round half away from zero" aka "round half up" for
    positive numbers.

    Add a small value to make sure that values like the following are correctly rounded despite
    floating point inaccuracies:

    8.6 - 7.15 = 1.4499999999999993 (float) => 1.5
    """
    return float(D(x + EPSILON).quantize(D("0.1"), rounding=ROUND_HALF_UP))


class CVSS4(object):
    """
    Class to hold CVSS4 vector, parsed values, and all scores.
    """

    def __init__(self, vector):
        """
        Args:
            vector (str): string specifying CVSS4 vector, fields may be out of order, fields which
                          are not mandatory may be missing
        """
        self.vector = vector
        self.metrics = {}
        self.missing_metrics = []

        self.base_score = None
        self.severity = None

        self.parse_vector()
        self.check_mandatory()
        self.add_missing_optional()
        self.compute_base_score()
        self.compute_severity()

    @classmethod
    def from_rh_vector(cls, vector):
        """
        Creates a CVSS4 object from CVSS vector in Red Hat notation, e.g. containing base score.
        Also checks if the score matches the vector.

        Args:
            vector (str): string specifying CVSS4 vector in Red Hat notation, fields may be out of
                          order, fields which are not mandatory may be missing

        Returns:
            CVSS4: the generated CVSS4 object created from the vector string

        Raises:
            CVSS4RHMalformedError: if vector is not in expected format for Red Hat notation
            CVSS4RHScoreDoesNotMatch: if vector and score do not match
        """
        try:
            score, base_vector = vector.split("/", 1)
        except ValueError:
            raise CVSS4RHMalformedError(
                'Malformed CVSS4 vector in Red Hat notation "{0}"'.format(vector)
            )
        try:
            score_value = float(score)
        except ValueError:
            raise CVSS4RHMalformedError(
                'Malformed CVSS4 vector in Red Hat notation "{0}"'.format(vector)
            )
        cvss_object = cls(base_vector)
        if cvss_object.scores()[0] == score_value:
            return cvss_object
        else:
            raise CVSS4RHScoreDoesNotMatch(
                'CVSS4 vector in Red Hat notation "{0}" has score of '
                '"{1}" which does not match specified score of "{2}"'.format(
                    base_vector, cvss_object.scores()[0], score
                )
            )

    def check_mandatory(self):
        """
        Checks if mandatory fields are in CVSS4 vector.

        Raises:
            CVSS4MandatoryError: if mandatory metric is missing in the vector
        """
        missing = []
        for mandatory_metric in METRICS_MANDATORY:
            if mandatory_metric not in self.metrics:
                missing.append(mandatory_metric)
        if missing:
            raise CVSS4MandatoryError('Missing mandatory metrics "{0}"'.format(", ".join(missing)))

    def add_missing_optional(self):
        """
        Adds missing optional parameters, so they match the mandatory ones. Original metrics are
        also stored, as they may be used for printing back the minimal vector.
        """
        self.original_metrics = copy.copy(self.metrics)

        for abbreviation in [
            "MAV",
            "MAC",
            "MAT",
            "MPR",
            "MUI",
            "MVC",
            "MVI",
            "MVA",
            "MSC",
            "MSI",
            "MSA",
        ]:
            if abbreviation not in self.metrics or self.metrics[abbreviation] == "X":
                self.metrics[abbreviation] = self.metrics[abbreviation[1:]]

        for abbreviation in [
            "S",
            "AU",
            "R",
            "V",
            "RE",
            "U",
            "CR",
            "IR",
            "AR",
            "E",
        ]:
            if abbreviation not in self.metrics:
                self.metrics[abbreviation] = "X"

    def parse_vector(self):
        """
        Parses metrics from the CVSS4 vector.

        Raises:
            CVSS4MalformedError: if vector is not in expected format
        """
        if self.vector == "":
            raise CVSS4MalformedError("Malformed CVSS4 vector, vector is empty")

        if self.vector.endswith("/"):
            raise CVSS4MalformedError('Malformed CVSS4 vector, trailing "/"')
        # Handle 'CVSS:4.x' in the beginning of vector and split vector
        if not self.vector.startswith("CVSS:4.0/"):
            raise CVSS4MalformedError(
                'Malformed CVSS4 vector "{0}" is missing mandatory prefix '
                "or uses unsupported CVSS version".format(self.vector)
            )
        try:
            fields = self.vector.split("/")[1:]
        except IndexError:
            raise CVSS4MalformedError('Malformed CVSS4 vector "{0}"'.format(self.vector))

        # Parse fields
        for field in fields:
            if field == "":
                raise CVSS4MalformedError('Empty field in CVSS4 vector "{0}"'.format(self.vector))

            try:
                metric, value = field.split(":")
            except ValueError:
                raise CVSS4MalformedError('Malformed CVSS4 field "{0}"'.format(field))

            if metric in self.metrics:
                raise CVSS4MalformedError('Duplicate metric "{0}"'.format(metric))

            if metric not in METRICS_VALUE_NAMES:
                raise CVSS4MalformedError('Invalid metric key in CVSS4 vector "{0}"'.format(field))

            if value not in METRICS_VALUE_NAMES[metric]:
                raise CVSS4MalformedError(
                    'Invalid metric value in CVSS4 vector "{0}"'.format(field)
                )

            self.metrics[metric] = value

    def get_eq_maxes(self, lookup, eq):
        return MAX_COMPOSED["eq" + str(eq)][str(lookup[eq - 1])]

    def extract_value_metric(self, metric, string):
        # indexOf gives first index of the metric, we then need to go over its size
        extracted_index = string.index(metric) + len(metric) + 1
        extracted = string[extracted_index:]
        # remove what follow
        metric_val = ""
        if "/" in extracted:
            metric_val = extracted[: extracted.index("/")]
        else:
            # case where it is the last metric so no ending /
            metric_val = extracted
        return metric_val

    def m(self, metric):
        selected = self.metrics.get(metric)
        if metric == "E" and selected == "X":
            return "A"

        if metric == "CR" and selected == "X":
            return "H"

        if metric == "IR" and selected == "X":
            return "H"

        if metric == "AR" and selected == "X":
            return "H"

        if "M" + metric in self.metrics:
            modified_selected = self.metrics["M" + metric]
            if modified_selected != "X":
                return modified_selected

        return selected

    def macroVector(self):
        eq1 = "None"
        eq2 = "None"
        eq3 = "None"
        eq4 = "None"
        eq5 = "None"
        eq6 = "None"

        if self.m("AV") == "N" and self.m("PR") == "N" and self.m("UI") == "N":
            eq1 = "0"
        elif (
            (self.m("AV") == "N" or self.m("PR") == "N" or self.m("UI") == "N")
            and not (self.m("AV") == "N" and self.m("PR") == "N" and self.m("UI") == "N")
            and not self.m("AV") == "P"
        ):
            eq1 = "1"
        elif self.m("AV") == "P" or not (
            self.m("AV") == "N" or self.m("PR") == "N" or self.m("UI") == "N"
        ):
            eq1 = "2"

        if self.m("AC") == "L" and self.m("AT") == "N":
            eq2 = "0"
        elif not (self.m("AC") == "L" and self.m("AT") == "N"):
            eq2 = "1"

        if self.m("VC") == "H" and self.m("VI") == "H":
            eq3 = "0"
        elif not (self.m("VC") == "H" and self.m("VI") == "H") and (
            self.m("VC") == "H" or self.m("VI") == "H" or self.m("VA") == "H"
        ):
            eq3 = "1"
        elif not (self.m("VC") == "H" or self.m("VI") == "H" or self.m("VA") == "H"):
            eq3 = "2"

        if self.m("MSI") == "S" or self.m("MSA") == "S":
            eq4 = "0"
        elif not (self.m("MSI") == "S" or self.m("MSA") == "S") and (
            self.m("SC") == "H" or self.m("SI") == "H" or self.m("SA") == "H"
        ):
            eq4 = "1"
        elif not (self.m("MSI") == "S" or self.m("MSA") == "S") and not (
            (self.m("SC") == "H" or self.m("SI") == "H" or self.m("SA") == "H")
        ):
            eq4 = "2"

        if self.m("E") == "A":
            eq5 = "0"
        elif self.m("E") == "P":
            eq5 = "1"
        elif self.m("E") == "U":
            eq5 = "2"

        if (
            (self.m("CR") == "H" and self.m("VC") == "H")
            or (self.m("IR") == "H" and self.m("VI") == "H")
            or (self.m("AR") == "H" and self.m("VA") == "H")
        ):
            eq6 = "0"
        elif not (
            (self.m("CR") == "H" and self.m("VC") == "H")
            or (self.m("IR") == "H" and self.m("VI") == "H")
            or (self.m("AR") == "H" and self.m("VA") == "H")
        ):
            eq6 = "1"
        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6

    def compute_base_score(self):
        AV_levels = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
        PR_levels = {"N": 0.0, "L": 0.1, "H": 0.2}
        UI_levels = {"N": 0.0, "P": 0.1, "A": 0.2}

        AC_levels = {"L": 0.0, "H": 0.1}
        AT_levels = {"N": 0.0, "P": 0.1}

        VC_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
        VI_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
        VA_levels = {"H": 0.0, "L": 0.1, "N": 0.2}

        SC_levels = {"H": 0.1, "L": 0.2, "N": 0.3}
        SI_levels = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
        SA_levels = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}

        CR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}
        IR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}
        AR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}

        # E_levels = {"U": 0.2, "P": 0.1, "A": 0}

        macroVector = self.macroVector()

        if all([self.m(metric) == "N" for metric in ["VC", "VI", "VA", "SC", "SI", "SA"]]):
            self.base_score = 0.0
            return
        value = CVSS_LOOKUP_GLOBAL[macroVector]

        eq1_val = int(macroVector[0])
        eq2_val = int(macroVector[1])
        eq3_val = int(macroVector[2])
        eq4_val = int(macroVector[3])
        eq5_val = int(macroVector[4])
        eq6_val = int(macroVector[5])

        eq1_next_lower_macro = "".join(
            str(val) for val in [eq1_val + 1, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val]
        )
        eq2_next_lower_macro = "".join(
            str(val) for val in [eq1_val, eq2_val + 1, eq3_val, eq4_val, eq5_val, eq6_val]
        )

        if eq3_val == 1 and eq6_val == 1:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val]
            )
        elif eq3_val == 0 and eq6_val == 1:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val]
            )
        elif eq3_val == 1 and eq6_val == 0:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1]
            )
        elif eq3_val == 0 and eq6_val == 0:
            eq3eq6_next_lower_macro_left = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1]
            )
            eq3eq6_next_lower_macro_right = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val]
            )
        else:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val + 1]
            )

        eq4_next_lower_macro = "".join(
            str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val + 1, eq5_val, eq6_val]
        )
        eq5_next_lower_macro = "".join(
            str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val, eq5_val + 1, eq6_val]
        )

        score_eq1_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq1_next_lower_macro, float("nan"))
        score_eq2_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq2_next_lower_macro, float("nan"))

        if eq3_val == 0 and eq6_val == 0:
            score_eq3eq6_next_lower_macro_left = CVSS_LOOKUP_GLOBAL.get(
                eq3eq6_next_lower_macro_left, float("nan")
            )
            score_eq3eq6_next_lower_macro_right = CVSS_LOOKUP_GLOBAL.get(
                eq3eq6_next_lower_macro_right, float("nan")
            )

            score_eq3eq6_next_lower_macro = max(
                score_eq3eq6_next_lower_macro_left, score_eq3eq6_next_lower_macro_right
            )
        else:
            score_eq3eq6_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(
                eq3eq6_next_lower_macro, float("nan")
            )

        score_eq4_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq4_next_lower_macro, float("nan"))
        score_eq5_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq5_next_lower_macro, float("nan"))

        eq1_maxes = self.get_eq_maxes(macroVector, 1)
        eq2_maxes = self.get_eq_maxes(macroVector, 2)
        eq3_eq6_maxes = self.get_eq_maxes(macroVector, 3)[macroVector[5]]
        eq4_maxes = self.get_eq_maxes(macroVector, 4)
        eq5_maxes = self.get_eq_maxes(macroVector, 5)

        max_vectors = []
        for eq1_max in eq1_maxes:
            for eq2_max in eq2_maxes:
                for eq3_eq6_max in eq3_eq6_maxes:
                    for eq4_max in eq4_maxes:
                        for eq5max in eq5_maxes:
                            max_vectors.append(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max)

        for max_vector in max_vectors:
            severity_distance_AV = (
                AV_levels[self.m("AV")] - AV_levels[self.extract_value_metric("AV", max_vector)]
            )
            severity_distance_PR = (
                PR_levels[self.m("PR")] - PR_levels[self.extract_value_metric("PR", max_vector)]
            )
            severity_distance_UI = (
                UI_levels[self.m("UI")] - UI_levels[self.extract_value_metric("UI", max_vector)]
            )
            severity_distance_AC = (
                AC_levels[self.m("AC")] - AC_levels[self.extract_value_metric("AC", max_vector)]
            )
            severity_distance_AT = (
                AT_levels[self.m("AT")] - AT_levels[self.extract_value_metric("AT", max_vector)]
            )
            severity_distance_VC = (
                VC_levels[self.m("VC")] - VC_levels[self.extract_value_metric("VC", max_vector)]
            )
            severity_distance_VI = (
                VI_levels[self.m("VI")] - VI_levels[self.extract_value_metric("VI", max_vector)]
            )
            severity_distance_VA = (
                VA_levels[self.m("VA")] - VA_levels[self.extract_value_metric("VA", max_vector)]
            )
            severity_distance_SC = (
                SC_levels[self.m("SC")] - SC_levels[self.extract_value_metric("SC", max_vector)]
            )
            severity_distance_SI = (
                SI_levels[self.m("SI")] - SI_levels[self.extract_value_metric("SI", max_vector)]
            )
            severity_distance_SA = (
                SA_levels[self.m("SA")] - SA_levels[self.extract_value_metric("SA", max_vector)]
            )
            severity_distance_CR = (
                CR_levels[self.m("CR")] - CR_levels[self.extract_value_metric("CR", max_vector)]
            )
            severity_distance_IR = (
                IR_levels[self.m("IR")] - IR_levels[self.extract_value_metric("IR", max_vector)]
            )
            severity_distance_AR = (
                AR_levels[self.m("AR")] - AR_levels[self.extract_value_metric("AR", max_vector)]
            )

            if any(
                [
                    met < 0
                    for met in [
                        severity_distance_AV,
                        severity_distance_PR,
                        severity_distance_UI,
                        severity_distance_AC,
                        severity_distance_AT,
                        severity_distance_VC,
                        severity_distance_VI,
                        severity_distance_VA,
                        severity_distance_SC,
                        severity_distance_SI,
                        severity_distance_SA,
                        severity_distance_CR,
                        severity_distance_IR,
                        severity_distance_AR,
                    ]
                ]
            ):
                continue
            break

        current_severity_distance_eq1 = (
            severity_distance_AV + severity_distance_PR + severity_distance_UI
        )
        current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
        current_severity_distance_eq3eq6 = (
            severity_distance_VC
            + severity_distance_VI
            + severity_distance_VA
            + severity_distance_CR
            + severity_distance_IR
            + severity_distance_AR
        )
        current_severity_distance_eq4 = (
            severity_distance_SC + severity_distance_SI + severity_distance_SA
        )
        # current_severity_distance_eq5 = 0

        step = 0.1

        available_distance_eq1 = value - score_eq1_next_lower_macro
        available_distance_eq2 = value - score_eq2_next_lower_macro
        available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
        available_distance_eq4 = value - score_eq4_next_lower_macro
        available_distance_eq5 = value - score_eq5_next_lower_macro

        percent_to_next_eq1_severity = 0
        percent_to_next_eq2_severity = 0
        percent_to_next_eq3eq6_severity = 0
        percent_to_next_eq4_severity = 0
        percent_to_next_eq5_severity = 0

        n_existing_lower = 0

        normalized_severity_eq1 = 0
        normalized_severity_eq2 = 0
        normalized_severity_eq3eq6 = 0
        normalized_severity_eq4 = 0
        normalized_severity_eq5 = 0

        max_severity_eq1 = MAX_SEVERITY["eq1"][eq1_val] * step
        max_severity_eq2 = MAX_SEVERITY["eq2"][eq2_val] * step
        max_severity_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3_val][eq6_val] * step
        max_severity_eq4 = MAX_SEVERITY["eq4"][eq4_val] * step
        if type(available_distance_eq1) in (float, int) and available_distance_eq1 >= 0:
            n_existing_lower += 1
            percent_to_next_eq1_severity = (current_severity_distance_eq1) / max_severity_eq1
            normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity

        if type(available_distance_eq2) in (float, int) and available_distance_eq2 >= 0:
            n_existing_lower += 1
            percent_to_next_eq2_severity = (current_severity_distance_eq2) / max_severity_eq2
            normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity

        if type(available_distance_eq3eq6) in (float, int) and available_distance_eq3eq6 >= 0:
            n_existing_lower += 1
            percent_to_next_eq3eq6_severity = (
                current_severity_distance_eq3eq6
            ) / max_severity_eq3eq6
            normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity

        if type(available_distance_eq4) in (float, int) and available_distance_eq4 >= 0:
            n_existing_lower += 1
            percent_to_next_eq4_severity = (current_severity_distance_eq4) / max_severity_eq4
            normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity

        if type(available_distance_eq5) in (float, int) and available_distance_eq5 >= 0:
            n_existing_lower += 1
            percent_to_next_eq5_severity = 0
            normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity

        mean_distance = (
            0
            if n_existing_lower == 0
            else (
                normalized_severity_eq1
                + normalized_severity_eq2
                + normalized_severity_eq3eq6
                + normalized_severity_eq4
                + normalized_severity_eq5
            )
            / n_existing_lower
        )

        value -= mean_distance
        value = max(0.0, value)
        value = min(10.0, value)

        self.base_score = final_rounding(value)

    def clean_vector(self, output_prefix=True):
        """
        Returns vector without optional metrics marked as X and in preferred order.

        Args:
            output_prefix (bool): defines if CVSS vector should be printed with prefix

        Returns:
            (str): cleaned CVSS4 with metrics in correct order
        """
        vector = []
        for metric in METRICS_ABBREVIATIONS:
            if metric in self.original_metrics:
                value = self.original_metrics[metric]
                if value != "X":
                    vector.append("{0}:{1}".format(metric, value))
        if output_prefix:
            prefix = "CVSS:4.0/"
        else:
            prefix = ""
        return prefix + "/".join(vector)

    def get_value_description(self, abbreviation):
        """
        Gets textual description of specific metric specified by its abbreviation.
        """
        string_value = self.metrics.get(abbreviation, "X")
        result = METRICS_VALUE_NAMES[abbreviation][string_value]
        return result

    def compute_severity(self):
        """
        Returns the severity based on score.

        Returns:
            (str): Severity string
        """
        if self.base_score == 0.0:
            self.severity = "None"
        elif self.base_score <= 3.9:
            self.severity = "Low"
        elif self.base_score <= 6.9:
            self.severity = "Medium"
        elif self.base_score <= 8.9:
            self.severity = "High"
        else:
            self.severity = "Critical"

    def scores(self):
        """
        Returns computed base score as tuple for backwards compatibility.

        Returns:
            (tuple of floats): Base Score
        """
        return (self.base_score,)

    def severities(self):
        """
        Returns severities based on base score as tuple for backwards compatibility.

        Returns:
            (tuple): Base Severity as string
        """
        return (self.severity,)

    def rh_vector(self):
        """
        Returns cleaned vector with score in Red Hat notation, e.g. score/vector.

        Example: 7.3/CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A
        """
        return str(self.base_score) + "/" + self.clean_vector()

    def as_json(self, sort=False, minimal=False):
        """
        Returns a dictionary formatted with attribute names and values defined by the official
        CVSS JSON schema:

        CVSS v4.0: https://www.first.org/cvss/cvss-v4.0.json?20231011

        Serialize a `cvss` instance to JSON with:

        json.dumps(cvss.as_json())

        Or get sorted JSON in an OrderedDict with:

        json.dumps(cvss.as_json(sort=True))

        Returns:
            (dict): JSON schema-compatible CVSS representation
        """

        def us(text):
            # If this is the (modified) attack vector description, convert it from "adjacent" to
            # "adjacent network" as defined by the schema.
            if text == "Adjacent":
                return "ADJACENT_NETWORK"
            # Uppercase and convert to snake case
            return text.upper().replace("-", "_").replace(" ", "_")

        def add_metric_to_data(metric):
            k = METRICS_ABBREVIATIONS_JSON[metric]
            data[k] = us(self.get_value_description(metric))

        data = {
            "version": "4",
            "vectorString": self.vector,
        }

        for metric in METRICS:
            add_metric_to_data(metric)
        data["baseScore"] = float(self.base_score)
        data["baseSeverity"] = self.severity

        if sort:
            data = OrderedDict(sorted(data.items()))
        return data

    def __hash__(self):
        return hash(self.clean_vector())

    def __eq__(self, o):
        if isinstance(o, CVSS4):
            return self.clean_vector() == o.clean_vector()
        return False
