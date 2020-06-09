# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Implements class for CVSS2 specification as defined at
https://www.first.org/cvss/v2/guide .

The library is compatible with both Python 2 and Python 3.
"""

from __future__ import unicode_literals

from decimal import Decimal as D, ROUND_HALF_UP

from .constants2 import METRICS_ABBREVIATIONS, METRICS_MANDATORY, METRICS_VALUES
from .exceptions import CVSS2MalformedError, CVSS2MandatoryError, CVSS2RHMalformedError, \
    CVSS2RHScoreDoesNotMatch


def round_to_1_decimal(value):
    """
    Round to one decimal.
    """
    return value.quantize(D('0.1'), rounding=ROUND_HALF_UP)


class CVSS2(object):
    """
    Class to hold CVSS2 vector, parsed values, and all scores.
    """
    @classmethod
    def from_rh_vector(cls, vector):
        """
        Creates a CVSS2 object from CVSS vector in Red Hat notation, e.g. containing base score.
        Also checks if the score matches the vector.

        Args:
            vector (str): string specifying CVSS3 vector in Red Hat notation, fields may be out of
                          order, fields which are not mandatory may be missing

        Returns:
            CVSS2: the generated CVSS2 object created from the vector string

        Raises:
            CVSS2RHMalformedError: if vector is not in expected format for Red Hat notation
            CVSS2RHScoreDoesNotMatch: if vector and score do not match
        """
        try:
            score, base_vector = vector.split('/', 1)
        except ValueError:
            raise CVSS2RHMalformedError('Malformed CVSS2 vector in Red Hat notation "{0}"'
                                        .format(vector))
        try:
            score_value = float(score)
        except ValueError:
            raise CVSS2RHMalformedError('Malformed CVSS2 vector in Red Hat notation "{0}"'
                                        .format(vector))
        cvss_object = cls(base_vector)
        if cvss_object.scores()[0] == score_value:
            return cvss_object
        else:
            raise CVSS2RHScoreDoesNotMatch('CVSS2 vector in Red Hat notation "{0}" has score of '
                                           '"{1}" which does not match specified score of "{2}"'
                                           .format(base_vector, cvss_object.scores()[0],
                                                   score))

    def __init__(self, vector):
        """
        Args:
            vector (str): string specifying CVSS2 vector, fields may be out of order, fields which
                          are not mandatory may be missing
        """
        self.vector = vector
        self.metrics = {}

        self.base_score = None
        self.temporal_score = None
        self.environmental_score = None

        self.parse_vector()
        self.check_mandatory()
        self.compute_base_score()
        self.compute_temporal_score()
        self.compute_environmental_score()

    def parse_vector(self):
        """
        Parses metrics from the CVSS2 vector.

        Raises:
            CVSS2MalformedError: if vector is not in expected format
        """
        if self.vector == '':
            raise CVSS2MalformedError('Malformed CVSS2 vector, vector is empty')

        if self.vector.endswith('/'):
            raise CVSS2MalformedError('Malformed CVSS2 vector, trailing "/"')

        fields = self.vector.split('/')

        # Parse fields
        for field in fields:
            if field == '':
                raise CVSS2MalformedError('Empty field in CVSS2 vector "{0}"'.format(self.vector))

            try:
                metric, value = field.split(':')
            except ValueError:
                raise CVSS2MalformedError('Malformed CVSS2 field "{0}"'.format(field))

            if metric in METRICS_ABBREVIATIONS:
                if value in METRICS_VALUES[metric]:
                    if metric in self.metrics:
                        raise CVSS2MalformedError('Duplicate metric "{0}"'.format(metric))
                    self.metrics[metric] = value
                else:
                    raise CVSS2MalformedError('Unknown value "{0}" in field "{1}"'.format(value,
                                                                                          field))
            else:
                raise CVSS2MalformedError('Unknown metric "{0}" in field "{1}"'.format(metric,
                                                                                       field))

    def check_mandatory(self):
        """
        Checks if mandatory fields are in CVSS2 vector.

        Raises:
            CVSS2MandatoryError: if mandatory metric is missing in the vector
        """
        missing = []
        for mandatory_metric in METRICS_MANDATORY:
            if mandatory_metric not in self.metrics:
                missing.append(mandatory_metric)
        if missing:
            raise CVSS2MandatoryError('Missing mandatory metrics "{0}"'.format(', '.join(missing)))

    def get_value(self, abbreviation):
        """
        Gets value of specific metric specified by its abbreviation.
        """
        string_value = self.metrics.get(abbreviation, 'ND')
        result = METRICS_VALUES[abbreviation][string_value]
        return result

    def impact_equation(self):
        """
        Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
        """
        return D('10.41') * (D('1') - (D('1') - self.get_value('C')) *
                                      (D('1') - self.get_value('I')) *
                                      (D('1') - self.get_value('A')))

    def adjusted_impact_equation(self):
        """
        AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
                                     *(1-AvailImpact*AvailReq)))
        """
        return min(D('10'),
                   D('10.41') * (D('1') - (D('1') - self.get_value('C') * self.get_value('CR')) *
                                          (D('1') - self.get_value('I') * self.get_value('IR')) *
                                          (D('1') - self.get_value('A') * self.get_value('AR')))
                   )

    def base_score_equation(self, adjusted_impact=False):
        """
        BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
        Impact = see impact_equation or modified_impact_equation
        Exploitability = 20*AccessVector*AccessComplexity*Authentication
        f(impact)= 0 if Impact=0, 1.176 otherwise
        """
        if adjusted_impact:
            impact = self.adjusted_impact_equation()
        else:
            impact = self.impact_equation()

        exploitability = (D('20') * self.get_value('AV') * self.get_value('AC') *
                          self.get_value('Au'))
        f_impact = D('0') if impact == D('0') else D('1.176')
        return round_to_1_decimal(((D('0.6') * impact) + (D('0.4') * exploitability) -
                                   D('1.5')) * f_impact)

    def compute_base_score(self):
        """
        Compute base score using normal Impact equation. Do not allow negative result.
        """
        self.base_score = max(D('0.0'), self.base_score_equation())

    def temporal_score_equation(self, adjusted_impact=False):
        """
        TemporalScore = round_to_1_decimal(BaseScore*Exploitability
                        *RemediationLevel*ReportConfidence)
        """
        if adjusted_impact:
            base_score = self.base_score_equation(adjusted_impact=True)
        else:
            base_score = self.base_score
        return round_to_1_decimal(base_score * self.get_value('E') * self.get_value('RL') *
                                  self.get_value('RC'))

    def compute_temporal_score(self):
        """
        Compute temporal score using normal Impact equation.
        """
        if all(self.metrics.get(a, 'ND') == 'ND' for a in ['E', 'RL', 'RC']):
            self.temporal_score = None
        else:
            self.temporal_score = max(D('0.0'), self.temporal_score_equation())

    def compute_environmental_score(self):
        """
        EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
        (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)

        AdjustedTemporal = TemporalScore recomputed with the BaseScores Impact sub-equation
                           replaced with the AdjustedImpact equation
        """
        if all(self.metrics.get(a, 'ND') == 'ND' for a in ['CDP', 'TD', 'CR', 'IR', 'AR']):
            self.environmental_score = None
        else:
            temporal_score_adjusted = self.temporal_score_equation(adjusted_impact=True)
            raw_environmental_score = round_to_1_decimal((temporal_score_adjusted +
                                                          (D('10') - temporal_score_adjusted) *
                                                          self.get_value('CDP')) *
                                                         self.get_value('TD'))
            self.environmental_score = max(D('0.0'), raw_environmental_score)

    def scores(self):
        """
        Returns all computed scores.

        Returns:
            (tuple): Base Score, Temporal Score, Environmental Score, either float or None if not
                     defined
        """
        scores = (self.base_score, self.temporal_score, self.environmental_score)
        return tuple(float(a) if a is not None else None for a in scores)

    def clean_vector(self):
        """
        Returns vector without optional metrics marked as ND and in preferred order.

        Returns:
            (str): cleaned CVSS2 with metrics in correct order
        """
        vector = []
        for metric in METRICS_ABBREVIATIONS:
            if metric in self.metrics:
                value = self.metrics[metric]
                if value != 'ND':
                    vector.append('{0}:{1}'.format(metric, value))
        return '/'.join(vector)
    
    def severities(self):
        """
        Returns severities based on scores. https://nvd.nist.gov/vuln-metrics/cvss
        
        Returns:
            (tuple): Base Severity, Temporal Severity, Environmental Severity as strings
        """
        severities = []
        for score in (self.base_score, self.temporal_score, self.environmental_score):
            if score is None:
                severities.append('None')
            elif score <= D('3.9'):
                severities.append('Low')
            elif score <= D('6.9'):
                severities.append('Medium')
            else:
                severities.append('High')
        return tuple(severities)

    def rh_vector(self):
        """
        Returns cleaned vector with score in Red Hat notation, e.g. score/vector.

        Example: 5.0/AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/CDP:L/TD:H/AR:M
        """
        return str(self.scores()[0]) + '/' + self.clean_vector()

    def __eq__(self, o):
        if isinstance(o, CVSS2):
            return self.clean_vector().__eq__(o.clean_vector())
        return NotImplemented

    def __hash__(self):
        return hash(self.clean_vector())
