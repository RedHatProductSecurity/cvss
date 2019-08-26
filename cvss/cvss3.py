# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Implements class for CVSS3 specification as defined at
https://www.first.org/cvss/specification-document .

The library is compatible with both Python 2 and Python 3.
"""

from __future__ import unicode_literals

import copy
from decimal import Decimal as D, ROUND_CEILING

from .constants3 import METRICS_ABBREVIATIONS, METRICS_MANDATORY, METRICS_VALUES
from .exceptions import CVSS3MalformedError, CVSS3MandatoryError, CVSS3RHMalformedError, \
    CVSS3RHScoreDoesNotMatch


def round_up(value):
    """
    Round up is defined as the smallest number, specified to one decimal place, that is equal to
    or higher than its input. For example, Round up (4.02) is 4.1; and Round up (4.00) is 4.0.
    """
    return value.quantize(D('0.1'), rounding=ROUND_CEILING)


class CVSS3(object):
    """
    Class to hold CVSS3 vector, parsed values, and all scores.
    """
    @classmethod
    def from_rh_vector(cls, vector):
        """
        Creates a CVSS3 object from CVSS vector in Red Hat notation, e.g. containing base score.
        Also checks if the score matches the vector.

        Args:
            vector (str): string specifying CVSS3 vector in Red Hat notation, fields may be out of
                          order, fields which are not mandatory may be missing

        Returns:
            CVSS3: the generated CVSS3 object created from the vector string

        Raises:
            CVSS3RHMalformedError: if vector is not in expected format for Red Hat notation
            CVSS3RHScoreDoesNotMatch: if vector and score do not match
        """
        try:
            score, base_vector = vector.split('/', 1)
        except ValueError:
            raise CVSS3RHMalformedError('Malformed CVSS3 vector in Red Hat notation "{0}"'
                                        .format(vector))
        try:
            score_value = float(score)
        except ValueError:
            raise CVSS3RHMalformedError('Malformed CVSS3 vector in Red Hat notation "{0}"'
                                        .format(vector))
        cvss_object = cls(base_vector)
        if cvss_object.scores()[0] == score_value:
            return cvss_object
        else:
            raise CVSS3RHScoreDoesNotMatch('CVSS3 vector in Red Hat notation "{0}" has score of '
                                           '"{1}" which does not match specified score of "{2}"'
                                           .format(base_vector, cvss_object.scores()[0],
                                                   score))

    def __init__(self, vector):
        """
        Args:
            vector (str): string specifying CVSS3 vector, fields may be out of order, fields which
                          are not mandatory may be missing
        """
        self.vector = vector
        self.minor_version = None
        self.metrics = {}
        self.original_metrics = None
        self.missing_metrics = []

        self.scope = None
        self.modified_scope = None
        self.base_score = None
        self.temporal_score = None
        self.environmental_score = None

        self.isc_base = None
        self.isc = None
        self.esc = None
        self.modified_isc_base = None
        self.modified_isc = None
        self.modified_esc = None

        self.parse_vector()
        self.check_mandatory()
        self.handle_scope()
        self.add_missing_optional()
        self.compute_base_score()
        self.compute_temporal_score()
        self.compute_environmental_score()

    def parse_vector(self):
        """
        Parses metrics from the CVSS3 vector.

        Raises:
            CVSS3MalformedError: if vector is not in expected format
        """
        if self.vector == '':
            raise CVSS3MalformedError('Malformed CVSS3 vector, vector is empty')

        if self.vector.endswith('/'):
            raise CVSS3MalformedError('Malformed CVSS3 vector, trailing "/"')

        # Handle 'CVSS:3.x' in the beginning of vector and split vector
        if self.vector.startswith('CVSS:3.0/'):
            self.minor_version = 0
        elif self.vector.startswith('CVSS:3.1/'):
            self.minor_version = 1
        else:
            raise CVSS3MalformedError('Malformed CVSS3 vector "{0}" is missing mandatory prefix '
                                      'or uses unsupported CVSS version'.format(self.vector))

        try:
            fields = self.vector.split('/')[1:]
        except IndexError:
            raise CVSS3MalformedError('Malformed CVSS3 vector "{0}"'.format(self.vector))

        # Parse fields
        for field in fields:
            if field == '':
                raise CVSS3MalformedError('Empty field in CVSS3 vector "{0}"'.format(self.vector))

            try:
                metric, value = field.split(':')
            except ValueError:
                raise CVSS3MalformedError('Malformed CVSS3 field "{0}"'.format(field))

            if metric in METRICS_ABBREVIATIONS:
                if value in METRICS_VALUES[metric]:
                    if metric in self.metrics:
                        raise CVSS3MalformedError('Duplicate metric "{0}"'.format(metric))
                    self.metrics[metric] = value
                else:
                    raise CVSS3MalformedError('Unknown value "{0}" in field "{1}"'.format(value,
                                                                                          field))
            else:
                raise CVSS3MalformedError('Unknown metric "{0}" in field "{1}"'.format(metric,
                                                                                       field))

    def handle_scope(self):
        """
        Sets scope and modified scope variables based on S and MS metrics
        """
        self.scope = self.metrics['S']
        self.modified_scope = self.metrics.get('MS', None)
        if self.modified_scope in [None, 'X']:
            self.modified_scope = self.scope

    def check_mandatory(self):
        """
        Checks if mandatory fields are in CVSS3 vector.

        Raises:
            CVSS3MandatoryError: if mandatory metric is missing in the vector
        """
        missing = []
        for mandatory_metric in METRICS_MANDATORY:
            if mandatory_metric not in self.metrics:
                missing.append(mandatory_metric)
        if missing:
            raise CVSS3MandatoryError('Missing mandatory metrics "{0}"'.format(', '.join(missing)))

    def add_missing_optional(self):
        """
        Adds missing optional parameters, so they match the mandatory ones. Original metrics are
        also stored, as they may be used for printing back the minimal vector.
        """
        self.original_metrics = copy.copy(self.metrics)
        for abbreviation in ['MAV', 'MAC', 'MPR', 'MUI', 'MC', 'MI', 'MA']:
            if abbreviation not in self.metrics or self.metrics[abbreviation] == 'X':
                self.metrics[abbreviation] = self.metrics[abbreviation[1:]]

    def get_value(self, abbreviation):
        """
        Gets value of specific metric specified by its abbreviation. Handles exception for
        Privileges Required based on Scope or Modified scope.
        """
        string_value = self.metrics.get(abbreviation, 'X')
        if ((abbreviation == 'PR' and self.scope == 'C') or
                (abbreviation == 'MPR' and self.modified_scope == 'C')):
            result = {'X': None, 'N': D('0.85'), 'L': D('0.68'), 'H': D('0.50')}[string_value]
        else:
            result = METRICS_VALUES[abbreviation][string_value]
        return result

    def compute_isc_base(self):
        """
        ISCBase = 1 - [(1-ImpactConf) x (1-ImpactInteg) x (1-ImpactAvail)]
        """
        self.isc_base = D('1') - ((D('1') - self.get_value('C')) *
                                  (D('1') - self.get_value('I')) *
                                  (D('1') - self.get_value('A')))

    def compute_isc(self):
        """
        Scope Unchanged 6.42 x ISCBase
        Scope Changed 7.52 x [ISCBase-0.029] - 3.25 x [ISCBase-0.02]^15
        """
        if self.scope == 'U':
            self.isc = D('6.42') * self.isc_base
        elif self.scope == 'C':
            self.isc = (D('7.52') * (self.isc_base - D('0.029')) -
                        D('3.25') * (self.isc_base - D('0.02')) ** D('15'))
        else:  # This should never happen
            raise RuntimeError('Invalid Scope: "{0}"'.format(self.scope))

    def compute_esc(self):
        """
        8.22 x AttackVector x AttackComplexity x PrivilegeRequired x UserInteraction
        """
        self.esc = (D('8.22') * self.get_value('AV') * self.get_value('AC') *
                    self.get_value('PR') * self.get_value('UI'))

    def compute_base_score(self):
        """
        If (Impact sub score =< 0) 0 else,
        Scope Unchanged Round up (Minimum [(Impact + Exploitability),10])
        Scope Changed Round up (Minimum [1.08 x (Impact + Exploitability),10])
        """
        self.compute_isc_base()
        self.compute_isc()
        self.compute_esc()

        if self.isc <= D('0.0'):
            self.base_score = D('0.0')
        else:
            assert self.scope in ('U', 'C')
            if self.scope == 'U':
                self.base_score = round_up(min((self.isc + self.esc), D('10')))
            elif self.scope == 'C':
                self.base_score = round_up(min(D('1.08') * (self.isc + self.esc), D('10')))

    def compute_temporal_score(self):
        """
        Round up(BaseScore x ExploitCodeMaturity x RemediationLevel x ReportConfidence)
        """
        self.temporal_score = round_up(self.base_score * self.get_value('E') *
                                       self.get_value('RL') * self.get_value('RC'))

    def compute_modified_isc_base(self):
        """
        ISCModified = Minimum[[1-(1-M.IConf x CR)x(1-M.IInteg x IR)x(1-M.IAvail x AR)],0.915]
        """
        # Had to rename this term, as Modified Impact Sub score is already taken.
        self.modified_isc_base = min((D('1') - (D('1') - self.get_value('MC') *
                                                self.get_value('CR')) *
                                               (D('1') - self.get_value('MI') *
                                                self.get_value('IR')) *
                                               (D('1') - self.get_value('MA') *
                                                self.get_value('AR'))
                                      ),
                                     D('0.915'))

    def compute_modified_isc_30(self):
        """
        This is CVSS:3.0 version

        If Modified Scope Unchanged    6.42 x [ISCModified]
        If Modified Scope Changed      7.52 x [ISCModified-0.029] - 3.25 x [ISCModified-0.02]^15
        """
        if self.modified_scope == 'U':
            self.modified_isc = D('6.42') * self.modified_isc_base
        else:  # Modified scope has always value, if not defined then matches Scope
            self.modified_isc = (D('7.52') * (self.modified_isc_base - D('0.029')) -
                                 D('3.25') * (self.modified_isc_base - D('0.02')) ** D('15'))

    def compute_modified_isc(self):
        """
        This is CVSS:3.1 version

        If Modified Scope Unchanged    6.42 x [ISCModified]
        If Modified Scope Changed      7.52 x (ISCModified - 0.029) - 3.25 x
                                       (ISCModified x 0.9731 - 0.02)^13
        """
        if self.modified_scope == 'U':
            self.modified_isc = D('6.42') * self.modified_isc_base
        else:  # Modified scope has always value, if not defined then matches Scope
            self.modified_isc = (D('7.52') * (self.modified_isc_base - D('0.029')) -
                                 D('3.25') * (self.modified_isc_base * D('0.9731') - D('0.02'))
                                 ** D('13'))

    def compute_modified_esc(self):
        """
        8.22 x M.AttackVector x M.AttackComplexity x M.PrivilegeRequired x M.UserInteraction
        """
        self.modified_esc = (D('8.22') * self.get_value('MAV') * self.get_value('MAC') *
                             self.get_value('MPR') * self.get_value('MUI'))

    def compute_environmental_score(self):
        """
        If (Modified Impact Sub score =< 0)    0 else,
        If Modified Scope Unchanged    Round up(Round up (Minimum [
                          (M.Impact + M.Exploitability),10])
                          x Exploit Code Maturity
                          x Remediation Level
                          x Report Confidence)

        If Modified Scope Changed    Round up(Round up (Minimum [1.08
                          x (M.Impact + M.Exploitability),10])
                          x Exploit Code Maturity
                          x Remediation Level
                          x Report Confidence))
        """
        self.compute_modified_isc_base()
        if self.minor_version == 0:
            self.compute_modified_isc_30()
        else:
            self.compute_modified_isc()
        self.compute_modified_esc()

        if self.modified_isc <= D('0.0'):
            self.environmental_score = D('0.0')
        else:
            if self.modified_scope == 'U':
                modified = round_up(min((self.modified_isc + self.modified_esc), D('10')))
            else:
                modified = round_up(min(D('1.08') * (self.modified_isc + self.modified_esc), D('10')))
            self.environmental_score = round_up(modified *
                                                self.get_value('E') *
                                                self.get_value('RL') *
                                                self.get_value('RC'))

    def scores(self):
        """
        Returns all computed scores.

        Returns:
            (tuple of floats): Base Score, Temporal Score, Environmental Score
        """
        return float(self.base_score), float(self.temporal_score), float(self.environmental_score)

    def clean_vector(self, output_prefix=True):
        """
        Returns vector without optional metrics marked as X and in preferred order.

        Args:
            output_prefix (bool): defines if CVSS vector should be printed with prefix

        Returns:
            (str): cleaned CVSS3 with metrics in correct order
        """
        vector = []
        for metric in METRICS_ABBREVIATIONS:
            if metric in self.original_metrics:
                value = self.original_metrics[metric]
                if value != 'X':
                    vector.append('{0}:{1}'.format(metric, value))
        if output_prefix:
            prefix = 'CVSS:3.{0}/'.format(self.minor_version)
        else:
            prefix = ''
        return prefix + '/'.join(vector)

    def severities(self):
        """
        Returns severities based on scores.

        Returns:
            (tuple): Base Severity, Temporal Severity, Environmental Severity as strings
        """
        severities = []
        for score in (self.base_score, self.temporal_score, self.environmental_score):
            if score == D('0.0'):
                severities.append('None')
            elif score <= D('3.9'):
                severities.append('Low')
            elif score <= D('6.9'):
                severities.append('Medium')
            elif score <= D('8.9'):
                severities.append('High')
            else:
                severities.append('Critical')
        return tuple(severities)

    def rh_vector(self):
        """
        Returns cleaned vector with score in Red Hat notation, e.g. score/vector.

        Example: 6.5/CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L
        """
        return str(self.scores()[0]) + '/' + self.clean_vector()

    def __eq__(self, o):
        if isinstance(o, CVSS3):
            return self.clean_vector().__eq__(o.clean_vector())
        return NotImplemented

    def __hash__(self):
        return hash(self.clean_vector())
