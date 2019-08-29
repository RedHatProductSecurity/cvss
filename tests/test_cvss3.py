from os import path
import sys
import unittest

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.cvss3 import CVSS3
from cvss.cvss2 import CVSS2
from cvss import parser
from cvss.exceptions import CVSS3MalformedError, CVSS3MandatoryError, CVSS3RHScoreDoesNotMatch, \
    CVSS3RHMalformedError

WD = path.dirname(path.abspath(sys.argv[0]))  # Manage to run script anywhere in the path


class TestCVSS3(unittest.TestCase):
    def run_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.split(' - ')
                expected_scores = expected_scores.replace('(', '').replace(')', '').split(', ')
                expected_scores = tuple(float(a) for a in expected_scores)
                result = CVSS3(vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + ' - ' + vector)

    def run_rh_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.split(' - ')
                expected_scores = expected_scores.replace('(', '').replace(')', '').strip().split(', ')
                expected_scores = tuple(float(a) if a != 'None' else None for a in expected_scores)
                tested_rh_vector = str(expected_scores[0]) + '/' + vector
                result = CVSS3.from_rh_vector(tested_rh_vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + ' - ' + vector)

    def test_simple(self):
        """
        All vector combinations with only mandatory fields, 2,592 vectors.
        """
        self.run_tests_from_file('vectors_simple3')

    def test_simple_31(self):
        """
        All vector combinations with only mandatory fields. Computed using
         https://www.first.org/cvss/calculator/3.1 . 2,592 vectors.
        """
        self.run_tests_from_file('vectors_simple31')

    def test_calculator(self):
        """
        Hand picked vectors using https://www.first.org/cvss/calculator/3.0 . 2 vectors.
        """
        self.run_tests_from_file('vectors_calculator3')

    def test_cvsslib(self):
        """
        Tests which cvsslib from https://pypi.python.org/pypi/cvsslib uses. 29 vectors.
        """
        self.run_tests_from_file('vectors_cvsslib3')

    def test_random(self):
        """
        Random generated test vectors, values computed using cvsslib from
        https://pypi.python.org/pypi/cvsslib . 100,000 vectors.
        """
        self.run_tests_from_file('vectors_random3')

    def test_random_31(self):
        """
        Random generated test vectors, values computed using
        https://www.first.org/cvss/calculator/3.1 . 100,000 vectors.
        """
        self.run_tests_from_file('vectors_random31')

    def test_clean_vector(self):
        """
        Tests for cleaning-up vector, where fields are not in order or some fields have X values.
        """
        v = 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'
        self.assertEqual('CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L',
                         CVSS3(v).clean_vector())

        v = 'CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MUI:X/MS:U/MI:X'
        self.assertEqual('CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MS:U',
                         CVSS3(v).clean_vector())

        v = 'CVSS:3.0/A:N/E:P/RC:C/MAV:N/AV:A/AC:H/S:U/C:N/I:L/MPR:H/MUI:X/MS:U/MI:X/PR:H/UI:R'
        self.assertEqual('CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MS:U',
                         CVSS3(v).clean_vector())

    def test_severities(self):
        """
        Tests for computing severities.
        """
        v = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:N'
        self.assertEqual(('None', 'None', 'None'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N'
        self.assertEqual(('Low', 'Low', 'Low'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N'
        self.assertEqual(('Low', 'Low', 'Low'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L'
        self.assertEqual(('Low', 'Low', 'Low'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L'
        self.assertEqual(('Medium', 'Medium', 'Medium'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L'
        self.assertEqual(('Medium', 'Medium', 'Medium'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N'
        self.assertEqual(('Medium', 'Medium', 'Medium'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
        self.assertEqual(('High', 'High', 'High'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H'
        self.assertEqual(('High', 'High', 'High'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N'
        self.assertEqual(('Critical', 'Critical', 'Critical'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H'
        self.assertEqual(('Critical', 'Critical', 'Critical'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:W/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MC:N/MI:N'
        self.assertEqual(('High', 'High', 'Medium'), CVSS3(v).severities(), v)

        v = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/E:H/RC:U/CR:M/MAV:P/MAC:L/MUI:R/MC:N/MI:N'
        self.assertEqual(('Medium', 'Low', 'None'), CVSS3(v).severities(), v)

    def test_exceptions(self):
        """
        Test for exceptions in CVSS vector parsing.
        """
        v = ''
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        v = '/'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Missing ':'
        v = 'CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MCL'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unknown metric
        v = 'CVSS:3.0/AX:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unknown value
        v = 'CVSS:3.0/AV:W/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Duplicate metric
        v = 'CVSS:3.0/AV:P/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Duplicate metric
        v = 'CVSS:3.0/AV:P/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Missing mandatory metric PR
        v = 'CVSS:3.0/AV:P/AC:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MandatoryError, CVSS3, v)

        # Missing mandatory metric S
        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H'
        self.assertRaises(CVSS3MandatoryError, CVSS3, v)

        # Missing prefix
        v = 'AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unsupported version
        v = 'CVSS:3.2/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Empty field
        'CVSS:3.0//AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

    def test_rh_vector(self):
        """
        Test for parsing Red Hat style of CVSS vectors, e.g. containing score.
        """
        self.run_rh_tests_from_file('vectors_simple3')

        # Bad values
        v = '10.0/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:L'
        self.assertRaises(CVSS3RHScoreDoesNotMatch, CVSS3.from_rh_vector, v)

        v = '7.0/CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H'
        self.assertRaises(CVSS3RHScoreDoesNotMatch, CVSS3.from_rh_vector, v)

        v = '6.1/CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L'
        self.assertRaises(CVSS3RHScoreDoesNotMatch, CVSS3.from_rh_vector, v)

        # Vector cannot be split to score/vector
        v = ''
        self.assertRaises(CVSS3RHMalformedError, CVSS3.from_rh_vector, v)

        v = '6.1|CVSS:3.0|AV:A|AC:H|PR:N|UI:R|S:C|C:L|I:H|A:L'
        self.assertRaises(CVSS3RHMalformedError, CVSS3.from_rh_vector, v)

        # Score is not float
        v = 'ABC/CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L'
        self.assertRaises(CVSS3RHMalformedError, CVSS3.from_rh_vector, v)

    def test_parse_from_text_cvss3(self):
        i = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        e = [CVSS3(i)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # Truncated vector
        i = 'CVSS:3'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS:3.0'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS:3.0/'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS:3.0/AV:N'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS:3.0/AV:X'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS:3.0/AV:ZZZ'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = 'CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N'
        e = [CVSS3(i)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # Missing mandatory prefix
        i = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        v1 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        v2 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
        i = ' '.join([v1, v2])
        e = set()
        e.add(CVSS3(v1))
        e.add(CVSS3(v2))
        self.assertEqual(set(parser.parse_cvss_from_text(i)), e)

        # Correct text
        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        i = 'xxx ' + v
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        i = v + ' xxx'
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

    def test_parse_from_text_optional_sentence_cases(self):
        # Missing space after end of sentence and before vector
        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
        i = '.' + v
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # End of sentence
        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
        i = v + '.'
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # Missing space after dot before vector
        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        i = 'xxx.' + v
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

    def test_parse_from_text_both_versions(self):
        v1 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
        v2 = 'AV:N/AC:L/Au:N/C:C/I:C/A:C'
        i = 'xxx. ' + v1 + ' ' + v2 + '. xxx'
        e = set()
        e.add(CVSS3(v1))
        e.add(CVSS2(v2))
        self.assertEqual(set(parser.parse_cvss_from_text(i)), e)

    def test_parse_from_text_both_versions_optional(self):
        # Missing spaces around sentence
        v1 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
        v2 = 'AV:N/AC:L/Au:N/C:C/I:C/A:C'
        i = 'xxx.' + v1 + ' ' + v2 + '.xxx'
        e = set()
        e.add(CVSS3(v1))
        e.add(CVSS2(v2))
        self.assertEqual(set(parser.parse_cvss_from_text(i)), e)

    def test_parse_from_text_multiple_vectors_same_cvss(self):
        v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        e = [CVSS3(v)]
        i = 'Title: {0}\nThis is an overview of {0} problem.\nLinks: {0}'.format(v)
        self.assertEqual(parser.parse_cvss_from_text(i), e)


if __name__ == '__main__':
    unittest.main()
