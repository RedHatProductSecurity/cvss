from os import path
import sys
import unittest

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError, CVSS3MandatoryError


WD = path.dirname(path.abspath(__file__))  # Manage to run script anywhere in the path


class Test_CVSS3(unittest.TestCase):
    def run_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.split(' - ')
                expected_scores = expected_scores.replace('(', '').replace(')', '').split(', ')
                expected_scores = tuple(float(a) for a in expected_scores)
                result = CVSS3(vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + ' - ' + vector)

    def test_simple(self):
        """
        All vector combinations with only mandatory fields, 2,592 vectors.
        """
        self.run_tests_from_file('vectors_simple3')

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

    def test_clean_vector(self):
        """
        Tests for cleaning-up vector, where fields are not in order or some fields have X velues.
        """
        v = 'S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'
        self.assertEqual('AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L',
                         CVSS3(v).clean_vector())

        v = 'AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MUI:X/MS:U/MI:X'
        self.assertEqual('AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MS:U',
                         CVSS3(v).clean_vector())

        v = 'A:N/E:P/RC:C/MAV:N/AV:A/AC:H/S:U/C:N/I:L/MPR:H/MUI:X/MS:U/MI:X/PR:H/UI:R'
        self.assertEqual('AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MS:U',
                         CVSS3(v).clean_vector())

    def test_severities(self):
        """
        Tests for computing severities.
        """
        v = 'AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:N'
        self.assertEqual(('None', 'None', 'None'), CVSS3(v).severities(), v)

        v = 'AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N'
        self.assertEqual(('Low', 'Low', 'Low'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N'
        self.assertEqual(('Low', 'Low', 'Low'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L'
        self.assertEqual(('Low', 'Low', 'Low'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L'
        self.assertEqual(('Medium', 'Medium', 'Medium'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L'
        self.assertEqual(('Medium', 'Medium', 'Medium'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N'
        self.assertEqual(('Medium', 'Medium', 'Medium'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
        self.assertEqual(('High', 'High', 'High'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H'
        self.assertEqual(('High', 'High', 'High'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N'
        self.assertEqual(('Critical', 'Critical', 'Critical'), CVSS3(v).severities(), v)

        v = 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H'
        self.assertEqual(('Critical', 'Critical', 'Critical'), CVSS3(v).severities(), v)

        v = 'AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:W/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MC:N/MI:N'
        self.assertEqual(('High', 'High', 'Medium'), CVSS3(v).severities(), v)

        v = 'AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/E:H/RC:U/CR:M/MAV:P/MAC:L/MUI:R/MC:N/MI:N'
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
        v = 'AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MCL'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unknown metric
        v = 'AX:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unknown value
        v = 'AV:W/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Duplicit metric
        v = 'AV:P/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Duplicit metric
        v = 'AV:P/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Missing mandatory
        v = 'AV:P/AC:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L'
        self.assertRaises(CVSS3MandatoryError, CVSS3, v)


if __name__ == '__main__':
    unittest.main()
