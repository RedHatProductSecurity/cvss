import ast
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.cvss4 import CVSS4
from cvss.exceptions import (
    CVSS4MalformedError,
    CVSS4RHMalformedError,
    CVSS4RHScoreDoesNotMatch,
)

WD = path.dirname(path.abspath(sys.argv[0]))  # Manage to run script anywhere in the path


class TestCVSS4(unittest.TestCase):
    def run_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_score = line.split(" - ")
                expected_score = expected_score.replace("(", "").replace(")", "")
                expected_score = float(expected_score)
                result = CVSS4(vector)
                results_score = result.base_score
                self.assertEqual(expected_score, results_score, test_name + " - " + vector)
                results_json_score = result.as_json()["baseScore"]
                self.assertEqual(
                    expected_score, results_json_score, test_name + " - " + vector + " - JSON"
                )

    def run_rh_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.strip().split(" - ")
                expected_scores = ast.literal_eval(expected_scores)
                tested_rh_vector = str(expected_scores[0]) + "/" + vector
                result = CVSS4.from_rh_vector(tested_rh_vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + " - " + vector)

    def test_base(self):
        """
        All vector combinations with only mandatory fields, 104,976 bn vectors.
        """
        self.run_tests_from_file("vectors_base4")

    def test_modified(self):
        """
        All vector combinations of modified environmental fields, 373,248 vectors.
        """
        self.run_tests_from_file("vectors_modified4")

    def test_supplemental(self):
        """
        All vector combinations of supplemental fields, 576 vectors.
        """
        self.run_tests_from_file("vectors_supplemental4")

    def test_security(self):
        """
        All vector combinations of security fields, 54 vectors.
        """
        self.run_tests_from_file("vectors_security4")

    def test_threat(self):
        """
        All vector combinations of threat fields, 6 vectors.
        """
        self.run_tests_from_file("vectors_threat4")

    def test_random(self):
        """
        Random vector combinations across all fields, 10,000 bn vectors.
        """
        self.run_tests_from_file("vectors_random4")

    def test_severity(self):
        """
        Tests for computing severities.
        """

        v = (
            "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/"
            "SC:N/SI:N/AU:N/SA:N/S:P/R:A/V:D/RE:L/U:Red/MAV:L/MAC:L/MAT:N/"
            "MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:H/MSI:L/MSA:N/CR:H/IR:L/AR:L/E:P"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/"
            "SC:H/SI:N/AU:Y/SA:N/S:N/R:I/V:C/RE:M/U:Amber/MAV:L/MAC:H/MAT:P"
            "/MPR:N/MUI:P/MVC:L/MVI:N/MVA:H/MSC:H/MSI:H/MSA:S/CR:M/IR:M/AR:M/E:A"
        )
        self.assertEqual(("High"), CVSS4(v).severity, v)
        self.assertEqual(("High"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/"
            "SC:L/SI:N/AU:Y/SA:L/S:P/R:U/V:D/RE:M/U:Red/MAV:N/MAC:H/MAT:P"
            "/MPR:H/MUI:P/MVC:L/MVI:H/MVA:L/MSC:N/MSI:H/MSA:H/CR:L/IR:H/AR:M/E:U"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/"
            "SC:N/SI:H/AU:N/SA:L/S:P/R:U/V:D/RE:H/U:Clear/MAV:A/MAC:L/MAT:N"
            "/MPR:N/MUI:P/MVC:N/MVI:L/MVA:L/MSC:H/MSI:N/MSA:L/CR:M/IR:M/AR:L/E:U"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:N/"
            "SC:H/SI:N/AU:Y/SA:N/S:N/R:I/V:C/RE:L/U:Green/MAV:L/MAC:L/MAT:N"
            "/MPR:H/MUI:P/MVC:L/MVI:L/MVA:N/MSC:H/MSI:H/MSA:S/CR:H/IR:H/AR:H/E:P"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:H/"
            "SC:H/SI:L/AU:Y/SA:H/S:N/R:U/V:C/RE:M/U:Amber/MAV:L/MAC:H/MAT:N"
            "/MPR:H/MUI:N/MVC:N/MVI:L/MVA:N/MSC:L/MSI:S/MSA:H/CR:H/IR:M/AR:M/E:A"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/"
            "SC:H/SI:H/AU:N/SA:N/S:N/R:A/V:C/RE:M/U:Green/MAV:L/MAC:L/MAT:P"
            "/MPR:L/MUI:A/MVC:N/MVI:L/MVA:H/MSC:L/MSI:N/MSA:S/CR:L/IR:L/AR:M/E:P"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/"
            "SC:L/SI:N/AU:N/SA:H/S:P/R:I/V:D/RE:M/U:Red/MAV:N/MAC:L/MAT:N"
            "/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/CR:H/IR:H/AR:H/E:U"
        )
        self.assertEqual(("Critical"), CVSS4(v).severity, v)
        self.assertEqual(("Critical"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:H/"
            "SC:L/SI:N/AU:Y/SA:H/S:P/R:I/V:D/RE:H/U:Green/MAV:A/MAC:L/MAT:N"
            "/MPR:N/MUI:A/MVC:L/MVI:H/MVA:H/MSC:N/MSI:H/MSA:L/CR:L/IR:H/AR:L/E:U"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/"
            "SC:L/SI:H/AU:N/SA:H/S:P/R:U/V:C/RE:H/U:Red/MAV:L/MAC:L/MAT:P"
            "/MPR:L/MUI:P/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/CR:H/IR:H/AR:H/E:P"
        )
        self.assertEqual(("None"), CVSS4(v).severity, v)
        self.assertEqual(("None"), CVSS4(v).as_json()["baseSeverity"], v)

    def test_json_schema_no_impact_metrics(self):
        v = "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 0.0)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("attackVector", json_data)

    def test_json_schema_high_va(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 8.7)
        self.assertEqual(json_data["vectorString"], v)

    def test_json_schema_high_va_low_ar(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/AR:L"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 7.9)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("availabilityRequirements", json_data)

    def test_json_schema_high_msi(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:H"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 7.7)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("modifiedSubsequentSystemImpactIntegrity", json_data)
        self.assertIn("subsequentSystemImpactIntegrity", json_data)

    def test_invalid_metric_key(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/JJ:H"
        error = ""
        try:
            CVSS4(v)
        except CVSS4MalformedError as e:
            error = str(e)
        self.assertEqual(error, 'Invalid metric key in CVSS4 vector "JJ:H"')

    def test_invalid_metric_value(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:J"
        error = ""
        try:
            CVSS4(v)
        except CVSS4MalformedError as e:
            error = str(e)
        self.assertEqual(error, 'Invalid metric value in CVSS4 vector "SA:J"')

    def test_duplicate_metric_key(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SI:H"
        error = ""
        try:
            CVSS4(v)
        except CVSS4MalformedError as e:
            error = str(e)
        self.assertEqual(error, 'Duplicate metric "SI"')

    def test_rh_vector(self):
        """
        Test for parsing Red Hat style of CVSS vectors, e.g. containing score.
        """
        self.run_rh_tests_from_file("vectors_simple4")

        # Bad values
        v = "8.3/CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N"
        self.assertRaises(CVSS4RHScoreDoesNotMatch, CVSS4.from_rh_vector, v)

        v = "7.0/CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:L/SA:N"
        self.assertRaises(CVSS4RHScoreDoesNotMatch, CVSS4.from_rh_vector, v)

        # Vector cannot be split to score/vector
        v = ""
        self.assertRaises(CVSS4RHMalformedError, CVSS4.from_rh_vector, v)

        v = "8.3|AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L"
        self.assertRaises(CVSS4RHMalformedError, CVSS4.from_rh_vector, v)

        # Score is not float
        v = "ABC|AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L"
        self.assertRaises(CVSS4RHMalformedError, CVSS4.from_rh_vector, v)


if __name__ == "__main__":
    unittest.main()
