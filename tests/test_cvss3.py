import json
import random
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import parser
from cvss.cvss2 import CVSS2
from cvss.cvss3 import CVSS3
from cvss.exceptions import (
    CVSS3MalformedError,
    CVSS3MandatoryError,
    CVSS3RHMalformedError,
    CVSS3RHScoreDoesNotMatch,
)

WD = path.dirname(path.abspath(sys.argv[0]))  # Manage to run script anywhere in the path


class TestCVSS3(unittest.TestCase):
    def run_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.split(" - ")
                expected_scores = expected_scores.replace("(", "").replace(")", "").split(", ")
                expected_scores = tuple(float(a) for a in expected_scores)
                result = CVSS3(vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + " - " + vector)

    def run_rh_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.split(" - ")
                expected_scores = (
                    expected_scores.replace("(", "").replace(")", "").strip().split(", ")
                )
                expected_scores = tuple(float(a) if a != "None" else None for a in expected_scores)
                tested_rh_vector = str(expected_scores[0]) + "/" + vector
                result = CVSS3.from_rh_vector(tested_rh_vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + " - " + vector)

    def test_simple(self):
        """
        All vector combinations with only mandatory fields, 2,592 vectors.
        """
        self.run_tests_from_file("vectors_simple3")

    def test_simple_31(self):
        """
        All vector combinations with only mandatory fields. Computed using
         https://www.first.org/cvss/calculator/3.1 . 2,592 vectors.
        """
        self.run_tests_from_file("vectors_simple31")

    def test_calculator(self):
        """
        Hand picked vectors using https://www.first.org/cvss/calculator/3.0 . 2 vectors.
        """
        self.run_tests_from_file("vectors_calculator3")

    def test_cvsslib(self):
        """
        Tests which cvsslib from https://pypi.python.org/pypi/cvsslib uses. 29 vectors.
        """
        self.run_tests_from_file("vectors_cvsslib3")

    def test_random(self):
        """
        Random generated test vectors, values computed using cvsslib from
        https://pypi.python.org/pypi/cvsslib . 100,000 vectors.
        """
        self.run_tests_from_file("vectors_random3")

    def test_random_31(self):
        """
        Random generated test vectors, values computed using
        https://www.first.org/cvss/calculator/3.1 . 100,000 vectors.
        """
        self.run_tests_from_file("vectors_random31")

    def test_clean_vector(self):
        """
        Tests for cleaning-up vector, where fields are not in order or some fields have X values.
        """
        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L",
            CVSS3(v).clean_vector(),
        )

        v = "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MUI:X/MS:U/MI:X"
        self.assertEqual(
            "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MS:U",
            CVSS3(v).clean_vector(),
        )

        v = "CVSS:3.0/A:N/E:P/RC:C/MAV:N/AV:A/AC:H/S:U/C:N/I:L/MPR:H/MUI:X/MS:U/MI:X/PR:H/UI:R"
        self.assertEqual(
            "CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RC:C/MAV:N/MPR:H/MS:U",
            CVSS3(v).clean_vector(),
        )

    def test_severities(self):
        """
        Tests for computing severities.
        """
        v = "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:N"
        self.assertEqual(("None", "None", "None"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N"
        self.assertEqual(("Low", "Low", "Low"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N"
        self.assertEqual(("Low", "Low", "Low"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
        self.assertEqual(("Low", "Low", "Low"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
        self.assertEqual(("Medium", "Medium", "Medium"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L"
        self.assertEqual(("Medium", "Medium", "Medium"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
        self.assertEqual(("Medium", "Medium", "Medium"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        self.assertEqual(("High", "High", "High"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
        self.assertEqual(("High", "High", "High"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
        self.assertEqual(("Critical", "Critical", "Critical"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H"
        self.assertEqual(("Critical", "Critical", "Critical"), CVSS3(v).severities(), v)

        v = (
            "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/"
            "E:P/RL:W/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MC:N/MI:N"
        )
        self.assertEqual(("High", "High", "Medium"), CVSS3(v).severities(), v)

        v = "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/E:H/RC:U/CR:M/MAV:P/MAC:L/MUI:R/MC:N/MI:N"
        self.assertEqual(("Medium", "Low", "None"), CVSS3(v).severities(), v)

    def test_exceptions(self):
        """
        Test for exceptions in CVSS vector parsing.
        """
        v = ""
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        v = "/"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Missing ':'
        v = "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MCL"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unknown metric
        v = "CVSS:3.0/AX:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unknown value
        v = "CVSS:3.0/AV:W/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Duplicate metric
        v = "CVSS:3.0/AV:P/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Duplicate metric
        v = "CVSS:3.0/AV:P/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Missing mandatory metric PR
        v = "CVSS:3.0/AV:P/AC:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MandatoryError, CVSS3, v)

        # Missing mandatory metric S
        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"
        self.assertRaises(CVSS3MandatoryError, CVSS3, v)

        # Missing prefix
        v = "AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Unsupported version
        v = "CVSS:3.2/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

        # Empty field
        "CVSS:3.0//AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L"
        self.assertRaises(CVSS3MalformedError, CVSS3, v)

    def test_rh_vector(self):
        """
        Test for parsing Red Hat style of CVSS vectors, e.g. containing score.
        """
        self.run_rh_tests_from_file("vectors_simple3")

        # Bad values
        v = "10.0/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:L"
        self.assertRaises(CVSS3RHScoreDoesNotMatch, CVSS3.from_rh_vector, v)

        v = "7.0/CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
        self.assertRaises(CVSS3RHScoreDoesNotMatch, CVSS3.from_rh_vector, v)

        v = "6.1/CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L"
        self.assertRaises(CVSS3RHScoreDoesNotMatch, CVSS3.from_rh_vector, v)

        # Vector cannot be split to score/vector
        v = ""
        self.assertRaises(CVSS3RHMalformedError, CVSS3.from_rh_vector, v)

        v = "6.1|CVSS:3.0|AV:A|AC:H|PR:N|UI:R|S:C|C:L|I:H|A:L"
        self.assertRaises(CVSS3RHMalformedError, CVSS3.from_rh_vector, v)

        # Score is not float
        v = "ABC/CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L"
        self.assertRaises(CVSS3RHMalformedError, CVSS3.from_rh_vector, v)

    def test_temporal_vector(self):
        """
        Test for retrieving only the Temporal CVSS Vector.
        """
        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "E:H/RL:O/RC:R",
            CVSS3(v).temporal_vector(),
        )

        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "E:X/RL:X/RC:X",
            CVSS3(v).temporal_vector(),
        )

        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "E:X/RL:O/RC:R",
            CVSS3(v).temporal_vector(),
        )

        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "E:H/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "E:H/RL:X/RC:R",
            CVSS3(v).temporal_vector(),
        )

        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "E:H/RL:O/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "E:H/RL:O/RC:X",
            CVSS3(v).temporal_vector(),
        )

    def test_environmental_vector(self):
        """
        Test for retrieving only the Environmental CVSS Vector.
        """
        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X"
        )
        self.assertEqual(
            "CR:H/IR:X/AR:X/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:N",
            CVSS3(v).environmental_vector(),
        )

        v = "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R"
        self.assertEqual(
            "CR:X/IR:X/AR:X/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:N",
            CVSS3(v).environmental_vector(),
        )

        v = (
            "CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/"
            "E:H/RL:O/RC:R/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:L/MI:N/MA:H/CR:M/IR:L/AR:M"
        )
        self.assertEqual(
            "CR:M/IR:L/AR:M/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:L/MI:N/MA:H",
            CVSS3(v).environmental_vector(),
        )

    def test_parse_from_text_cvss3(self):
        i = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        e = [CVSS3(i)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = "CVSS"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # Truncated vector
        i = "CVSS:3"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = "CVSS:3.0"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = "CVSS:3.0/"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = "CVSS:3.0/AV:N"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = "CVSS:3.0/AV:X"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = "CVSS:3.0/AV:ZZZ"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        i = (
            "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/"
            "MAV:A/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N"
        )
        e = [CVSS3(i)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # Missing mandatory prefix
        i = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        e = []
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        v1 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v2 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        i = " ".join([v1, v2])
        e = set()
        e.add(CVSS3(v1))
        e.add(CVSS3(v2))
        self.assertEqual(set(parser.parse_cvss_from_text(i)), e)

        # Correct text
        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        i = "xxx " + v
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        i = v + " xxx"
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

    def test_parse_from_text_optional_sentence_cases(self):
        # Missing space after end of sentence and before vector
        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
        i = "." + v
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # End of sentence
        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
        i = v + "."
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

        # Missing space after dot before vector
        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        i = "xxx." + v
        e = [CVSS3(v)]
        self.assertEqual(parser.parse_cvss_from_text(i), e)

    def test_parse_from_text_both_versions(self):
        v1 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
        v2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        i = "xxx. " + v1 + " " + v2 + ". xxx"
        e = set()
        e.add(CVSS3(v1))
        e.add(CVSS2(v2))
        self.assertEqual(set(parser.parse_cvss_from_text(i)), e)

    def test_parse_from_text_both_versions_optional(self):
        # Missing spaces around sentence
        v1 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
        v2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        i = "xxx." + v1 + " " + v2 + ".xxx"
        e = set()
        e.add(CVSS3(v1))
        e.add(CVSS2(v2))
        self.assertEqual(set(parser.parse_cvss_from_text(i)), e)

    def test_parse_from_text_multiple_vectors_same_cvss(self):
        v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        e = [CVSS3(v)]
        i = "Title: {0}\nThis is an overview of {0} problem.\nLinks: {0}".format(v)
        self.assertEqual(parser.parse_cvss_from_text(i), e)

    def test_json_ordering(self):
        vectors_to_schema = {
            "vectors_random3": "schemas/cvss-v3.0.json",
            "vectors_random31": "schemas/cvss-v3.1.json",
        }
        for vectors_file_path, schema_file_path in vectors_to_schema.items():
            with open(path.join(WD, vectors_file_path)) as f:
                for line in f:
                    vector, _ = line.split(" - ")
                    cvss = CVSS3(vector).as_json(sort=True)
                    old_key = ""
                    for key in cvss:
                        if key < old_key:
                            self.fail(
                                "dict ordering was not preserved: key {} less than previous key {} "
                                "for CVSS object {}".format(key, old_key, cvss)
                            )
                        old_key = key

    def test_json_schema_repr(self):
        try:
            import jsonschema
        except ImportError:
            return
        vectors_to_schema = {
            "vectors_random3": "schemas/cvss-v3.0.json",
            "vectors_random31": "schemas/cvss-v3.1.json",
        }
        for vectors_file_path, schema_file_path in vectors_to_schema.items():
            with open(path.join(WD, schema_file_path)) as schema_file:
                schema = json.load(schema_file)

            vectors = []
            with open(path.join(WD, vectors_file_path)) as f:
                for line in f:
                    vectors.append(line.split(" - ")[0])

            # Pick 500 random vectors; verifying all 100k is very slow.
            for vector in random.sample(vectors, k=500):
                cvss = CVSS3(vector)
                try:
                    jsonschema.validate(instance=cvss.as_json(), schema=schema)
                except jsonschema.exceptions.ValidationError:
                    self.fail("jsonschema validation failed on vector: {}".format(vector))

    def test_json_schema_severities(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/CR:L/IR:L/AR:L/MAV:P"
        json_data = CVSS3(v).as_json()

        self.assertEqual(json_data["baseSeverity"], "HIGH")
        self.assertEqual(json_data["temporalSeverity"], "MEDIUM")
        self.assertEqual(json_data["environmentalSeverity"], "LOW")

    def test_json_schema_minimal_base_only(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        json_data = CVSS3(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseSeverity"], "HIGH")
        self.assertIn("attackVector", json_data)
        self.assertNotIn("exploitCodeMaturity", json_data)
        self.assertNotIn("modifiedAttackVector", json_data)

    def test_json_schema_minimal_temporal_only(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:H"
        json_data = CVSS3(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseSeverity"], "HIGH")
        self.assertIn("attackVector", json_data)
        self.assertIn("exploitCodeMaturity", json_data)
        self.assertIn("temporalSeverity", json_data)
        self.assertNotIn("modifiedAttackVector", json_data)

    def test_json_schema_minimal_environmental_only(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:H"
        json_data = CVSS3(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseSeverity"], "HIGH")
        self.assertIn("attackVector", json_data)
        self.assertNotIn("exploitCodeMaturity", json_data)
        self.assertIn("confidentialityRequirement", json_data)


if __name__ == "__main__":
    unittest.main()
