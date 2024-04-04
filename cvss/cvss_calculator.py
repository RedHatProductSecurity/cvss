# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Computes CVSS2/3 score either supplied on command line or interactively. By default it only takes
mandatory metrics and computes CVSS3.1.
"""

from __future__ import print_function

import argparse
import json

from cvss import CVSS2, CVSS3, CVSS4, CVSSError, ask_interactively

PAD = 24  # string padding for score names
DEFAULT_VERSION = 3.1


def main():
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "-2", action="store_true", help="compute CVSS2 (default {0})".format(DEFAULT_VERSION)
        )
        parser.add_argument(
            "-3", action="store_true", help="compute CVSS3.0 (default {0})".format(DEFAULT_VERSION)
        )
        parser.add_argument(
            "-4", action="store_true", help="compute CVSS4.0 (default {0})".format(DEFAULT_VERSION)
        )
        parser.add_argument("-a", "--all", action="store_true", help="ask for all metrics")
        parser.add_argument("-v", "--vector", help="input string with CVSS vector")
        parser.add_argument(
            "-n", "--no-colors", action="store_true", help="do not use terminal coloring"
        )
        parser.add_argument(
            "-j", "--json", action="store_true", help="output vector in JSON format"
        )
        args = parser.parse_args()

        version_mapping = {"2": 2, "3": 3.0, "3.1": 3.1, "4": 4.0}
        # Find the key in args where the value is True
        true_version_key = next((key for key, value in args.__dict__.items() if value), None)
        # Use the found key to get the version from version_mapping,
        # default to DEFAULT_VERSION if not found.
        version = version_mapping.get(true_version_key, DEFAULT_VERSION)
        # Vector input, either from command line or interactively
        if args.vector:
            vector_string = args.vector
        else:
            vector_string = ask_interactively(version, args.all, args.no_colors)

        # Compute scores and clean vector
        try:
            # Init the correct CVSS module
            if version == 2:
                cvss_vector = CVSS2(vector_string)
            elif 3.0 <= version < 4.0:
                cvss_vector = CVSS3(vector_string)
            elif version == 4.0:
                cvss_vector = CVSS4(vector_string)
            else:
                raise CVSSError("Unknown version: {0}".format(version))
        except CVSSError as e:
            print(e)
        else:
            scores = cvss_vector.scores()
            severities = None
            if version == 2:
                print("CVSS2")
            elif 3.0 <= version < 4.0:
                print("CVSS3")
                severities = cvss_vector.severities()
            elif version >= 4.0:
                print("CVSS4")
                severities = cvss_vector.severities()
            else:
                raise ValueError("Unknown CVSS version: {0}".format(version))

            for i, score_name in enumerate(["Base Score", "Temporal Score", "Environmental Score"]):
                score = None
                try:
                    if version >= 3.0:
                        score = scores[i], "({0})".format(severities[i])
                    else:
                        score = (scores[i],)
                except IndexError:
                    pass
                if score:
                    print(score_name + ":" + " " * (PAD - len(score_name) - 2), end="")
                    print(*score)
            print("Cleaned vector:       ", cvss_vector.clean_vector())
            print("Red Hat vector:       ", cvss_vector.rh_vector())
            if args.json:
                json_output = json.dumps(cvss_vector.as_json(sort=True, minimal=True), indent=2)
                print("CVSS vector in JSON:", json_output, sep="\n")
    except (KeyboardInterrupt, EOFError):
        print()


if __name__ == "__main__":
    main()
