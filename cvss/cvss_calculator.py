# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Computes CVSS2/3 score either supplied on command line or interactively. By default it only takes
mandatory metrics and computes CVSS3.1.
"""

from __future__ import print_function

import argparse

from cvss import CVSSError, ask_interactively


PAD = 24  # string padding for score names


def main():
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('-2', action='store_true', help='compute CVSS2 instead')
        parser.add_argument('-3', action='store_true', help='compute CVSS3.0 instead')
        parser.add_argument('-a', '--all', action='store_true', help='ask for all metrics')
        parser.add_argument('-v', '--vector', help='input string with CVSS vector')
        parser.add_argument('-n', '--no-colors', action='store_true',
                            help='do not use terminal coloring')
        args = parser.parse_args()

        # Import the correct CVSS module
        if getattr(args, '2'):
            version = 2
            from cvss import CVSS2 as CVSS
        else:
            if getattr(args, '3'):
                version = 3.0
            else:
                version = 3.1
            from cvss import CVSS3 as CVSS

        # Vector input, either from command line or interactively
        if args.vector:
            vector_string = args.vector
        else:
            vector_string = ask_interactively(version, args.all, args.no_colors)

        # Compute scores and clean vector
        try:
            cvss_vector = CVSS(vector_string)
        except CVSSError as e:
            print(e)
        else:
            scores = cvss_vector.scores()
            if version == 2:
                print('CVSS2')
                severities = None
            elif version >= 3.0:
                print('CVSS3')
                severities = cvss_vector.severities()
            else:
                raise ValueError('Unknown CVSS version: {0}'.format(version))

            for i, score_name in enumerate(['Base Score', 'Temporal Score', 'Environmental Score']):
                print(score_name + ':' + ' ' * (PAD - len(score_name) - 2), end='')

                if version >= 3.0:
                    print(scores[i], '({0})'.format(severities[i]))
                else:
                    print(scores[i])
            print('Cleaned vector:       ', cvss_vector.clean_vector())
            print('Red Hat vector:       ', cvss_vector.rh_vector())
    except (KeyboardInterrupt, EOFError):
        print()


if __name__ == '__main__':
    main()
