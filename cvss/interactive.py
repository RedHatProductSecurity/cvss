# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Functions for interactively building CVSS vector string.

Compatible with both Python 2 and Python 3.
"""

from __future__ import print_function, unicode_literals


try:
    # noinspection PyUnresolvedReferences
    string_input = raw_input
except NameError:
    string_input = input


def color(text):
    """
    Replaces text in brackets with yellow bold variant for terminal. Also replaces | symbol with
    blue one. Should improve readability. Uses ANSI Styling codes.
    """
    colored = text.replace('(', '\033[33m\033[1m').replace(')', '\033[0m')
    colored = colored.replace('|', '\033[94m\033[1m|\033[0m')
    return colored


def ask_interactively(version=3.1, all_metrics=False, no_colors=False):
    """
    Asks user to build CVSS vector string interactively.

    Args:
        version (float): 2 or 3.0/3.1 for CVSS2 or CVSS3 respectively
        all_metrics (bool): If true, temporal and environmental metrics are asked, else only base
                            metrics are asked for
        no_colors (bool): If true, terminal coloring is not used in interactive mode

    Returns:
        (str): CVSS vector
    """
    # Import correct constants
    if version == 2:
        print('Interactive CVSS2 calculator')
        from .constants2 import METRICS_ABBREVIATIONS, METRICS_MANDATORY, METRICS_VALUE_NAMES
    elif version >= 3.0:
        print('Interactive CVSS3 calculator')
        from .constants3 import METRICS_ABBREVIATIONS, METRICS_MANDATORY, METRICS_VALUE_NAMES
    else:
        raise ValueError('Unknown version: {0}'.format(version))
    print()

    vector = []

    if all_metrics:
        metrics = METRICS_ABBREVIATIONS.keys()
    else:
        metrics = METRICS_MANDATORY

    for metric in metrics:
        # Print full metric name
        print(METRICS_ABBREVIATIONS[metric] + ':', end=' ')

        # Create metric value names with hints
        values = METRICS_VALUE_NAMES[metric]
        value_names = []
        for value in values:
            name = METRICS_VALUE_NAMES[metric][value]
            name_with_hints = name
            for letter in value:
                name_with_hints = name_with_hints.replace(letter, '(' + letter + ')')

            # Exceptions for hints
            if version >= 3.0 and name_with_hints == 'Not Defined':
                name_with_hints = '(X)Not Defined'
            elif version < 3.0:
                name_with_hints = {
                    '(P)roof-of-(C)oncept': '(P)roof-(O)f-(C)oncept',
                    '(U)nconfirmed': '(U)n(C)onfirmed',
                    '(U)ncorroborated': '(U)nco(R)roborated',
                }.get(name_with_hints, name_with_hints)

            value_names.append(name_with_hints)

        # Print value names with hints
        value_names_string = ' | '.join(value_names)
        if no_colors:
            print(value_names_string)
        else:
            print(color(value_names_string))

        # Ask for input
        while True:
            print(METRICS_ABBREVIATIONS[metric] + ':', end=' ')
            print('/'.join(values), end=' ')
            input_value = string_input().upper()
            if not input_value:
                if version == 2:
                    input_value = 'ND'
                else:
                    input_value = 'X'
            if input_value in values:
                vector.append(metric + ':' + input_value)
                break
        print()

    if version == 3.0:
        vector_string = 'CVSS:3.0/' + '/'.join(vector)
    elif version == 3.1:
        vector_string = 'CVSS:3.1/' + '/'.join(vector)
    else:
        vector_string = '/'.join(vector)
    return vector_string
