CVSS
====

This Python package contains CVSS v2, v3 and v4 computation utilities and
interactive calculator (for v2 and v3 only) compatible with both Python 2 and Python 3.

The library is tested on all currently-supported Python versions available
via GitHub Actions (with the exception of Python 2.7, which is EOL but
still tested against), but it is simple enough to run on even older versions.

Installation
------------

::

    # pip install cvss

Usage
-----

Library
~~~~~~~

.. code-block:: python

    from cvss import CVSS2, CVSS3, CVSS4


    vector = 'AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M'
    c = CVSS2(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())

    print()

    vector = 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'
    c = CVSS3(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

    print()

    vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'
    c = CVSS4(vector)
    print(vector)
    print(c.base_score)
    print(c.severity)

Sample output:

::

   AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M
   AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/CDP:L/TD:H/AR:M
   (5.0, 4.0, 4.6)

   CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X
   CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L
   (6.5, 6.0, 5.3)
   ('Medium', 'Medium', 'Medium')

   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
   9.9
   Critical

Interactive calculator
~~~~~~~~~~~~~~~~~~~~~~

For interactive calculator run the following:

::

    $ cvss_calculator

For help on the calculator options run:

::

    $ cvss_calculator --help

Testing
-------

For extensive testing, the test vectors were generated using official
JavaScript generators and `cvsslib <https://github.com/ctxis/cvsslib>`_.

To run all tests using all supported versions of Python 2 and Python 3 installed:

::

    $ tox
    $ tox -e py311   # Run tests using a specific version of Python
