#!/bin/bash -x

export PYTHONPATH=".."

python3 test_cvss2.py
python3 test_cvss3.py

python2 test_cvss3.py
python2 test_cvss2.py
