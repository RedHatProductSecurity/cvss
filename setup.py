import codecs
from os import path

from setuptools import find_packages, setup

try:
    from collections import OrderedDict  # noqa
except ImportError:
    dependencies = ["ordereddict"]
else:
    dependencies = []

here = path.abspath(path.dirname(__file__))

with codecs.open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

with open("cvss/__init__.py") as f:
    for line in f:
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            version = line.split(delim)[1]
            break
    else:
        raise RuntimeError("Unable to find version string.")

setup(
    name="cvss",
    version=version,
    description="CVSS2/3/4 library with interactive calculator for Python 2 and Python 3",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/RedHatProductSecurity/cvss",
    project_urls={
        "Releases": "https://github.com/RedHatProductSecurity/cvss/releases",
        "Source code": "https://github.com/RedHatProductSecurity/cvss",
        "Issues": "https://github.com/RedHatProductSecurity/cvss/issues",
        "CI": "https://github.com/RedHatProductSecurity/cvss/actions",
    },
    author="Stanislav Kontar, Red Hat Product Security",
    author_email="skontar@redhat.com",
    license="LGPLv3+",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    keywords="security cvss score calculator",
    packages=find_packages(),
    install_requires=dependencies,
    tests_require=["jsonschema"],
    entry_points={
        "console_scripts": [
            "cvss_calculator = cvss.cvss_calculator:main",
        ],
    },
    # to make Python 2 and Python 3 compatible wheel
    options={"bdist_wheel": {"universal": "1"}},
)
