import codecs
from os import path

from setuptools import setup, find_packages


try:
    from collections import OrderedDict
except ImportError:
    dependencies = ['ordereddict']
else:
    dependencies = []

here = path.abspath(path.dirname(__file__))

with codecs.open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='cvss',
    version='2.2',
    description='CVSS2/3 library with interactive calculator for Python 2 and Python 3',
    long_description=long_description,
    url='https://github.com/skontar/cvss',
    author='Stanislav Kontar, Red Hat Product Security',
    author_email='skontar@redhat.com',
    license='LGPLv3+',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='security cvss score calculator',
    packages=find_packages(),
    install_requires=dependencies,
    entry_points={
        'console_scripts': [
            'cvss_calculator = cvss.cvss_calculator:main',
        ],
    },
)
