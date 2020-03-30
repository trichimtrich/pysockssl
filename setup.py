#!/usr/bin/env python3
# coding: utf-8

import os
from setuptools import setup, find_packages

from sockssl.__init__ import __version__


# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

# read the package requirements for install_requires
with open(os.path.join(here, 'requirements.txt'), 'r') as f:
    requirements = f.readlines()

# setup!
setup(
    name='pysockssl',
    description='Simple TCP/TLS mitm engine supports SOCKSv4 + SOCKSv5 + Cert store',
    license='GPL v3',

    author='trichimtrich',
    author_email='trichimtrich@gmail.com',

    long_description=long_description,
    long_description_content_type="text/markdown",

    url='https://github.com/trichimtrich/pysockssl',

    keywords=['mitm', 'proxy', 'ssl', 'tls', 'socksv4', 'socksv5', 'socks4', 'socks5'],
    version=__version__,

    # include other files
    package_data={},
    packages=find_packages(),
    install_requires=requirements,
    python_requires='>=3.5',
    classifiers=[
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
    ],
    entry_points={
        'console_scripts': [
            'sockssl=sockssl.cli:cli',
        ],
    },
)