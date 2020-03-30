#!/usr/bin/env python3
# coding: utf-8

import os
from setuptools import setup, find_packages

from sockssl.__init__ import __version__


# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# read the package requirements for install_requires
with open(os.path.join(here, 'requirements.txt'), 'r') as f:
    requirements = f.readlines()

# setup!
setup(
    name='pysockssl',
    description='mitm engine with socks4 + socks5 server and TLS cert store',
    license='GPL v3',

    author='trichimtrich',
    author_email='trichimtrich@gmail.com',

    url='https://github.com/trichimtrich/pysockssl',
    download_url='https://github.com/trichimtrich/pysockssl/archive/' + __version__ + '.tar.gz',

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