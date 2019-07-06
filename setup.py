#!/usr/bin/env python3

# ./setup.py sdist bdist_wheel

from setuptools import setup
from gridmeld import __version__

with open('README.rst') as f:
    long_description = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='gridmeld',
    version=__version__,
    author='Palo Alto Networks, Inc.',
    author_email='techbizdev@paloaltonetworks.com',
    description='Cisco ISE pxGrid to ' +
    'Palo Alto Networks MineMeld Gateway',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    url='https://github.com/PaloAltoNetworks/gridmeld',
    install_requires=requirements,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: Apache Software License',
    ],
    packages=[
        'gridmeld',
        'gridmeld/pxgrid',
        'gridmeld/util',
        'gridmeld/minemeld',
    ],
    scripts=[
        'bin/grid.py',
        'bin/meld.py',
        'bin/gate.py',
    ],
)
