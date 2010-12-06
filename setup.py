#!/usr/bin/env python
# -*- coding: utf-8 -*-

#from distutils.core import setup
import sys
try:
    from setuptools import setup, find_packages
except ImportError:
    sys.stderr.write("setuptools must be installed")
    sys.exit(1)
from sys import version

setup(
    name='python-foafcert',
    version=version,
    description='Python utils to generate a X509 client certificate for XMPP or HTTP  FOAF+SSL authentication (including WebId and XMPP id at SubjectAltName).',
    author='duy',
    author_email='duy at rhizomatik dot net',
    url='http://git.rhizomatik.net/?p=python-foafcert',
    download_url='git://git.rhizomatik.net/python-foafcert',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    keywords = 'python foaf ssl certificate X509 PKCS12',
    license = 'GPL',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GPL License',
        'Operating System :: OS Independent',
        'Programming Language :: Python'
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)

