#!/usr/bin/env python

from distutils.core import setup

setup(
    name='python-foafcert',
    version=_'0.1'
    description='Python functions for generate a X509 certificate for FOAF+SSL authentication  (including WebId at SubjectAltName).',
    author='duy',
    author_email='duy@rhizomatik.net',
    url='http://git.rhizomatik.net/?p=python-foafcert',
#      download_url="http://pypy.rhizomatik.net/sesamerestclient-0.0.tar.gz",
      py_modules=['foafcert'],
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
    ]
    install_requires = ['httplib', 'urllib', 'urlib2'],
)

