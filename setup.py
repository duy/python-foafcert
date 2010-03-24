#!/usr/bin/env python

from distutils.core import setup

setup(
    name='python-foafcert',
    version='0.1',
    description='Python functions for generate a X509 client certificate for XMPP or HTTP  FOAF+SSL authentication (including WebId and XMPP id at SubjectAltName).',
    author='duy',
    author_email='duy@rhizomatik.net',
    url='http://git.rhizomatik.net/?p=python-foafcert',
#      download_url="http://pypy.rhizomatik.net/sesamerestclient-0.0.tar.gz",
#    py_modules=['foafcert'],
#    data_files=[('conf', ['openssl-foaf.cnf',]),],
#    package_data={'': ['data/openssl-foaf.cnf']},
    packages=['foafcert'],
    package_dir={'foafcert': 'foafcert'},
    package_data={'foafcert': ['data/openssl-foaf.cnf']},

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
    requires = ['m2crypto'],
)

