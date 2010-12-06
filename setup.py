#!/usr/bin/env python

#from distutils.core import setup
from setuptools import setup, find_packages

setup(
    name='python-foafcert',
    version='0.1',
    description='Python functions for generate a X509 client certificate for XMPP or HTTP  FOAF+SSL authentication (including WebId and XMPP id at SubjectAltName).',
    author='duy',
    author_email='duy@rhizomatik.net',
    url='https://rhizomatik.net/myceliafoafssl/wiki/XmppFoafSSL',
    download_url='git://git.rhizomatik.net/python-foafcert',
    packages=find_packages(),
    include_package_data=True,

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

