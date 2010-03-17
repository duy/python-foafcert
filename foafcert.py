#!/usr/bin/python
#!/usr/bin/python
# vim: set expandtab tabstop=4 shiftwidth=4:
# -*- coding: utf-8 -*-

# foafcert <http://rhizomatik.net/>
# Python wrapper for Sesame's REST HTTP API
#
# Copyright (C) 2009 duy at rhizomatik dot net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
"""
foafcert

Python functions for generate a X509 certificate for FOAF+SSL authentication
 (including WebId at SubjectAltName)

Usage: execute ./foafcert -h

@author:       duy
@organization: rhizomatik labs
@copyright:    author 
@license:      GNU GPL version 3 or any later version 
                (details at http://www.gnu.org)
@contact:      duy at rhizomatik dot net
@dependencies: python (>= version 2.4.5)
@change log:
@TODO: implement with pyOpenSSL or M2Crypto
"""

__app__ = "foafcert"
__author__ = "duy"
__version__ = "0.1"
__copyright__ = "Copyright (c) 2009 duy"
__date__ = "2009/10/23"
__license__ = " GNU GPL version 3 or any later version (details at http://www.gnu.org)"
__credits__ = ""

import sys
## ----------------------------------------------------------------------
## administrative functions
## ----------------------------------------------------------------------

def _usage():
    print "Usage: %s " % __app__
    print """
Options:
  -h, --help      Print this usage message.
  -d,             debug
"""

def _version():
    """
    Display a formatted version string for the module
    """
    print """%(__app__)s %(__version__)s
%(__copyright__)s
released %(__date__)s

Thanks to:
%(__credits__)s""" % globals()


import tempfile
import sys
import os
from string import Template

def create_openssl(name, webid, openssl_file_name):
    openssl_file = open(openssl_file_name, "r")
    openssl_template_data = openssl_file.read()
    openssl_file.close()
    openssl_data = Template(openssl_template_data)
    openssl_data = openssl_data.substitute(name = name, webid = webid)
    openssl_custom_file = open(name+openssl_file_name, "w")
    openssl_custom_file.write(openssl_data)
    openssl_custom_file.close()

def generate_cert_x509(openssl_custom_file_name, name):
    command = "openssl req -x509 -nodes -newkey rsa:1024 -config %s -out %s_cert.pem" % (openssl_custom_file_name, name)
    output = os.system(command)
    return output

def export_pkcs12(name):
    command = "openssl pkcs12 -export -in %s_cert.pem -inkey %s_privatekey.pem -out %s_cert.p12" % (name, name, name)
    output = os.system(command)
    return output




def main(argv):
#    tmpSPKACfname, tmpCERTfname, SAN = create_identity_x509(foafLocation="http://bblfish.net/people/henry/card#me", 
#        commonName="Henry Story", pubkey="password")
    name = "henrystory"
    webid = "http://bblfish.net/people/henry/card#me"
    openssl_file_name = "openssl-foaf.cnf"
    create_openssl(name, webid, openssl_file_name)
    generate_cert_x509(name+openssl_file_name, name)
    export_pkcs12(name)



if __name__ == "__main__":
    main(sys.argv[1:])
