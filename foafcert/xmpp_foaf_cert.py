#!/usr/bin/python
# vim: set expandtab tabstop=4 shiftwidth=4:
# -*- coding: utf-8 -*-

# xmpp_foaf_cert <http://rhizomatik.net/>
# Python functions for generate a X509 client certificate for XMPP or HTTP
# FOAF+SSL authentication (including WebId and XMPP id at SubjectAltName).
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
xmpp_foaf_cert

Python functions for generate a X509 client certificate for XMPP or HTTP
 FOAF+SSL authentication (including WebId and XMPP id at SubjectAltName).

Usage: execute ./xmpp_foaf_cert -h

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

__app__ = "xmpp_foaf_cert"
__author__ = "duy"
__version__ = "0.1"
__copyright__ = "Copyright (c) 2009 duy"
__date__ = "2009/10/23"
__license__ = " GNU GPL version 3 or any later version (details at http://www.gnu.org)"
__credits__ = ""

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

"""
----> ca.key
----> ca-cert.pem ---> copy to /etc/jabberd2/ca-chain.pem

CA_CERT, CA_KEY ---> in settings.py 
"""

import os, time, base64, sys
from M2Crypto import X509, EVP, RSA, Rand, ASN1, m2, util, BIO

ID_ON_XMPPADDR_OID = "1.3.6.1.5.5.7.8.5"

def mkkeypair(bits):
    pk = EVP.PKey()
    rsa = RSA.gen_key(bits, 65537)
    pk.assign_rsa(rsa)
    print "Generated private RSA key:"
    # Print the new private key as a PEM-encoded (but unencrypted) string
    print rsa.as_pem(cipher=None)
    return pk

def mkreq_ca(bits=1024):
    """
    Create an x509 request
    @param bits: key bits lenght
    @type bits: int
    return x: x509 request
    return pk: private key
    """

    # create key pair (private only?)
    pk = mkkeypair(bits)

    # create x509 request
    x = X509.Request()

    # set public key
    x.set_pubkey(pk)

    x509_name = x.get_subject()
    # optional
    # set Subject commonName
    x509_name.CN = "CA Certificate Request"

#    # Create a new X509_Name object for our new certificate
#    x509_name=X509.X509_Name()
    x509_name.C = "CR"
    x509_name.O="Rhizomatik Labs"
    x509_name.OU="Mycelia project"
    x509_name.Email="ca@rhizomatik.net"

#    # Set the new cert subject
#    x.set_subject_name(x509_name.x509_name)


    # sign the x509 certificate request with private? key
    x.sign(pk,'sha1')
    
    print "Generated new CA req:"
    print x.as_pem()

    return x, pk


def mkreq_client(id_xmpp, webid, bits=1024):
    """
    Create an x509 request
    @param bits: key bits lenght
    @param id_xmpp: (optional) xmpp id
    @param webid: (optional) FOAF WebId
    @type bits: int
    @type id_xmpp: string
    @type webid: string
    return x: x509 request
    return pk: private? key
    """

    # create key pair (private only?)
    pk = mkkeypair(bits)

    # create x509 request
    x = X509.Request()

    # set public key
    x.set_pubkey(pk)

    x509_name = x.get_subject()

    # set Subject commonName
    x509_name.CN = webid + "/"+ ID_ON_XMPPADDR_OID + "=" + id_xmpp
#    name.CN = webid

    # if the req is going to be signed by a ca
    # there is not need to add CN because the ca cert is going to overwrite it
    # optional
#    # Create a new X509_Name object for our new certificate
#    x509_name=X509.X509_Name()
    x509_name.C = "CR"
    x509_name.O="Rhizomatik Labs"
    x509_name.OU="Mycelia project"
    x509_name.Email="ca@rhizomatik.net"

#    # Set the new cert subject
#    x.set_subject_name(x509_name.x509_name)

    # set subjectAltName extension
    ext1 = X509.new_extension('subjectAltName', 'URI:%s, otherName:%s;UTF8:%s' %(webid, ID_ON_XMPPADDR_OID, id_xmpp))
#    ext1 = X509.new_extension('subjectAltName', 'URI:%s' %webid)
    extstack = X509.X509_Extension_Stack()
    extstack.push(ext1)
    x.add_extensions(extstack)

    # sign the x509 certificate request with private? key
    x.sign(pk,'sha1')
    print "Generated new client req:"
    print x.as_pem()

    return x, pk

def set_valtime(cert):
    t = long(time.time()) + time.timezone
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    nowPlusYear = ASN1.ASN1_UTCTIME()
    nowPlusYear.set_time(t + 60 * 60 * 24 * 365)
#    return now, nowPlusYear
    cert.set_not_before(now)
    cert.set_not_after(nowPlusYear)

def set_serial(cert):
    serial=m2.asn1_integer_new()
    m2.asn1_integer_set(serial,20)
    m2.x509_set_serial_number(cert.x509,serial)
#    return cert

def mkcert_defaults(req):

    # create x509 certificate
    cert = X509.X509()
    # get public key from request
    pkey = req.get_pubkey()
    # set public key
    cert.set_pubkey(pkey) # pk if not req create

    # get subject from request
    x509_name = req.get_subject()
#    # Set the new cert subject
    cert.set_subject(x509_name) # the same as if a req subject was created

    # optional
#    cert.set_issuer_name(x509_name.x509_name)
    cert.set_issuer(x509_name)

    # set version
    cert.set_version(3)

    #@TODO: set a real serial number
#    cert.set_serial_number(1)
    set_serial(cert)

    # Set Cert validity time
#    now, nowPlusYear = mktime()
#    cert.set_not_before(now)
#    cert.set_not_after(nowPlusYear)
    set_valtime(cert)

    return cert

def mkcert_selfsigned(id_xmpp, webid):

    req, pk = mkreq_client(id_xmpp, webid)
    cert = mkcert_defaults(req)

    # the cert subject is the same as req subject
    # the issuer is going to be the same, ?

    # set subjectAltName extension
#    ext = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
    ext = X509.new_extension('subjectAltName', 'URI:%s, otherName:%s;UTF8:%s' %(webid, ID_ON_XMPPADDR_OID, id_xmpp))
#    ext = X509.new_extension('subjectAltName', 'URI:%s' %webid)
    ext.set_critical(0)
    cert.add_ext(ext)

    # sign the x509 certificate with private? key generated in the request
    cert.sign(pk, 'sha1')

    # Print the new certificate as a PEM-encoded string
    print cert.as_pem()

    print "Generated new self-signed client certificate:"
    print cert.as_pem()

    return cert, pk


def mkcert_casigned(id_xmpp, webid, req, cacert, capk):

    # the cert public key is the req public key
    cert = mkcert_defaults(req)

    # if certificate is going to be signed by a CA

    # this is not optional
    # set the certificate Issuer name as the CA subject name
#    issuer = X509.X509_Name()
#    issuer.C  = "CR"
#    issuer.CN = "Rhizomatik Labs"
#    cert.set_issuer(issuer)
    #cert.set_issuer_name(cacert.get_subject().x509_name)
#    cert.set_issuer_name(x509_name.x509_name)
    cert.set_issuer(cacert.get_subject())

    # set subjectAltName extension
#    ext = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
    ext = X509.new_extension('subjectAltName', 'URI:%s, otherName:%s;UTF8:%s' %(webid, ID_ON_XMPPADDR_OID, id_xmpp))
#    ext = X509.new_extension('subjectAltName', 'URI:%s' %webid)
    ext.set_critical(0)
    cert.add_ext(ext)

    # sign the x509 certificate with private? key generated in the request
    cert.sign(capk, 'sha1')

    # verify
    print "Client certificate verfication with CA certificate public key"
    print m2.x509_verify(cert.x509, m2.x509_get_pubkey(cacert.x509))

    # Print the new certificate as a PEM-encoded string
    print "Generated new client certificate signed with CA: "
    print cert.as_pem()
    return cert

def mkcacert():
    req, pk = mkreq_ca()
    cert = mkcert_defaults(req)

    # this is not optional
    # set the CA certificate Subject name
    # is allready assigned in mkcert_defaults
#    name = cert.get_subject()
#    name.C = "CR"
#    name.CN = "Rhizomatik Labs"

    # this is not optional
    # set the CA certificate Issuer name
    # is allready assigned in mkcert_defaults
#    issuer = X509.X509_Name()
#    issuer.C = "CR"
#    issuer.CN = "Rhizomatik Labs"
#    cert.set_issuer(issuer)

    # set basicConstraints extension
    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    cert.add_ext(ext)

    # sign the x509 CA certificate with private? key generated in the request
    cert.sign(pk, 'sha1')

    print "Generated new CA certificate:"
    # Print the new certificate as a PEM-encoded string
    print cert.as_pem()

    return cert, pk

def mkcacert_save(cacert_path='/tmp/xmpp_foaf_cacert.pem', 
        cakey_path='/tmp/xmpp_foaf_cakey.key'):
# create ca signed certificate
    # create ca cert
    cacert, capk = mkcacert()
    # save key without ask for password
    capk.save_key(cakey_path, None)
    cacert.save_pem(cacert_path)
    return cacert, capk

def get_cacert_cakey_from_file(cacert_path='/tmp/xmpp_foaf_cacert.pem', 
        cakey_path='/tmp/xmpp_foaf_cakey.key'):
    # with ca cert from file
    # Load the CA certificate and private key
    cacert=X509.load_cert(cacert_path)
    ca_priv_rsa=RSA.load_key(cakey_path)
    capk=EVP.PKey()
    capk.assign_rsa(ca_priv_rsa)
    return cacert, capk

def mkcert_selfsigned_save(cert_path='/tmp/xmpp_foaf_cert.pem', 
        key_path='/tmp/xmpp_foaf_key.key'):
    # create self-signed certificate
    cert, pk = mkcert_selfsigned(id_xmpp, webid)
    # save key without ask for password
    pk.save_key(key_path, None)
    cert.save_pem(cert_path)
    #R  = req.as_der()
    #from pyasn1.codec.der import decoder as asn1
    # a = asn1.decode(R)
    return cert, pk

def mkcert_casigned_from_file(id_xmpp, webid, 
        cacert_path='/tmp/xmpp_foaf_cacert.pem', 
        cakey_path='/tmp/xmpp_foaf_cakey.key'):
    # with recently generated ca cert
    cacert, capk = get_cacert_cakey_from_file(cacert_path, cakey_path)
    req, pk = mkreq_client(id_xmpp, webid)
    cert = mkcert_casigned(id_xmpp, webid, req, cacert, capk)
    return cert, pk

def mkcert_casigned_from_file_save(id_xmpp, webid, 
        cacert_path='/tmp/xmpp_foaf_cacert.pem', 
        cakey_path='/tmp/xmpp_foaf_cakey.key', 
        cert_path='/tmp/xmpp_foaf_cert.pem', 
        key_path='/tmp/xmpp_foaf_key.key'):
    # with recently generated ca cert
    cacert, capk = get_cacert_cakey_from_file(cacert_path, cakey_path)
    req, pk = mkreq_client(id_xmpp, webid)
    cert = mkcert_casigned(id_xmpp, webid, req, cacert, capk)
    cert.save_pem(cert_path)
    pk.save_key(key_path, None)
    return cert, pk

def pkcs12cert_from_file_save(cert_path='/tmp/xmpp_foaf_cert.pem', 
        key_path='/tmp/xmpp_foaf_cakey.key', 
        p12cert_path='/tmp/xmpp_foaf_cert.p12'):
    # Instantiate an SMIME object; set it up; sign the buffer.
    command = "openssl pkcs12 -export -in %s -inkey %s -out %s" % (cert_path, key_path, p12cert_path)
    os.system(command)
    return p12cert_path

def pkcs12cert(cert_path='/tmp/xmpp_foaf_cert.pem', 
        key_path='/tmp/xmpp_foaf_key.key', 
        p12cert_path='/tmp/xmpp_foaf_cert.p12'):
    """
    @TODO: create pkcs12 m2crypto function (http://osdir.com/ml/python.cryptography/2004-05/msg00001.html)
    """
    import OpenSSL
    pk = OpenSSL.crypto.load_privatekey(OpenSSL.SSL.FILETYPE_PEM, open(key_path).read())
    cert = OpenSSL.crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM, open(cert_path).read())
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_privatekey(pk)
    p12.set_certificate(cert)
    # @TODO: without key
    p12cert = open(p12cert_path,"w")
    p12cert.write(p12.export())
    p12cert.close()
    return p12cert_path

#def pkcs12cert(cert, capk, p12cert_path='/tmp/xmpp_foaf_cert.p12'):
#    import OpenSSL
#    pk = capk.as_pem()
#    cert = cert.as_pem()
#    p12 = OpenSSL.crypto.PKCS12()
#    p12.set_privatekey(pk)
#    p12.set_certificate(cert)
#    open(p12cert_path,"w").write(p12.export()) 

def pemcert(cert_path='/tmp/xmpp_foaf_cert.pem', 
        key_path='/tmp/xmpp_foaf_key.key',
        certkey_path='/tmp/xmpp_foaf_cert_key.pem'):
    """
    @TODO: check if possible to create with m2crypt
    """
    cert = open(cert_path)
    cert_data = cert.read()
    cert.close()
    key = open(key_path)
    cert_data += key.read()
    key.close()
    certkey = open(certkey_path, "w")
    certkey.write(cert_data)
    certkey.close()
    return certkey_path

def main(argv):
#    name = "henrystory"
#    webid = "http://bblfish.net/people/henry/card#me"
    id_xmpp = "duy@xmpp.rhizomatik.net"
    webid = "http://foafssl.rhizomatik.net/duy#me"
    
    mkcacert_save()
    get_cacert_cakey_from_file()
    mkcert_casigned_from_file_save(id_xmpp, webid)
    p12cert_path = pkcs12cert()
#    p12cert_path = pkcs12cert_from_file_save()
#    cert, capk = mkcert_casigned_from_file(id_xmpp, webid)
#    p12cert_path = pkcs12cert(cert, capk)

if __name__ == "__main__":
    main(sys.argv[1:])
