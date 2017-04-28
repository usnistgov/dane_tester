#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
import sys
assert sys.version > '3'

#import cgitb;cgitb.enable()
from mako.template import Template
from tester import Tester
import dbmaint
import tester
import cgi
from subprocess import Popen,PIPE,STDOUT
import re,base64,hashlib,os
import html 

# Force output to be encoded in UTF8
# http://stackoverflow.com/questions/14860034/python-cgi-utf-8-doesnt-work
import codecs; sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

os.environ['GNUPGHOME'] = '/var/www/gpg'

#
# Create a GPG public key record
# See https://tools.ietf.org/html/rfc7929

openssl_exe = '/usr/bin/openssl'
gpg_exe = '/usr/bin/gpg'

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }
    
def def html_escape(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c,c) for c in text)


def hexdump(s, separator=''):
    if type(s)==str:
        return separator.join("{:02X}".format(ord(x)) for x in s)
    if type(s)==bytes:
        return separator.join("{:02X}".format(x) for x in s)
    if type(s)==memoryview:
        return separator.join("{:02X}".format(x) for x in bytes(s))
    raise RuntimeError("Unknown type for hexdump: {}".format(type(s)))

def gen_pgp_rr(email,pgpKey):
    """Given an email address and a pgpKey that's ASCII armored, turn it into RRs"""
    #
    # Import the key
    #
    (stdout,stderr) = Popen([gpg_exe, '--import'],stdin=PIPE,stdout=PIPE,stderr=PIPE).communicate(pgpKey.encode('utf-8'))
    keyfind = re.compile("key ([0-9A-F]{8})")
    stderr_out = stderr.decode('utf-8')
    m = keyfind.search(stderr.decode('utf-8'))
    if not m:
        return "Error: Key Format Invalid (error: {})".format(str(stderr))
    if email not in stderr_out:
        return "Error: Key '{}' not in public key".format(email)

    #
    # Export the key according to the spec
    # See https://tools.ietf.org/html/rfc7929
    #
    (stdout,stderr) = Popen([gpg_exe, '--export','--export-options','export-minimal,no-export-attributes',email],
                            stdin=PIPE,stdout=PIPE,stderr=PIPE).communicate()
    keyblob_base64 = base64.b64encode(stdout)
    if stderr:
        return "Error: Export failed (error: {})".format(str(stderr))

    (emailpart,domainpart) = email.split('@')
    hasher = hashlib.sha256()
    hasher.update(emailpart.encode('ascii'))
    hexpart = hasher.hexdigest()[0:28]
    return "{}._openpgpkey.{}. IN OPENPGPKEY {}\n".format(hexpart,domainpart,keyblob_base64.decode('ascii')) + \
        "{}._openpgpkey.{}. IN TYPE61 \# {} {}".format(hexpart,domainpart,len(keyblob_base64),hexdump(keyblob_base64))
   

def gen_smimea_rr(usage,selector,match,email,cert):
    if usage==0: return "Error: CA Constraint currently not implemented"
    if usage==1: return "Error: Service Certificate Constraint currently not implemented"
    if usage==2: return "Error: Trust anchor assertion currently not implemented"
    
    (cert_data ,stderr) = Popen([openssl_exe,'x509','-inform','der','-outform','der'],stdin=PIPE,stdout=PIPE,stderr=PIPE).communicate(cert)
    if stderr:
        return "Error: Key in invalid format ({})".format(stderr)
        
    if selector==1:             # Just the public key
        (pubkey_pem,pubkey_err) = Popen([openssl_exe,'x509','-pubkey','-inform','der'],stdin=PIPE,stdout=PIPE,stderr=PIPE).\
                                  communicate(cert_data )
        (pubkey_der,pubkey_err) = Popen([openssl_exe,'rsa','-inform','pem','-pubin','-outform','der'],stdin=PIPE,stdout=PIPE,stderr=PIPE).\
                                  communicate(pubkey_pem)
        cert_data  = pubkey_der

    comp_data = cert_data
    # Compute the matches
    if match == 0:
        print("aa",file=sys.stderr)
        comp_data = cert_data       # tlsa_rr contains the actual certificate
    if match == 1:
        print("bb",file=sys.stderr)
        comp_data = hashlib.sha256(cert_data).digest()
    if match == 2:
        print("bb",file=sys.stderr)
        comp_data = hashlib.sha512(cert_data).digest()

    (emailpart,domainpart) = email.split('@')
    hasher = hashlib.sha256()
    hasher.update(emailpart.encode('ascii'))
    hexpart = hasher.hexdigest()[0:28]
    ret = "{}._smimecert.{}. TLSA {} {} {} {}".format(hexpart,domainpart,usage,selector,match,hexdump(comp_data))
    print("ret=",ret,file=sys.stderr)
    return ret
    

if __name__=="__main__":
    import os

    if "SCRIPT_FILENAME" not in os.environ:
        print("*** LOCAL TESTING MODE ***")
        if len(sys.argv)==3:
            res = gen_smimea_rr(3,0,0,sys.argv[1],open(sys.argv[2],"rb").read())
            print('res=',res)
            exit(0)

        print("Enter email:"); sys.stdout.flush()
        email = sys.stdin.readline()
        print("Enter PGP key:"); sys.stdout.flush()
        pgpKey = ""
        while True:
            line = sys.stdin.readline()
            if not line: break
            pgpKey += line
        email = email.strip()
        pgpKey = pgpKey.strip() + "\n"
        print(gen_pgp_rr(email,pgpKey))
        exit(0)

    print("Content-Type: text/html")    # HTML is following
    print()                             # blank line, end of headers
    import cgitb; cgitb.enable()
    form = cgi.FieldStorage()
    
    if 'mode' not in form:
        print("No key type specified")
        exit(0)

    res = "Error: Unknown key type '{}'".format(form['mode'].value)
    if form['mode'].value=='SMIMEA':
        # File upload; must be the PGP
        usage = form["usage"].value if "usage" in form else "XXX"
        selector = form["selector"].value if "selector" in form else "XXX"
        match = form["match"].value if "match" in form else "XXX"
        email = form["email"].value if "email" in form else "XXX"
        cert = form['cert'].file.read()
        res = gen_smimea_rr(usage,selector,match,email,cert)

    if form['mode'].value=='OPENPGPKEY':
        if 'email' not in form:
            print("Please provide an email address")
            exit(0)

        if 'pgpKey' not in form:
            print("Please provide a Pgp Public Key address")
            exit(0)

        email   = form['email'].value.strip()
        pgpKey  = form['pgpKey'].value.strip() + "\n"
        res     = gen_pgp_rr(email,pgpKey)

    lines = res.split("\n")
    if not res.startswith("Error"):
        if len(lines)>1:
            print("<p><i>Add one of these records to your DNS:</i></p>")
        else:
            print("<p><i>Add this record to your DNS:</i></p>")
    for line in lines:
        print("<pre>\n{}\n</pre>\n".format(line))
    exit(0)


