#!/usr/bin/env python3
#
# DANE openpgpkey implementation
#
import pytest,unittest
import dns
import dns,dns.resolver,dns.query,dns.zone,dns.message
import dbdns
import tempfile
from subprocess import Popen,PIPE,call

# Info on command line
# http://www.spywarewarrior.com/uiuc/gpg/gpg-com-4.htm#4-2c

smtp_server = "mail.nist.gov"
dns_resolver = "8.8.8.8"
signing_key_file = "/home/slg/.gnupg/nistsecretkey.asc"

my_email="simson.garfinkel@nist.gov"

email_template="""To: %TO%
From: %FROM%
Subject: This is a test %KIND% message

This is a test %KIND% message. Thanks for playing.
"""

def make_message(to=None,sender=None,kind=None,template=None):
    template = template.replace("%TO%",to)
    template = template.replace("%FROM%",sender)
    template = template.replace("%KIND%",kind)
    return template

from contextlib import contextmanager
@contextmanager
def make_file(buf):
    import tempfile
    """Returns the name of buf written into a file"""
    kfile = tempfile.NamedTemporaryFile(mode="wb+")
    kfile.write(buf)
    kfile.flush()
    yield kfile.name

def email_to_dns(email):
    """Given an email address, return the OPENPGPKEY encoding."""
    import hashlib
    (box,domain) = email.split("@")
    dns = hashlib.sha256(box.encode("utf-8")).hexdigest()[0:28*2] + "._openpgpkey." + domain
    if dns.endswith("."):
        dns = dns[:-1]
    return dns

def get_pubkey(T,email):
    """Returns the DNS cert for email"""
    import re,codecs
    msg = dbdns.query(T,email_to_dns(email), "TYPE61")

    # response.answer[0] is in wire format. 
    # I've been unable to parse it, so I convert it to RFC 3597-format text,
    # which I then parse. It's not that slow.

    r = re.compile(r"\\# (\d+) (.*)")
    data = msg.response.answer[0][0].to_text()
    m = r.search(data)
    if m:
        hexdata = codecs.decode(m.group(2).replace(" ",""),"hex")
        return hexdata


def import_key(tempdir,kfile):
    "Imports a key to the keyring in tempdir and returns the keyid"
    import re
    out = Popen(['gpg','--homedir',tempdir,'--import',kfile],stderr=PIPE).communicate()[1].decode('utf-8')
    m = re.search("gpg: key ([0-9A-F]+).*imported",out.replace("\n"," "))
    if m:
        return m.group(1)
    raise RuntimeError("No PGP key imported")
    

def print_pubkey(key):
    # Print GPG key
    tempdir = tempfile.mkdtemp()  # location for temporary keyfiles
    with make_file(key) as kfile:
        keyid = import_key(tempdir,kfile)
        call(['gpg','--batch','--homedir',tempdir,'--list-sigs',keyid])

def pgp_encrypt(msg,signing_key_file=None,encrypting_key=None):
    tempdir = tempfile.mkdtemp()
    if not signing_key_file and encrypting_key:
        with make_file(encrypting_key) as efile:
            keyid = import_key(tempdir,efile)
            cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'-a','-e','--recipient',keyid]
            p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
            res = p.communicate(msg.encode('utf-8'))[0]
            return res.decode('utf-8')
            
    if signing_key_file and not encrypting_key:
        cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'--import',signing_key_file]
        print(cmd)
        call(cmd)
        cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'-a','--clearsign']
        print(cmd)
        p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
        res = p.communicate(msg.encode('utf-8'))[0]
        return res.decode('utf-8')
            
    

class MyTest(unittest.TestCase):
    def test_openpgp(self):
        assert email_to_dns("hugh@example.com")== \
            "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com"




if __name__=="__main__":
    import argparse,sys
    from tester import Tester

    parser = argparse.ArgumentParser(description="smimea tester")
    parser.add_argument("--print",help="get and print a certificate for an email address")
    parser.add_argument("--send",help="send test emails email to an address")
    args = parser.parse_args()
    T = Tester(testname="dig")
    if args.print:
        key = get_pubkey(T,args.print)
        if key:
            print_pubkey(key)

    if args.send:
        key = get_pubkey(T,args.send)
        print("key:",key)
        if key:
            msg="Hello World\n"
            #res = pgp_encrypt(msg,signing_key=None,encrypting_key=key)
            res = pgp_encrypt(msg,signing_key_file=signing_key_file,encrypting_key=None)
            print("Resulting message:")
            print(res)

        exit(0)
        import smtplib
        s = smtplib.SMTP("mail.nist.gov")
        cert = get_cert(T,args.send)
        x509_cert = der_to_text(cert[3])
        signing_key = open(signing_cert_file,"r").read()
        signing_cert = open(signing_key_file,"r").read()
        s.sendmail(my_email,[args.send],smime_encrypt(make_message(to=args.send,sender=my_email,kind='signed',template=email_template),
                                       signing_key=signing_key,signing_cert=signing_cert ))
        s.sendmail(my_email,[args.send],smime_encrypt(make_message(to=args.send,sender=my_email,kind='encrypted',template=email_template),
                                        encrypting_cert=x509_cert))
        s.sendmail(my_email,[args.send],smime_encrypt(make_message(to=args.send,sender=my_email,kind='encrypted',template=email_template),
                            signing_key=signing_key,signing_cert=signing_cert,
                            encrypting_cert=x509_cert))
