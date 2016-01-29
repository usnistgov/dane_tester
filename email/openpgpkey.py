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

smtp_server = "mail.nist.gov"
dns_resolver = "8.8.8.8"
#signing_key_file = "/home/slg/ca/smime.key"
#signing_cert_file = "/home/slg/ca/smime.crt"
signing_key_file = "/home/slg/ca/smime.2"
signing_cert_file = "/home/slg/ca/smime.2"
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


def print_pubkey(key):
    # Print GPG key
    dname = tempfile.mkdtemp()  # locateion for temporary keyfiles
    kname = tempfile.NamedTemporaryFile(mode="wb+",dir=dname)
    kname.write(key)
    kname.flush()

    import re
    
    out = Popen(['gpg','--homedir',dname,'--import',kname.name],stderr=PIPE).communicate()[1].decode('utf-8')
    m = re.search("gpg: key ([0-9A-F]+).*imported",out.replace("\n"," "))
    if m:
        keyid = m.group(1)
        call(['gpg','--homedir',dname,'--list-sigs',keyid])

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
        tname = args.print
        key = get_pubkey(T,tname)
        if key:
            print_pubkey(key)

    if args.send:
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
