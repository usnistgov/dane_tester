#!/usr/bin/env python3
#
# DANE smimea implementation
#
import pytest,unittest
import dns
import dns,dns.resolver,dns.query,dns.zone,dns.message
import dbdns
from subprocess import Popen,PIPE

smtp_server = "mail.nist.gov"
dns_resolver = "8.8.8.8"
#signing_key_file = "/home/slg/ca/smime.key"
#signing_cert_file = "/home/slg/ca/smime.crt"
SIGNING_KEY_FILE = "/home/slg/keystore/simson.garfinkel@nist.gov"
SIGNING_CERT_FILE = "/home/slg/keystore/simson.garfinkel@nist.gov"
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
    """Given an email address, return the SMIMEA encoding."""
    import hashlib
    (box,domain) = email.split("@")
    dns = hashlib.sha256(box.encode("utf-8")).hexdigest()[0:28*2] + "._smimecert." + domain
    if dns.endswith("."):
        dns = dns[:-1]
    return dns

def get_file(fname):
    return open(fname).read()

def get_cert_for_email(email):
    """Returns the DNS cert for email"""
    import re,codecs
    msg = dns.message.make_query(dns.name.from_text(email_to_dns(email)), "TYPE53")
    # Try UDP first
    response = dns.query.udp(msg,dns_resolver)
    if not response.answer:
        response = dns.query.tcp(msg,dns_resolver)
    if not response.answer:
        return None
    # response.answer[0] is in wire format. 
    # I've been unable to parse it, so I convert it to RFC 3597-format text,
    # which I then parse. It's not that slow.

    r = re.compile(r"\\# (\d+) (.*)")
    data = response.answer[0][0].to_text()
    m = r.search(data)
    if m:
        hexdata = codecs.decode(m.group(2).replace(" ",""),"hex")
        v0 = hexdata[0]
        v1 = hexdata[1]
        v2 = hexdata[2]
        der_encoded_cert = hexdata[3:]
        return(v0,v1,v2,der_encoded_cert)


def get_certdb(email):
    """Returns the DNS cert for email"""
    from tester import Tester
    T = Tester(testname="dig")
    import re,codecs
    msg = dbdns.query(T,email_to_dns(email), "TYPE53")
    # response.answer[0] is in wire format. 
    # I've been unable to parse it, so I convert it to RFC 3597-format text,
    # which I then parse. It's not that slow.

    r = re.compile(r"\\# (\d+) (.*)")
    data = msg.response.answer[0][0].to_text()
    m = r.search(data)
    if m:
        hexdata = codecs.decode(m.group(2).replace(" ",""),"hex")
        v0 = hexdata[0]
        v1 = hexdata[1]
        v2 = hexdata[2]
        der_encoded_cert = hexdata[3:]
        return(v0,v1,v2,der_encoded_cert)


def print_cert(cert):
    p = Popen(['openssl','x509','-inform','der','-text'],stdin=PIPE)
    p.stdin.write(cert)
    p.stdin.close()

def der_to_text(cert):
    p = Popen(['openssl','x509','-inform','der','-text'],stdin=PIPE,stdout=PIPE)
    #p.stdin.write(cert)
    return p.communicate(cert)[0]

def smime_crypto(msg,signing_key=None,signing_cert=None,
                  signing_addr=None,
                  encrypting_cert=None):
    from tempfile import NamedTemporaryFile
    import sys,email
    infile = NamedTemporaryFile(mode="w+")
    infile.write(msg)
    infile.flush()
    m = email.message_from_string(msg)

    cmd = ['openssl','smime','-in',infile.name]
    if signing_key:
        sk = NamedTemporaryFile(mode="w+")
        sk.write(signing_key)
        sk.flush()
        sc = NamedTemporaryFile(mode="w+")
        sc.write(signing_cert)
        sc.flush()

        cmd += ['-sign','-signer',sk.name,'-inkey',sk.name,'-certfile',sc.name]

    if encrypting_cert:
        ek = NamedTemporaryFile()
        ek.write(encrypting_cert)
        ek.flush()
        cmd += ['-encrypt','-aes256',ek.name]
        
    p = Popen(cmd,stdout=PIPE)
    m2 = email.message_from_string(p.communicate()[0].decode('utf-8'))
    for h in ['To','From','Subject']:
        m2[h] = m[h]
    return str(m2)
    

class MyTest(unittest.TestCase):
    def test_smimea(self):
        print(email_to_dns("hugh@example.com"))
        assert email_to_dns("slg@had-pilot.com")== \
            "77a3c94a8ebb95e36eb9682857da339d8ab09597d8e57eb1a4eb3f46._smimecert.had-pilot.com"


if __name__=="__main__":
    import argparse,sys

    parser = argparse.ArgumentParser(description="smimea tester")
    parser.add_argument("--print",help="get and print a certificate for an email address")
    parser.add_argument("--send",help="send test emails email to an address")
    args = parser.parse_args()
    if args.print:
        tname = args.print
        cert = get_certdb(tname)
        if cert:
            print("DANE Certificate Usage: {} {} {}".format(cert[0],cert[1],cert[2]))
            print_cert(cert[3])

    if args.send:
        import smtplib
        s = smtplib.SMTP("mail.nist.gov")
        cert = get_cert_for_email(args.send)
        x509_cert = der_to_text(cert[3])
        signing_key  = get_file(SIGNING_CERT_FILE)
        signing_cert = get_file(SIGNING_KEY_FILE)
        s.sendmail(my_email,[args.send],smime_crypto(make_message(to=args.send,sender=my_email,kind='signed',template=email_template),
                                       signing_key=signing_key,signing_cert=signing_cert ))
        s.sendmail(my_email,[args.send],smime_crypto(make_message(to=args.send,sender=my_email,kind='encrypted',template=email_template),
                                        encrypting_cert=x509_cert))
        s.sendmail(my_email,[args.send],smime_crypto(make_message(to=args.send,sender=my_email,kind='encrypted',template=email_template),
                            signing_key=signing_key,signing_cert=signing_cert,
                            encrypting_cert=x509_cert))
