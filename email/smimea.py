#!/usr/bin/env python3
#
# DANE smimea implementation
#
import pytest
import dns
import dns,dns.resolver,dns.query,dns.zone,dns.message
import dbdns
from subprocess import Popen,PIPE

smtp_server = "mail.nist.gov"
dns_resolver = "8.8.8.8"
signing_key_file = "/home/slg/ca/smime.key"
signing_cert_file = "/home/slg/ca/smime.crt"
my_email="simson.garfinkel@nist.gov"

email_template="""To: %TO%
From: %FROM%
Subject: This is a test message

This is a test. Thanks for playing.
"""

def make_message(msg_to,msg_from,template):
    template = template.replace("%TO%",msg_to)
    template = template.replace("%FROM%",msg_from)
    return template

def email_to_dns(email):
    """Given an email address, return the SMIMEA encoding."""
    import hashlib
    (box,domain) = email.split("@")
    dns = hashlib.sha256(box.encode("utf-8")).hexdigest()[0:28*2] + "._smimecert." + domain
    if not dns.endswith("."):
        dns += "."
    return dns

def get_cert(email):
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


def smimea_test():
    assert email_to_dns("slg@had-pilot.com")== \
        "77a3c94a8ebb95e36eb9682857da339d8ab09597d8e57eb1a4eb3f46._smimecert.had-pilot.com."

def print_cert(cert):
    p = Popen(['openssl','x509','-inform','der','-text'],stdin=PIPE)
    p.stdin.write(cert)
    p.stdin.close()

def smime_encrypt(msg,signing_key=None,signing_addr=None,
                  encrypting_key=None,encrypting_addr=None):
    from tempfile import TemporaryFIle
    cmd = ['openssl','smime']
    if signing_key:
        t = TemporaryFile()
        t.write(signing_key)
        t.flush()
        cmd += ['-sign',t.name]
    if encrypting_key:
        t = TemporaryFile()
        t.write(signing_key)
        t.flush()
        
    p = Popen(cmd,stdout=PIPE)
    return p.communicate()[0]
    

if __name__=="__main__":
    import argparse

    parser = argparse.ArgumentParser(description="smimea tester")
    parser.add_argument("--print",help="get and print a certificate for an email address")
    parser.add_argument("--send",help="send a signed email to an address")
    args = parser.parse_args()
    if args.print:
        tname = args.print
        cert = get_certdb(tname)
        if cert:
            print("DANE Certificate Usage: {} {} {}".format(cert[0],cert[1],cert[2]))
            print_cert(cert[3])

    if args.send:
        cert = get_cert(args.send)
        msg = make_message(args.send,my_email,email_template)
        print("signed:")
        signing_key = open(signing_key_file,"r").read()
        print(smime_encrypt(msg,signing_key=signing_key))
        print("encrypted:")
        print(smime_encrypt(msg,encrypting_cert=cert))
        print("signed and encrypted:")
        print(smime_encrypt(msg,signing_key=signing_key,encrypting_cert=cert))
