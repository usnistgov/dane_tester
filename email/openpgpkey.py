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
from mako.template import Template

# Info on command line
# http://www.spywarewarrior.com/uiuc/gpg/gpg-com-4.htm#4-2c

smtp_server = "mail.nist.gov"
dns_resolver = "8.8.8.8"
SIGNING_KEY_FILE = "/home/slg/keystore/nistsecretkey.asc"

my_email="simson.garfinkel@nist.gov"

email_template="""To: %TO%
Subject: This is a test %KIND% message
From: %FROM%

This is a test %KIND% message. Thanks for playing.
"""

class DebugSendmail:
    def sendmail(self,from_,to,msg):
        print("MAIL FROM: {}".format(from_))
        print("TO: {}".format(" ".join(to)))
        print("MESSAGE:")
        print(msg)
        print("="*80)
        print("="*80)
        print("="*80)

def make_message(to=None,sender=None,kind=None,template=None):
    template = template.replace("%TO%",to)
    template = template.replace("%FROM%",sender)
    template = template.replace("%KIND%",kind)
    return template

#def make_message(to=None,sender=None,kind=None,template=None):
#    t = Template(text=template)
#    return t.render(**{'to':to,
#                     'from':sender,
#                     'kind':kind})

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
    try:
        msg = dbdns.query(T,email_to_dns(email), "TYPE61")
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.Timeout:
        return None


    # response.answer[0] is in wire format. 
    # I've been unable to parse it, so I convert it to RFC 3597-format text,
    # which I then parse. It's not that slow.

    data = msg.response.answer[0][0].to_text()
    r = re.compile(r"\\# (\d+) (.*)")
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
    

def pubkey_to_txt(key):
    # Print GPG key
    tempdir = tempfile.mkdtemp()  # location for temporary keyfiles
    with make_file(key) as kfile:
        keyid = import_key(tempdir,kfile)
        msg  = Popen(['gpg','--batch','--homedir',tempdir,'--list-sigs',keyid],stdout=PIPE).communicate()[0].decode('utf-8')
        msg += Popen(['gpg','--batch','--homedir',tempdir,'-a','--export',keyid],stdout=PIPE).communicate()[0].decode('utf-8')
        return msg

def pgp_process1(msg,signing_key_file=None,encrypting_key=None):
    tempdir = tempfile.mkdtemp()

    # If we are signing, need to import the key into the signing_key_file
    if signing_key_file:
        # Import the key into the temporary keychain
        cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'--import',signing_key_file]
        call(cmd)

    # If we are encrypting, need to import the encrypting key
    if encrypting_key:
        with make_file(encrypting_key) as encrypting_key_file:
            encrypting_keyid = import_key(tempdir,encrypting_key_file)

            if signing_key_file:
                cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'--armor','--sign','--encrypt','--recipient',encrypting_keyid]
            else:
                cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'--armor','--encrypt','--recipient',encrypting_keyid]
            p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
            (res,res_error) = p.communicate(msg.encode('utf-8'))
            if res_error:
                raise RuntimeError(res_error.encode('utf-8'))
            return res.decode('utf-8')
                
    # Only signing
    # Use the temporary keychain to sign the message
    cmd = ['gpg','--batch','--trust-model','always','--homedir',tempdir,'--armor','--clearsign']
    p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
    (res,res_error) = p.communicate(msg.encode('utf-8'))
    if res_error:
        raise RuntimeError(res_error.encode('utf-8'))
    return res.decode('utf-8') # return the result
            
    
def pgp_process(msg,signing_key_file=None,encrypting_key=None):
    import email
    e = email.message_from_string(msg)
    e.set_payload(pgp_process1(e.get_payload(),signing_key_file=signing_key_file,encrypting_key=encrypting_key))
    return(e.as_string())


def openpgpkey_to_txt(T,email):
    key = get_pubkey(T,email)
    if key:
        return pubkey_to_txt(key)
    else:
        return ""

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
    parser.add_argument("--debug",help="print the test email messages, but don't send them",action='store_true')
    parser.add_argument("--smtpdebug",help="enable SMTP debugging",action='store_true')
    args = parser.parse_args()
    T = Tester()
    T.newtest(testname="dig")
    if args.print:
        print(openpgpkey_to_txt(T,args.print))

    if args.send:
        encrypting_key = get_pubkey(T,args.send)
        if not encrypting_key:
            print("Cannot find key for {}".format(args.send))
            exit(1)
            
        import smtplib
        if args.debug:
            s = DebugSendmail()
        else:
            s = smtplib.SMTP("mail.nist.gov")
            if args.smtpdebug:
                s.set_debuglevel(True)
        s.sendmail(my_email,[args.send],pgp_process(make_message(to=args.send,sender=my_email,kind='signed',template=email_template),
                                                    signing_key_file=SIGNING_KEY_FILE))
        s.sendmail(my_email,[args.send],pgp_process(make_message(to=args.send,sender=my_email,kind='encrypted',template=email_template),
                                                    encrypting_key=encrypting_key))
        s.sendmail(my_email,[args.send],pgp_process(make_message(to=args.send,sender=my_email,kind='encrypted',template=email_template),
                                                    signing_key_file=SIGNING_KEY_FILE,
                                                    encrypting_key=encrypting_key))
