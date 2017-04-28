#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# NIST-developed software is provided by NIST as a public service. You
# may use, copy and distribute copies of the software in any medium,
# provided that you keep intact this entire notice. You may improve,
# modify and create derivative works of the software or any portion of
# the software, and you may copy and distribute such modifications or
# works. Modified works should carry a notice stating that you changed
# the software and should note the date and nature of any such
# change. Please explicitly acknowledge the National
# Institute of Standards and Technology as the source of the software.

# NIST-developed software is expressly provided “AS IS.” NIST MAKES NO
# WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY
# OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
# NON-INFRINGEMENT AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR
# WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR
# ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT
# WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE
# SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE
# CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

# You are solely responsible for determining the appropriateness of
# using and distributing the software and you assume all risks
# associated with its use, including but not limited to the risks and
# costs of program errors, compliance with applicable laws, damage to
# or loss of data, programs or equipment, and the unavailability or
# interruption of operation. This software is not intended to be used
# in any situation where a failure could cause risk of injury or
# damage to property. The software developed by NIST employees is not
# subject to copyright protection within the United States.

import sys; assert sys.version > '3'

import pytest
import os,os.path
import subprocess
from subprocess import Popen,call,PIPE


sys.path.append("../email")     # bring in the dbdns libraries
import dbdns


MAX_CNAME_DEPTH=20
MAX_TIMEOUT=30
VERSION=1.0

INFO="INFO"
WARNING="WARNING"
PROGRESS="PROGRESS"

# From RFC 6698
cert_usage_str = {0:"CA constraint",
                  1:"Service certificate constraint",
                  2:"Trust anchor assertion",
                  3:"Domain-issued certificate"}

selector_str = {0:"Full certificate",
                1:"SubjectPublicKeyInfo"}

mtype_str = {0:"No hash used",
             1:"SHA-256",
             2:"SHA-512"}



################################################################
## 
## OpenSSL Gateway
##
################################################################


GET_ALTNAMES_EXE = './get_altnames'
OPENSSL_EXE = 'openssl' 
OPENSSL_CAFILE = 'ca-bundle.crt'
BEGIN_PEM_CERTIFICATE="-----BEGIN CERTIFICATE-----"
END_PEM_CERTIFICATE="-----END CERTIFICATE-----"


# See if a better openssl exists; remove OpenSSL defaults
if os.path.exists("/usr/local/ssl/bin/openssl"):
    OPENSSL_EXE = "/usr/local/ssl/bin/openssl"
os.environ["SSL_CERT_DIR"]="/nonexistant"
os.environ["SSL_CERT_FILE"]="/nonexistant"

def verify_package():
    """Returns True if package is properly installed"""
    return os.path.exists(GET_ALTNAMES_EXE) and os.path.exists(OPENSSL_EXE)

def openssl_debug():
    return "OPENSSL_DEBUG" in os.environ

def openssl_version():
    res = subprocess.check_output([OPENSSL_EXE,'version'.encode('utf8')]).decode('utf8')
    return res.strip().replace("OpenSSL ","")

def test_openssl_version():
    assert openssl_version() >= "1.0.2"

# Use OpenSSL for a command on a certificate, take input from stdin, return output from stdout.
# If anything goes to stderr, generate an errror
OPENSSL_IGNORES = [b"writing RSA key\n"]
def openssl_cmd(cmd,cert=None,der=None,get_returncode=False,output=str,ignore_error=False):
    if openssl_debug():
        sys.stderr.write("OPENSSL CMD: {}\n".format(" ".join(cmd)))
    p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
    if cert:
        (stdout,stderr) = p.communicate(cert.encode('utf-8'))
    elif der:
        (stdout,stderr) = p.communicate(der)
    else:
        raise RuntimeError("Must specify cert or der")
    if get_returncode:
        return p.returncode
    # ignore error on stderr that we can't seem to get rid of
    if stderr in OPENSSL_IGNORES: stderr=""               
    if len(stderr)>0 or p.returncode!=0:
        if not ignore_error:
            sys.stderr.write("**** OPENSSL ERROR (LEN={}  CODE={})****\n".format(len(stderr),p.returncode))
            sys.stderr.write("OPENSSL CMD: {}\n".format(" ".join(cmd)))
            sys.stderr.write("INPUT:\n")
            sys.stderr.write(cert+"\n")
            sys.stderr.write("STDOUT:\n")
            sys.stderr.write(stdout.decode('latin1')+"\n")
            sys.stderr.write("STDERR:\n")
            sys.stderr.write(stderr.decode('latin1')+"\n")
            sys.stderr.write("RETURN CODE: {}\n".format(p.returncode))
            assert False
    if output==str:
        return stdout.decode('utf8',errors='ignore')
    return stdout
        

def openssl_get_service_certificate_chain(ipaddr,hostname,port,protocol):
    """"Returns a list of DaneTestResult objects for looking up a chain"""
    # Note: This can't use openssl_cmd above because it is getting results from a remote system 
    from subprocess import Popen,PIPE,STDOUT
    cmd = None
    inbuf = None
    if protocol.lower()=="https":
        if not port: port = 443
        cmd = [OPENSSL_EXE,'s_client','-host',ipaddr,'-port',str(port),'-servername',hostname,'-showcerts']
    if protocol.lower()=="smtp":
        if not port: port = 25
        inbuf = b"EHLO TEST\r\nHELO TEST\r\nQUIT\r\n"
        cmd = [OPENSSL_EXE,'s_client','-host',ipaddr,'-port',str(port),'-starttls','smtp','-showcerts']
    if not cmd:
        raise RuntimeError("invalid protocol")
    with timeout(seconds=MAX_TIMEOUT):
        try:
            multi_certs = ""
            passed = False
            def get_response(p):
                "Get the response and convert to UNICODE"
                response = b''
                while True:
                    line = p.stdout.readline()
                    response += line
                    if line[3:4]==b' ':
                        return (response.decode('utf8'),line[0:3])

            if openssl_debug():
                sys.stderr.write("OPENSSL CMD: {}\n".format(" ".join(cmd)))
            p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
            (multi_certs,code) = get_response(p)
            what="Fetching EE Certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol)
            passed="END CERTIFICATE" in multi_certs
            # Just QUIT; we will test QUIT conformance elsewhere.
            p.stdin.write(b"QUIT\r\n")
            (resp,code) = get_response(p)
        except TimeoutError:
            what="Timeout fetching certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol)
        except IOError:
            what="IOError fetching certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol)
        return [ DaneTestResult(test=TEST_EECERT_HAVE,
                                passed=passed,
                                what=what,
                                ipaddr=ipaddr,
                                hostname=hostname,
                                data=multi_certs) ]
    return []

def openssl_get_certificate_field(cert,field):
    """Uses openssl's x509 feature to return a specified field of a certificate
    We previously used asn1parse, but it had reliability problems"""
    cmd = [OPENSSL_EXE,'x509','-text']
    fields = openssl_cmd(cmd,cert).split("\n")
    for i in range(0,len(fields)-1):
        if field in fields[i]:
            return fields[i+1].strip()
    return None
            
def openssl_get_authority_key_identifier(cert):
    line = openssl_get_certificate_field(cert,"X509v3 Authority Key Identifier")
    line = line.replace("keyid:","").replace(":","")
    return line

def openssl_get_subject_key_identifier(cert):
    line = openssl_get_certificate_field(cert,"X509v3 Subject Key Identifier")
    if line:
        line = line.replace("keyid:","").replace(":","")
        return line
    return None

def get_cafile_certificate_by_subject_key_identifier(keyid):
    """Search OPENSSL_CAFILE for a specific key by keyid"""
    import codecs
    for cert in split_certs(codecs.open(OPENSSL_CAFILE,mode="r",encoding='latin1',errors='ignore').read()):
        if openssl_get_subject_key_identifier(cert)==keyid:
            return cert
    return None

def get_cafile_certificate_by_tlsa_rr(tlsa_rr):
    import codecs
    for cert in split_certs(codecs.open(OPENSSL_CAFILE,mode="r",encoding='latin1',errors='ignore').read()):
        tm = tlsa_match(tlsa_rr,cert)
        if tm[0].passed:
            return cert
    return None


################################################################
# Implement a simple timeout
# usage:
#    try:
#        with timeout(seconds=3):
#            stuff you do...
#    except TimeoutError as e:
#        pass
#
class TimeoutError(RuntimeError):
    pass

class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        import signal
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        import signal
        signal.alarm(0)
################################################################
# 
# Stylesheet for showing the HTML output of this command
html_style = """
<style>
.passed { background-color: #80FF80 }
.failed { background-color: red }
.warning { background-color: yellow }
table { border-collapse: collapse }
th, td { border: 1px solid black }
th { color: gray }
td { vertical-align: top }
th, td { padding: 3px }
.info { border-left: 1px solid white;
        border-right: 1px solid white;
        line-height: 200%;
      }
</style>
"""
################################################################
valid_tests = {}
class DaneTest:
    def __init__(self,num,desc,section="",failed_desc=None,recommendation=False):
        assert num not in valid_tests
        self.num  = num
        self.desc = desc
        self.section = section
        self.failed_desc = failed_desc
        self.recommendation = recommendation
        valid_tests[num] = self

## 100 series - DNS queries ##
INFO_TEST              = DaneTest(0,"","")

TEST_CNAME_NOERROR     = DaneTest(101,"""If at any stage of CNAME expansion an error is detected, the lookup of the original requested records MUST be considered to have failed.""","2.1.3") 
TEST_CNAME_EXPANSION_SECURE      = DaneTest(102,"""if at
   any stage of recursive expansion an "insecure" CNAME record is
   encountered, then it and all subsequent results (in particular, the
   final result) MUST be considered "insecure" regardless of whether any
   earlier CNAME records leading to the "insecure" record were "secure".""","2.1.3")
TEST_TLSA_PRESENT    = DaneTest(103,"Service hostname must have matching TLSA record")
TEST_TLSA_DNSSEC     = DaneTest(104,"TLSA records must be secured by DNSSEC")

## 200 Series - Server verification
TEST_SMTP_CONNECT    = DaneTest(201,"Server must have working SMTP server on IP address")
TEST_SMTP_STARTTLS   = DaneTest(202,"""Any connection to the MTA MUST employ TLS authentication (SMTP Server must offer STARTTLS)""","2.2")
TEST_SMTP_TLS        = DaneTest(203,"Any connection to the MTA MUST employ TLS authentication (SMTP Server must enter TLS mode)","2.2")
TEST_SMTP_QUIT       = DaneTest(204,"Any connection to the MTA MUST employ TLS authentication (SMTP Server must work after TLS entered)","2.2")
TEST_EECERT_HAVE     = DaneTest(205,"Server must have End Entity Certificate")
TEST_TLSA_CU0_FOUND       = DaneTest(206,"Certificate Usage 0 specifies a CA certificate, or the public key of such a certificate, that MUST be found in any of the PKIX certification paths for the end entity certificate given by the server in TLS","2.1.1")

## 300 series - Certificate verification
TEST_SMTP_CU         = DaneTest(301,"TLSA records for port 25 SMTP service used by client MTAs SHOULD "\
                                    "NOT include TLSA RRs with certificate usage PKIX-TA(0) or PKIX-EE(1)","3.1.3")
TEST_TLSA_CU02_TP_FOUND = DaneTest(302,"TLSA certificate usage 0 and 2 specifies a trust point that is found in the server's certificate chain")
TEST_TLSA_PARMS      = DaneTest(303,"TLSA Certificate Usage must be in the range 0..3, Selector in the range 0..1, and matching type in the range 0..2")
TEST_TLSA_RR_LEAF    = DaneTest(304,"TLSA RR is not supposed to match leaf with usage 0 or 2")
TEST_DANE_SMTP_RECOMMEND  = DaneTest(305,"""Internet-Draft RECOMMEND[s] the use of "DANE-EE(3) SPKI(1) SHA2-256(1)" with "DANE-TA(2) Cert(0) SHA2-256(1)" TLSA records as a second choice, depending on site needs.""","3.1",recommendation=True)
TEST_EECERT_VERIFY   = DaneTest(306,"Server EE Certificate must PKIX Verify",failed_desc="Server EE Certificate does not PKIX Verify")
TEST_EECERT_NAME_CHECK = DaneTest(307,"""When name checks are applicable (certificate usage DANE-TA(2)), if
   the server certificate contains a Subject Alternative Name extension
   ([RFC5280]), with at least one DNS-ID ([RFC6125]) then only the DNS-
   IDs are matched against the client's reference identifiers.... The
   server certificate is considered matched when one of its presented
   identifiers ([RFC5280]) matches any of the client's reference
   identifiers.""","3.2.3")
TEST_DANE2_CHAIN     = DaneTest(308,"""SMTP servers that rely on certificate usage DANE-TA(2) TLSA records for TLS authentication MUST include the TA certificate as part of the certificate chain presented in the TLS handshake server certificate message even when it is a self-signed root certificate.""","3.2.1")

### 400 series - Ensemble results
TEST_TLSA_CU_VALIDATES = DaneTest(401,"At least one TLSA record must have a certificate usage and associated data that validates at least one EE cetficiate")
TEST_TLSA_ATLEAST1   = DaneTest(402,"There must be at least 1 usable TLSA record for a host name")
TEST_TLSA_ALL_IP     = DaneTest(403,"All IP addresses for a host that is TLSA protected must TLSA verify")

TEST_TLSA_HTTP_NO_FAIL = DaneTest(404,"No HTTP DANE test may fail")
TEST_DNSSEC_ALL      = DaneTest(405,"All DNS lookups must be secured by DNSSEC")
TEST_ALL_SMTP_PASS   = DaneTest(406,"All DANE-related tests must pass for a SMTP host")
TEST_MX_PREEMPTION   = DaneTest(407,""" "Domains that want secure inbound mail delivery need to ensure that all their SMTP servers and MX records are configured accordingly." Specifically, MX records that do not have DANE protection should not preempt MX servers that have DANE protection.""","2.2.1")

    
################################################################
#
# Object to represent the outputs

class DaneTestResult:
    __slots__ = ['passed','dnsrelied','hostname','ipaddr','test','what','data','response','rr','key']
    def __init__(self,passed=None,test=None,what='',data=None,
                 response=None,rr=None,hostname=None,ipaddr=None,key=0):
        self.passed = passed
        self.dnsrelied = True           # by default, assume we rely on this DNS
        self.hostname = hostname
        self.ipaddr = ipaddr
        self.test   = test
        self.what   = what
        self.data   = data
        self.response = response # the entire response
        self.rr     = rr        # the specific rr
        self.key    = key
    def dnssec(self):
        return bool(self.response.flags & dns.flags.AD) if self.response else None           # was query DNSSEC validated?

    def __repr__(self):
        if type(self.data)==str:
            count = self.data.count("\n")
            if count==0:
                lines = self.data
            else:
                lines = "{} lines ".format(count)
        else:
            lines = ""
        return "<%s %s %s %s>" % ({True:"P",False:"F","":"n/a",
                                   PROGRESS:PROGRESS,
                                   INFO:INFO,WARNING:WARNING,
                                   None:"None"}[self.passed],
                                  self.dnssec(),self.what,lines)

# Count the number of results in an array
def count_passed(ret,val=None):
    return len(list(filter(lambda a:a.passed==val,ret)))

def find_result(ret,what):
    for r in ret:
        if r.what==what: return r
    return None

# Return all of the results that have a certain test.
def find_first_test(ret,test):
    for r in ret:
        if r.test==test: return r
    return None

################################################################
## Simple conversion routines
def hexdump(s, separator=''):
    if type(s)==str:
        return separator.join("{:02X}".format(ord(x)) for x in s)
    if type(s)==bytes:
        return separator.join("{:02X}".format(x) for x in s)
    if type(s)==memoryview:
        return separator.join("{:02X}".format(x) for x in bytes(s))
    raise RuntimeError("Unknown type for hexdump: {}".format(type(s)))

def is_ldh_hostname(hostname):
    for ch in hostname.lower():
        if ch not in "abcdefghijklmnopqrstuvwxyz.1234567890-":
            return False
    return True

def is_wild_or_ldh_hostname(hostname):
    if hostname[0:2]=='*.': return is_ldh_hostname(hostname[2:])
    return is_ldh_hostname(hostname) 

def name_clean(n):
    n = n.lower()
    if n.endswith("."): n = n[0:-1]
    return n

# In this code "foo.bar.example.com" (hn) matches
# "*.example.com" (cn).  That's too permissive per
# RFC 6125, the "*" should match just one label.
#
def hostname_match(hn,cn):
    hn = name_clean(hn)
    cn = name_clean(cn)
    if not is_ldh_hostname(hn): return False
    if not is_wild_or_ldh_hostname(cn): return False
    if cn.startswith("*."):
        return hn.endswith(cn[1:])
    else:
        return hn==cn

# Tests for above

def test_hexdump():
    assert hexdump("ABC")=="414243"

def test_is_ldh_hostname():
    assert is_ldh_hostname("foo.bar")==True
    assert is_ldh_hostname("^foo.bar")==False

def test_is_wild_or_ldh_hostname():
    assert is_wild_or_ldh_hostname("*.foo.bar")==True
    assert is_wild_or_ldh_hostname("zorch.*.foo.bar")==False

def test_name_clean():
    assert name_clean("foo.bar.")=="foo.bar"

def test_hostname_match():
    assert hostname_match("this.that","this.that.")==True
    assert hostname_match("this.that","*.that.")==True


################################################################
## PEM Verification and manipulation routines
##
## Verify PEM certificate chain and end entity certificates in PEM format using OpenSSL
##
def is_pem(cert):
    return (type(cert)==str) and (BEGIN_PEM_CERTIFICATE in cert) and (END_PEM_CERTIFICATE in cert)


def pem_verify(anchor_cert,cert_chain,ee_cert):
    # Verify certificates using openssl
    assert not anchor_cert or is_pem(anchor_cert)
    assert not cert_chain  or is_pem(cert_chain)
    assert not ee_cert     or is_pem(ee_cert)
    import tempfile
    with tempfile.NamedTemporaryFile(delete=not openssl_debug()) as chainfile:
        with tempfile.NamedTemporaryFile(delete=not openssl_debug()) as eefile:
            with tempfile.NamedTemporaryFile(delete=not openssl_debug()) as acfile:
                eefile.write(ee_cert.encode('utf8'))
                eefile.flush()

                chainfile.write(cert_chain.encode('utf8'))
                chainfile.flush()

                cmd = [OPENSSL_EXE,'verify','-purpose','sslserver','-trusted_first','-partial_chain']
                cmd += ['-CApath','/etc/no-subdir']
                if anchor_cert:
                    acfile.write(anchor_cert.encode('utf8'))
                    acfile.flush()
                    cmd += ['-CAfile',acfile.name]
                else:
                    cmd += ['-CAfile',OPENSSL_CAFILE]

                cmd += ['-untrusted',chainfile.name,eefile.name]
                try:
                    returncode = openssl_cmd(cmd,cert="\n",get_returncode=True)
                    if returncode==0:
                        return True
                except subprocess.CalledProcessError:
                    return False

def der_to_pem(val):
    """Convert a hex representation of a certificate to PEM format"""
    cmd = [OPENSSL_EXE,'x509','-inform','DER','-outform','PEM']
    return openssl_cmd(cmd,der=val)

def pem_to_der(val):
    """Convert a hex representation of a certificate to PEM format"""
    cmd = [OPENSSL_EXE,'x509','-inform','PEM','-outform','DER']
    return openssl_cmd(cmd,cert=val,output=bytes)

# Uses external program to extract AltNames
# cert must be in PEM format
def cert_subject_alternative_names(cert):
    assert is_pem(cert)
    assert os.path.exists(GET_ALTNAMES_EXE)
    cmd = [GET_ALTNAMES_EXE,'/dev/stdin']
    p = Popen(cmd,stdout=PIPE,stdin=PIPE)
    res = p.communicate(input=cert.encode('utf8'))[0]
    if p.returncode!=0: return [] # error condition
    r = set(res.decode('utf8').split("\n"))
    r.remove("")
    return r

# Verify a certificate chain for a hostname
# The result should be all passed=True, no passed=False
def cert_verify(anchor_cert,cert_chain,hostnames,ipaddr,cert_usage):
    hostname0 = hostnames[0]
    certs = split_certs(cert_chain)
    if not certs:
        return [ DaneTestResult(passed=False,
                                test=TEST_EECERT_HAVE,
                                hostname=hostname0,ipaddr=ipaddr,
                                what="No EE Certificate presented") ]

    # Get the subject of the certificate
    cmd = [OPENSSL_EXE,'x509','-noout','-subject']
    cn = openssl_cmd(cmd,certs[0]).strip() # remove trailing newline

    ret = []
    against = "TLSA-provided anchors"  if anchor_cert else "system anchors"
    r = pem_verify(anchor_cert,cert_chain,certs[0])
    ret += [ DaneTestResult(passed=r,
                            test=TEST_EECERT_VERIFY,
                            hostname=hostname0,ipaddr=ipaddr,
                            what="Checking EE Certificate '{}' against {}".format(cn,against)) ]
    


    alt_names = cert_subject_alternative_names(certs[0])
    if alt_names:
        matched = False
        for hostname in hostnames:
            for an in alt_names:
                if hostname_match(hostname,an):
                    msg = "EE Certificate Alternative Name '{}' matches hostname '{}'".format(an,hostname)
                    ret += [ DaneTestResult(passed=True,
                                            hostname=hostname0,ipaddr=ipaddr,
                                            what=msg,
                                            test=TEST_EECERT_NAME_CHECK) ]
                    matched = True
                    break
        if not matched:
            ret += [ DaneTestResult(passed=False,
                                    hostname=hostname0,ipaddr=ipaddr,
                                    test=TEST_EECERT_NAME_CHECK,
                                    what="Hostname {} does not match EE Certificate AltNames {}.".
                                    format(hostnames,", ".join(alt_names)))]



    else:
        matched = hostname_match(hostname0,cn)
        if matched:
            what="Hostname {} matches EE Certificate Common Name '{}'".format(hostnames,cn)
        else:
            what="Hostname {} does not match EE Certificate Common Name '{}'".format(hostnames,cn)
        ret += [ DaneTestResult(passed=matched,
                                what=what,
                                hostname=hostname0,ipaddr=ipaddr,
                                test=TEST_EECERT_NAME_CHECK) ]
                 
    return ret

################################################################
## TLSA Verification
## Based on tlsa_survey.py from VeriSign
# Copyright (c) 2015, Verisign, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of tlsa-survey nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# DER = Binary DER (Distinguished Encoding Rules) encoded certificates. 
# PEM = Privacy Enhanced Mail (a certificate encoding format)

def tlsa_cert_select(selector,pem_cert):
    """Return the TLSA selector for a given certificate.
    @Param s - the TLSA selector. 0=Full Certificate (as DER), 1 = Pubkey (as DER)
    @Param cert - the certificate, as a PEM string
    """
    assert selector in [0,1]
    assert "-----BEGIN CERTIFICATE-----" in pem_cert
    if selector==0:             # The full certificate, in DER
        der = openssl_cmd([OPENSSL_EXE,'x509','-inform','pem','-outform','der'],pem_cert,output=bytes)
        return der
    if selector==1:             # Just the public key
        pubkey_pem = openssl_cmd([OPENSSL_EXE,'x509','-pubkey'],pem_cert,ignore_error=True)
        pubkey_der = openssl_cmd([OPENSSL_EXE,'rsa','-inform','pem','-pubin','-outform','der'],pubkey_pem,output=bytes,ignore_error=True)
        return pubkey_der
    
# matching type:
# 0 - raw certificate in DNS, in binary
# 1 - SHA256 is in the DNS
# 2 - SHA512 is in the DNS
                        
def tlsa_match(tlsa_rr, cert=None):
    """Returns a DaneTestResult that indicates if the TLSA matches the provided certificate or not"""
    mtype = tlsa_rr.mtype
    import hashlib
    assert mtype in [0,1,2]
    cert_data = tlsa_cert_select(tlsa_rr.selector,cert)
    if mtype == 0:
        comp_data = cert_data       # tlsa_rr contains the actual certificate
    elif mtype == 1:
        comp_data = hashlib.sha256(cert_data).digest()
    elif mtype == 2:
        comp_data = hashlib.sha512(cert_data).digest()
    else:
        raise RuntimeError("Invalid value for mtype=={}".format(mtype))
    matches = True if comp_data == tlsa_rr.cert else None
    return [ DaneTestResult(passed=matches,
                            what="TLSA mtype {}:  hex_data={} from_dns={}".format(mtype,hexdump(cert_data),hexdump(tlsa_rr.cert))) ]
    

# CU 0 - Directly specifies the CA certificate or public key used to validate the certificate provided by the End Entity (EE)
# There must be a valid chain from the EE to the CU 0 trust anchor and the CU 0 trust anchor must be a recognized CA.
#
# CU 1 - Directly specifies the EE certificate or public key, and the certificate must validate.
#
# CU 2 - Specifies a trust anchor. There must be a valid chain from the EE to the CU 2 trust anchor.
#
# CU 3 - Directly specifies the EE's certificate or public key, and the certificate need not validate.

# Cert usage 2 does not use the system trust anchors
# With usage 0, must verify *twice*, once with the
# anchor cert, and again with the system certs.
# With usage, verify with just the system certs.
#
# XXX: Update code accordingly.
#

# tlsa_verify:
# @param cert_chain - a PEM-encoded chain of certificates
# @param tlsa_rdata - the particular TLSA record being verified
# @param hostname   - the hostname being verified

def tlsa_verify(cert_chain, tlsa_rr, hostnames, ipaddr, protocol):
    hostname0  = hostnames[0]
    cert_usage = tlsa_rr.usage
    selector   = tlsa_rr.selector
    mtype      = tlsa_rr.mtype
    associated_data = tlsa_rr.cert
    ret = []

    ret += [ DaneTestResult(passed=PROGRESS,
                            what='Checking TLSA record {} {} {} {}'.format(cert_usage,selector,mtype,hexdump(associated_data))) ]

    tlsa_params_valid = (cert_usage in [0,1,2,3]) and (selector in [0,1]) and (mtype in [0,1,2])
    ret += [ DaneTestResult(passed=tlsa_params_valid,
                            test=TEST_TLSA_PARMS,
                            hostname=hostname0,
                            ipaddr=ipaddr,
                            what="Checking TLSA Parameters: {} {} {}".format(cert_usage,selector,mtype)) ]
    if not tlsa_params_valid: return ret

    verbose = False
    if verbose:
        ret += [ DaneTestResult(passed=INFO, hostname=hostname0, ipaddr=ipaddr,
                                what="Certificate Usage {}: {}".format(cert_usage,cert_usage_str[cert_usage])) ]
        ret += [ DaneTestResult(passed=INFO, hostname=hostname0, ipaddr=ipaddr,
                                what="TLSA Selector {}: {}".format(selector,selector_str[selector])) ]
        ret += [ DaneTestResult(passed=INFO, hostname=hostname0, ipaddr=ipaddr,
                                what="TLSA Matching Type {}: {}".format(mtype,mtype_str[mtype])) ]
                                                                   
    # Check for following recommendation
    if protocol=='smtp':
        if (cert_usage==3 and selector==1 and mtype==1) or (cert_usage==2 and selector==0 and mtype==1):
            follows_recommendation = True
        else:
            follows_recommendation = WARNING
        ret += [ DaneTestResult(passed=follows_recommendation,
                                test=TEST_DANE_SMTP_RECOMMEND,
                                hostname=hostname0,
                                ipaddr=ipaddr,
                                what="Checking TLSA Parameters against Internet-Draft Recommendation: {} {} {}"
                                .format(cert_usage,selector,mtype)) ]
                                
    # Cert Usage 0-1 SHOULD NOT be used with SMTP
    if protocol=='smtp':
        cu_valid = cert_usage not in [0,1]
        ret += [ DaneTestResult(passed=cu_valid,
                                hostname=hostname0,
                                ipaddr=ipaddr,
                                what="Checking certificate usage: {}".format(cert_usage),
                                test=TEST_SMTP_CU) ]
        if not cu_valid: return ret
                 
    usage_good    = False

    # NOTE: For certificate usage 2, selector 0, matching 0,
    # the certificate in the TLSA record should be added to the certificate chain
    if cert_usage==2 and selector==0 and mtype==0:
        cert_chain += der_to_pem(bytes(tlsa_rr.cert))

    certs = split_certs(cert_chain)
    if len(certs)==0:           # nothing to verify???
        return ret

    trust_anchor  = None

    if cert_usage == 0:
        # Cert usage 0 specifies a CA certificate. This should only be used for HTTP
        trust_anchor = get_cafile_certificate_by_tlsa_rr(tlsa_rr)
        ret += [ DaneTestResult(test=TEST_TLSA_CU0_FOUND,
                                passed=True if trust_anchor else False,
                                hostname=hostname0,
                                ipaddr=ipaddr,
                                what="Searching for CA certiciate in CAFile against TLSA record") ]
        usage_good = True if trust_anchor else False

    if cert_usage == 2:
        # Cert usage 2 specifies a trust anchor in the chain.
        # Examine the chain and extract the trust anchors
        ret_not_matching = []
        for count in range(len(certs)):
            cert = certs[count]         # certificate in PEM format, as returned by OpenSSL command line
            cert_name = "EE certificate" if count==0 else "Chain certificate {}".format(count)
            tm = tlsa_match(tlsa_rr, cert=cert)

            if tm[0].passed:
                ret += [ DaneTestResult(test=TEST_TLSA_CU02_TP_FOUND,
                                        passed=True,
                                        hostname=hostname0,
                                        ipaddr=ipaddr,
                                        what="Checking EE certificate {} against TLSA usage {}".format(cert_name,cert_usage)) ]
                ret += [ DaneTestResult(passed= (cert!=certs[0]),
                                        test=TEST_TLSA_RR_LEAF,
                                        hostname=hostname0,
                                        ipaddr=ipaddr,
                                        what="Checking if matching certificate is leaf certificate") ]
                trust_anchor  = cert
                usage_good    = True
            else:
                ret_not_matching += tm
                ret_not_matching += [ DaneTestResult(test=TEST_TLSA_CU02_TP_FOUND,
                                                     passed=None,
                                                     hostname=hostname0,
                                                     ipaddr=ipaddr,
                                                     what="Checking EE certificate {} against TLSA usage {}".format(cert_name,cert_usage)) ]
        if not trust_anchor:
            # No matching certs. This is an error condition
            ret += ret_not_matching
            ret += [ DaneTestResult(passed=None,
                                    test=TEST_TLSA_CU02_TP_FOUND,
                                    hostname=hostname0,
                                    ipaddr=ipaddr,
                                    what="Checked all server chain certificates against TLSA record") ]

    # Cert usages 1 and 3 specify the EE certificate
    if cert_usage in [1,3]:
        tm = tlsa_match(tlsa_rr, cert=certs[0])
        if tm[0].passed:
            # next line commented out so we do not print the whole matching certificate
            # ret += tm
            ret += [ DaneTestResult(passed=True,
                                    hostname=hostname0,
                                    ipaddr=ipaddr,
                                    what="TLSA record CU={} matches EE certificate".format(cert_usage)) ]
            usage_good = True
        else:
            ret += tm
            ret += [ DaneTestResult(passed=None,
                                    hostname=hostname0,
                                    ipaddr=ipaddr,what="EE certificate does not match TLSA usage {}".format(cert_usage)) ]
    
    # Cert usage 0 must validate against system trust anchors
    if cert_usage==0:
        r = cert_verify(trust_anchor,cert_chain,hostnames,ipaddr,cert_usage)
        ret += r
        if count_passed(r,val=False) > 0:
            usage_good = False

    # Cert usage 0, 1 and 2 must verify against the specified trust anchor
    if cert_usage in [0, 1, 2]:
        r = cert_verify(trust_anchor,cert_chain,hostnames,ipaddr,cert_usage)
        ret += r
        if count_passed(r,val=False) > 0:
            usage_good = False

    # If usage is still good, say so. Otherwise leave a blank line...
    if usage_good:
        ret += [ DaneTestResult(passed=True,
                                what="Verifying TLSA record against certificate chain",
                                test=TEST_TLSA_CU_VALIDATES) ]

    ret += [ DaneTestResult(passed=PROGRESS,
                            what='End of TLSA record test') ]
    return ret





################################################################
def split_certs(multi_certs):
    """Takes a long chain of certificates and returns an array of just the certificates"""
    cert_list = []
    # Split the certificates
    certs = multi_certs.split(END_PEM_CERTIFICATE)
    for cert in certs:
        if len(cert) == 0 or cert == '\n':
            continue
        ncert = cert + END_PEM_CERTIFICATE
        loc   = ncert.find(BEGIN_PEM_CERTIFICATE)
        if loc>0:
            ncert = ncert[loc:] # remove stuff before the BEGIN
        cert_list.append(ncert)
    return cert_list[0:-1]


        
################################################################
### Verify remote SMTP server is working properly
def validate_remote_smtp(ipaddr,hostname):
    ret = []
    import smtplib,ssl
    p = False
    c = None
    with timeout(seconds=MAX_TIMEOUT):
        try:
            c = smtplib.SMTP(ipaddr)
            ret += [ DaneTestResult(test=TEST_SMTP_CONNECT,
                                    passed=True if c else False,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="Checking for SMTP server on IPaddr {}".format(ipaddr)) ]
            if not c:
                return ret
            (code,resp) = c.ehlo("THERE")
            ret += [ DaneTestResult(test=TEST_SMTP_STARTTLS,
                                    passed="STARTTLS" in resp,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="Checking for STARTTLS") ]
            (code,resp) = c.starttls()
            ret += [ DaneTestResult(test=TEST_SMTP_TLS,
                                    passed=code==220,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="Executing STARTTLS") ]
            (code,resp) = c.quit()
            ret += [ DaneTestResult(test=TEST_SMTP_QUIT,
                                    passed=code==221,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="Executing QUIT") ]
        except (TimeoutError) as e:
            ret += [ DaneTestResult(test=TEST_SMTP_CONNECT,
                                    passed = False,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="Timeout while checking for SMTP server on IPaddr {}".format(ipaddr)) ]
        except (smtplib.SMTPException) as e:
            ret += [ DaneTestResult(test=TEST_SMTP_CONNECT,
                                    passed = False,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="SMTPExecption while checking for SMTP server on IPaddr {}".format(ipaddr)) ]
        except (ssl.SSLError) as e:
            ret += [ DaneTestResult(test=TEST_SMTP_TLS,
                                    passed = False,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="SMTPExecption while checking for SMTP server on IPaddr {}".format(ipaddr)) ]
        except (smtplib.SMTPServerDisconnected) as e:
            ret += [ DaneTestResult(test=TEST_SMTP_CONNECT,
                                    passed = False,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="SMTPServerDisconnected while connected to SMTP server on IPaddr {}".format(ipaddr)) ]
        except (Exception) as e:
            ret += [ DaneTestResult(test=TEST_SMTP_CONNECT,
                                    passed = False,
                                    hostname=hostname,
                                    ipaddr=ipaddr,
                                    what="Unexpected SMTP Error {} while connected to SMTP server on IPaddr {}".
                                    format(str(e),ipaddr)) ]
            

    return ret
        
        
def tlsa_hostname(host,port):
    return "_{}._tcp.{}".format(port,host)

################################################################
### DNS
### dnspython implementation.

def tlsa_rr_str(rr):
    """Return a normalized (all caps TLSA string associated with a DNS response"""
    return "%s %s %s %s" % (rr.usage, rr.selector, rr.mtype, hexdump(rr.cert))

from tester import Tester
import dns.rdatatype
def dns_query(qname,request_type=dns.rdatatype.A):
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,request_type)
    ret = []
    SUCCESS=""
    for rset in response.answer:
        for rr in rset:
            if rr.rdtype == dns.rdatatype.A == request_type:
                ret.append( DaneTestResult(passed=SUCCESS, 
                                           what="DNS A lookup {} = {}".format(qname, rr.address), 
                                           response=response,
                                           rr=rr, 
                                           data=rr.address,  key=rr.address))
            if rr.rdtype == dns.rdatatype.AAAA == request_type:
                ret.append( DaneTestResult(passed=SUCCESS, 
                                           what='DNS AAAA lookup {} = {}'.format(qname, rr.address), 
                                           response=response,
                                           rr=rr, data=rr.address,  key=rr.address))
            if rr.rdtype == dns.rdatatype.CNAME == request_type:
                ret.append( DaneTestResult(passed=SUCCESS, 
                                           what='DNS CNAME lookup {} = {}'.format(qname, rr.target), 
                                           response=response,
                                           rr=rr, data=rr.target, key=rr.target))
            if rr.rdtype == dns.rdatatype.MX == request_type:
                ret.append( DaneTestResult(passed=SUCCESS, 
                                           what='DNS MX lookup {} = {} {}'.format(qname, rr.preference, rr.exchange.to_text()), 
                                           response=response,
                                           rr=rr, data=rr.exchange.to_text(),  key=rr.preference))
            if rr.rdtype == dns.rdatatype.TLSA == request_type:
                ret.append( DaneTestResult(passed=SUCCESS, what='DNS TLSA lookup {} = {}'.format(qname, tlsa_rr_str(rr)), 
                                           response=response,
                                           rr=rr, key=tlsa_rr_str(rr)))
    ret.sort(key=lambda x:x.key)
    return ret
                

def dns_query_ipv6(qname):
    return dns_query(qname,request_type=dns.rdatatype.AAAA)

def dns_query_mx(qname):
    return dns_query(qname,request_type=dns.rdatatype.MX)

def dns_query_cname(qname):
    return dns_query(qname,request_type=dns.rdatatype.CNAME)

def dns_query_tlsa(host,port):
    # See if the TLSA record is actually pointing to a CNAME
    ret = []
    tlsa_name = tlsa_hostname(host,port)
    (tlsa_name,cname_ret) = chase_dns_cname(tlsa_name)
    ret += cname_ret
    ret += dns_query(tlsa_name,request_type=dns.rdatatype.TLSA)
    return ret

################################################################
#
# If hostname is a cname, return (canonical name,results)
# Otherwise return (hostname,[])
def chase_dns_cname(hostname):
    original_hostname = hostname
    results = []
    depth = 0
    secure = True
    while depth < MAX_CNAME_DEPTH and hostname:
        cname_results = dns_query_cname(hostname)
        if cname_results==[]:
            if depth>0:
                results += [ DaneTestResult(passed=secure,
                                            test=TEST_CNAME_EXPANSION_SECURE,
                                            what='Expanding CNAME {} to {}'.format(original_hostname,hostname))]
            return (hostname,results)
        for r in cname_results:
            if not r.dnssec():
                secure = False
        results += cname_results
        hostname = cname_results[0].data
        depth += 1
    results += [ DaneTestResult(passed=False,
                                what='CNAME search for {} reached depth of {}'.
                                format(original_hostname,MAX_CNAME_DEPTH))]
    return (None,results)
    
def get_tlsa_records(retlist):
    """Return the TLSA records in the set of DaneTestResult()"""
    for r in retlist:
        assert type(r)==DaneTestResult
    return list(filter(lambda e:e.rr and e.rr.rdtype==dns.rdatatype.TLSA,retlist))


#
# For a given hostname, port, and protocol, get the list
# of IP addresses and verify the certificate of each.

def tlsa_service_verify(desc="",hostname="",port=0,protocol="",delivery_hostname=None,delivery_tlsa=[]):
    ret = []
    ret += dns_query_tlsa(hostname,port)

    tlsa_records = get_tlsa_records(ret)

    if delivery_tlsa:
        tlsa_records += delivery_tlsa

    what = "Resolving TLSA records for hostname '{}'".format(tlsa_hostname(hostname,port))
    if delivery_hostname:
        what += " and hostname " + tlsa_hostname(delivery_hostname,port)
    ret += [ DaneTestResult(passed = (len(tlsa_records)>0),
                            test = TEST_TLSA_PRESENT,
                            hostname = hostname,
                            what = what) ]

    if tlsa_records:
        ret += [ DaneTestResult(passed = bool(tlsa_records[0].dnssec()),
                                what = what,
                                test = TEST_TLSA_DNSSEC,
                                hostname = hostname) ]

    # Chase the CNAME if possible
    (chased_hostname,cname_results) = chase_dns_cname(hostname)
    ret += cname_results
    if not chased_hostname:
        return ret              # CNAME recursion failed

    ip_results = dns_query(chased_hostname)

    # Check each ip address against each tlsa record
    tlsa_verified_ip_addresses = 0
    for ip_result in ip_results:
        ret += [ip_result]
        
        ipaddr = ip_result.data

        # If protocol is SMTP, make sure starttls works
        if protocol=="smtp":
            ret += validate_remote_smtp(ipaddr,hostname)
            if find_first_test(ret,TEST_SMTP_CONNECT).passed==False:
                # No valid SMTP server
                continue

        # Get the certificate for the IP address
        cert_results = openssl_get_service_certificate_chain(ipaddr,hostname,port,protocol)
        ret += cert_results
        cert_chain = cert_results[0].data

        # Verify against each TLSA record
        # If we find a usable TLSA record, report the success.
        # If we do not find a usable TLSA record, report all of the records failures.
        ret_tlsa_noverify = []
        ret_tlsa_verified = []
        validating_tlsa_records = 0
        hostnames         = [hostname]
        if chased_hostname and hostname!=chased_hostname:
            hostnames.append(chased_hostname)
        if delivery_hostname:
            hostnames.append(delivery_hostname)
        for tlsa_record in tlsa_records:
            ret_t = tlsa_verify(cert_chain, tlsa_record.rr, hostnames, ipaddr, protocol)

            if find_first_test(ret_t,TEST_TLSA_CU_VALIDATES) and find_first_test(ret_t,TEST_TLSA_CU_VALIDATES).passed:
                ret_tlsa_verified += ret_t
                validating_tlsa_records += 1
            else:
                ret_tlsa_noverify += ret_t

        # If there are TLSA records, and at least one verified, include that
        # result. Otherwise provide the results of every record that did not verify.
        if tlsa_records:
            if validating_tlsa_records>0:
                ret += ret_tlsa_verified
                tlsa_verified_ip_addresses += 1
            else:
                ret += ret_tlsa_noverify
            ret += [ DaneTestResult(passed=(validating_tlsa_records>0),
                                    test=TEST_TLSA_ATLEAST1,
                                    ipaddr=ipaddr,
                                    hostname=hostname,
                                    what='Counting usable TLSA records for {} host {} ipaddr {}. Total found: {}'\
                                    .format(desc,hostname,ipaddr,validating_tlsa_records)) ]
        else:
            # If not TLSA records, at least check the EE certificate
            ret += ret_tlsa_noverify
            ret += cert_verify(None,cert_chain,hostname,ipaddr,0)
    ret += [ DaneTestResult(passed=(tlsa_verified_ip_addresses == len(ip_results)),
                            test=TEST_TLSA_ALL_IP,
                            hostname=hostname,
                            what="Validating TLSA records for {} out of {} IP addresses found for host {}"\
                            .format(tlsa_verified_ip_addresses, len(ip_results), hostname)) ]

    # TK: We need to indicate that it works for ALL IP addresses.
    return ret

        
def apply_dnssec_test(ret):
    valid = True
    for test in ret:
        if test.dnsrelied and test.dnssec()==False:
            valid = False
            break
    ret += [ DaneTestResult(test=TEST_DNSSEC_ALL,
                            what="Was DNSSEC present for all tests on which DNSSEC was relied?",
                            passed=valid) ]
    return ret


def tlsa_https_verify(url):
    from urllib.parse import urlparse
    ret  = []
    o    = urlparse(url)    # Find the host and port
    port = o.port if o.port else 443
    ret += tlsa_service_verify(desc="HTTP",hostname=o.hostname,port=port,protocol='https')

    apply_dnssec_test(ret)

    # Make sure that none of the DANE tests were a hard fail
    valid = count_passed(ret,val=True) > 0 and count_passed(ret,val=False)==0
    ret += [ DaneTestResult(test=TEST_TLSA_HTTP_NO_FAIL,
                            what="Did no required DANE HTTP tests have a hard fail?",
                            passed=valid) ]
    return ret
    

# Check to see if the TLSA record for an SMTP host is okay.
# @param delivery_tlsa_records - additional TLSA records if hostname is not the final deliery
def tlsa_smtp_host_verify(hostname,delivery_hostname,delivery_tlsa_records,host_type):
    ret = [ DaneTestResult(passed=INFO,what='Detail for {} host {}:'.format(host_type,hostname)) ]
    ret += tlsa_service_verify(desc=host_type,hostname=hostname,port=25,protocol='smtp',
                               delivery_hostname=delivery_hostname,delivery_tlsa=delivery_tlsa_records)
    apply_dnssec_test(ret)
    return ret
    

def tlsa_smtp_verify(destination_hostname):
    # Get a list of hosts from either the MX list or the hostname
    ret = []
    delivery_tlsa = []
    mx_data  = dns_query_mx(destination_hostname)
    if not mx_data:
        ret += [ DaneTestResult(what='no MX record for {}'.
                                format(destination_hostname))]
        ret += tlsa_smtp_host_verify(destination_hostname,None,None,'non-MX')
        return ret
    

    # Get the TLSA record for the final destination
    destination_tlsa_ret = dns_query_tlsa(destination_hostname,25)
    delivery_tlsa_records   = get_tlsa_records(destination_tlsa_ret)
    ret += destination_tlsa_ret + mx_data

    # Get the MX hosts
    first = True
    mx_rets = []
    smtp_tlsa_status = None
    for hostname in [h.rr.exchange for h in mx_data]:
        this_ret       = tlsa_smtp_host_verify(hostname.to_text(),destination_hostname,delivery_tlsa_records,'MX')
        all_tests_pass = True if count_passed(this_ret,val=True)>0 and count_passed(this_ret,val=False)==0 else False
        if first:
            # If this is the first host and TEST_SMTP_CONNECT succeded,
            # make sure it is DANE protected.
            r = find_first_test(this_ret,TEST_SMTP_CONNECT)
            if r and r.passed:
                # we found the first working SMTP
                # Now verify if it is DANE-protected or not.
                first = False   
                smtp_tlsa_status = all_tests_pass

        this_ret += [ DaneTestResult(passed=all_tests_pass,
                                     what='Scanning DANE tests for MX host {}'.format(hostname),
                                     test=TEST_ALL_SMTP_PASS,
                                     hostname=hostname)]
        mx_rets += this_ret
        # If this MX hosts pasts, add success to destination_hostname
        if all_tests_pass:
            ret += [ DaneTestResult(passed=all_tests_pass,
                                    what='Scanning DANE tests for MX host {}'.format(hostname),
                                    test=TEST_ALL_SMTP_PASS,
                                    hostname=hostname)]

    ret += [DaneTestResult(passed=smtp_tlsa_status,
                           test=TEST_MX_PREEMPTION,
                           hostname=destination_hostname,
                           what="Highest priority MX server that is operational must be DANE protected")]
    ret += [DaneTestResult(passed=INFO,
                           what='Conclusion: {} {} receive DANE-secured EMAIL'.format(destination_hostname,
                                                                                      'can' if smtp_tlsa_status else 'cannot'),
                           hostname=destination_hostname)]
    ret += [DaneTestResult(passed=INFO,what='')] # blank line
    ret += mx_rets
    return ret
    
def print_test_results(results,format="text"):
    def dnssec(t):
        return "DNSSEC" if t.dnssec() else ""

    def passed(t):
        return {True:"PASSED: ",
                False:"FAILED: ",
                "":"",
                INFO:"INFO: ",
                WARNING:"WARNING: ",
                PROGRESS:"",
                None:""}[t]

    import textwrap
    w = textwrap.TextWrapper()
    w.width = 80
    w.subsequent_indent = "{:<20}".format("")

    needs_header = True
    if format=="text":
        print("  status ")
        print(" ------- ")
    if format=="html":
        print(html_style)
        print("<p>")
        print("<table>")
    for result in results:
        if format=="html":
            passed_text  = passed(result.passed).replace(":","").replace(" ","")
            passed_class = passed_text.lower()
            if result.passed==INFO:
                print("<tr class={}>".format(passed_class))
                print("<td colspan=5 class=info>{}</td></tr>".format(result.what))
                needs_header = True
                continue
            if needs_header:
                print("<tr><th>Test #</th><th>Host</th><th>IP</th><th>Status</th><th>Test Description (§ Section)</th></tr>")
                needs_header = False
            print("<tr class={}>".format(passed_class))
            if result.test:
                num  = result.test.num
                desc = result.test.desc
                if not result.passed and result.test.failed_desc:
                    desc = result.test.failed_desc
                if result.test.section:
                    if '"' in desc:
                        desc = '{} (§{})'.format(desc,result.test.section)
                    else:
                        desc = '"{}" (§{})'.format(desc,result.test.section)
            else:
                num = ""
                desc = ""
            desc += "<br>" if len(desc)>0 and len(result.what)>0 else ""
            desc += "<b>" + dnssec(result) + " </b>" + "<i>" + result.what + "</i>"

            def fixnone(x):
                return x if x!=None else ""

            print("<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>".format(
                    num,
                    fixnone(result.hostname),
                    fixnone(result.ipaddr),
                    passed_text,
                    desc ))
            continue

        # Text
        if result.passed==INFO:
            print("")
            print("  === {} ===".format(result.what))
            continue
        res = "  "
        res += dnssec(result) + result.what
        if not result.test:
            if result.hostname: res += " HOST="+result.hostname
            if result.ipaddr:   res += " ADDR="+result.ipaddr
        print(w.fill(res))
        if result.test:
            res = "  Test {} {} {}".format(result.test.num,passed(result.passed),result.test.desc)
            if result.hostname: res += " HOST="+result.hostname
            if result.ipaddr:   res += " ADDR="+result.ipaddr
            print(w.fill(res))
        print("")
    print("")
    if format=="html":
        print("</table>")
              
# Test system
passed = []
failed = []

def process(domain,format="text"):
    if "http" in domain:
        ret = tlsa_https_verify(domain)
    else:
        ret = tlsa_smtp_verify(domain)
    if ret[-1].passed==True:
        passed.append(domain)
    else:
        failed.append(domain)
    ret += [ DaneTestResult(passed=INFO,what="Using OpenSSL Version {}".format(openssl_version())) ]
    print_test_results(ret,format=format)

def print_stats():
    if passed:
        print("\n\n")
        print("{} Passed URLs:".format(len(passed)))
        for line in passed:
            print(line)

    if failed:
        print("\n\n")
        print("{} Failed URLs:".format(len(failed)))
        for line in failed:
            print(line)
    print("==============================")

if __name__=="__main__":
    import os,sys,argparse

    parser = argparse.ArgumentParser(description="Test one or more DANE servers")
    parser.add_argument("--list",help="List tests",action='store_true')
    parser.add_argument("--html",help="output in HTML",action='store_true')
    parser.add_argument("--test",help="Self test",action='store_true')
    parser.add_argument("--debug",help="Debug OpenSSL commands",action='store_true')
    parser.add_argument("--gethttpcert",help="Get the certificate for HTTP server (for testing)")
    parser.add_argument("--getdnstlsa",help="Get the DNS TLSA")
    parser.add_argument("names",nargs="*")
    args = parser.parse_args()

    if args.debug:
          os.environ['OPENSSL_DEBUG'] = "TRUE"
    format = 'text' if args.html==False else 'html'

    if args.list:
        import textwrap
        w = textwrap.TextWrapper()
        w.width = 80
        for (num,test) in sorted(valid_tests.items()):
            w.initial_indent    = "{:<5}".format(num)
            w.subsequent_indent = "{:<5}".format("")
            print(w.fill(test.desc))
        exit(0)
    

    if args.gethttpcert:
        for r in openssl_get_service_certificate_chain(args.gethttpcert,args.gethttpcert,443,'https'):
            print(r)
        exit(0)

    if args.getdnstlsa:
        for rrset in dns_query_tlsa(args.getdnstlsa,443).answer:
            for rr in rrset:
                if rr.rdtype==dns.rdatatype.TLSA:
                    print("{}: {} {} {} {}".format(args.getdnstlsa,rr.usage,rr.selector,rr.mtype,hexdump(rr.cert)))
        exit(0)

    def check(fn):
        print("\n==== {} ====".format(fn))
        process(fn,format=format)

    if args.names:
        for name in args.names:
            if os.path.exists(name):
                for line in open(name):
                    line = line.strip()
                    if line[0]=='#':
                        print(line)
                    else:
                        check(line)
            else:
                check(name)
        print_stats()
        exit(0)
            

    if args.test:

        # These test vectors from
        # http://www.internetsociety.org/deploy360/resources/dane-test-sites/
        for domain in ["spodhuis.org", "jhcloos.com", "nlnetlabs.nl", "nlnet.nl"
                       ]:
            print("=== {} ===".format(domain))
            process(domain,format=format)


        print("HTTP - Valid TLSA Record with Valid CA-signed TLSA")
        for domain in ["https://fedoraproject.org",
                       "https://www.freebsd.org/",
                       "https://torproject.org",
                       'https://jhcloos.com/',
                       'https://www.kumari.net/',
                       'https://good.dane.verisignlabs.com',
                       'https://www.statdns.net/',
                       'https://dougbarton.us/',
                       'https://www.huque.com/']:
            print("=== Valid: {} ===".format(domain))
            process(domain,format=format)

        print("HTTP Valid TLSA")
        for domain in ["https://rover.secure64.com/"]:
            print("=== Valid: {} ===".format(domain))
            process(domain,format=format)


        print("INVALID TLSA")
        for domain in ["https://rogue.nohats.ca",
                       "https://bad-sig.dane.verisignlabs.com",
                       "https://bad-hash.dane.verisignlabs.com",
                       "https://bad-params.dane.verisignlabs.com",
                       "https://www.nist.gov"]:
            print("=== INVALID: {} ===".format(domain))
            process(domain,format=format)

        print_stats()
        exit(0)
    parser.print_help()
    
