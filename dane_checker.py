#!/usr/bin/python
# -*- coding: utf-8 -*-

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

import getdns
import sys
import pytest
import M2Crypto

MAX_CNAME_DEPTH=20
MAX_TIMEOUT=30
VERSION=1.0

get_altnames_exe = './get_altnames'
openssl_exe = 'openssl' 
openssl_cafile = 'ca-bundle.crt'
openssl_debug = False

import subprocess,os

# See if a better openssl exists; remove OpenSSL defaults
if os.path.exists("/usr/local/ssl/bin/openssl"):
    openssl_exe = "/usr/local/ssl/bin/openssl"
os.environ["SSL_CERT_DIR"]="/nonexistant"
os.environ["SSL_CERT_FILE"]="/nonexistant"


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

valid_tests = {}
class MakeTest:
    def __init__(self,num,desc,section="",failed_desc=None,recommendation=False):
        assert num not in valid_tests
        self.num  = num
        self.desc = desc
        self.section = section
        self.failed_desc = failed_desc
        self.recommendation = recommendation
        valid_tests[num] = self

## 100 series - DNS queries ##
TEST_CNAME_NOERROR     = MakeTest(101,"""If at any stage of CNAME expansion an error is detected, the lookup of the original requested records MUST be considered to have failed.""","2.1.3") 
TEST_CNAME_EXPANSION_SECURE      = MakeTest(102,"""if at
   any stage of recursive expansion an "insecure" CNAME record is
   encountered, then it and all subsequent results (in particular, the
   final result) MUST be considered "insecure" regardless of whether any
   earlier CNAME records leading to the "insecure" record were "secure".""","2.1.3")
TEST_TLSA_PRESENT    = MakeTest(103,"Service hostname must have matching TLSA record")
TEST_TLSA_DNSSEC     = MakeTest(104,"TLSA records must be secured by DNSSEC")

## 200 Series - Server Verification
TEST_SMTP_CONNECT    = MakeTest(201,"Server must have working SMTP server on IP address")
TEST_SMTP_STARTTLS   = MakeTest(202,"""Any connection to the MTA MUST employ TLS authentication (SMTP Server must offer STARTTLS)""","2.2")
TEST_SMTP_TLS        = MakeTest(203,"Any connection to the MTA MUST employ TLS authentication (SMTP Server must enter TLS mode)","2.2")
TEST_SMTP_QUIT       = MakeTest(204,"Any connection to the MTA MUST employ TLS authentication (SMTP Server must work after TLS entered)","2.2")
TEST_EECERT_HAVE     = MakeTest(205,"Server must have End Entity Certificate")

## 200 series - Certificate verification
TEST_SMTP_CU         = MakeTest(301,"TLSA records for port 25 SMTP service used by client MTAs SHOULD "\
                                    "NOT include TLSA RRs with certificate usage PKIX-TA(0) or PKIX-EE(1)","3.1.3")
TEST_TLSA_CU02_TP_FOUND = MakeTest(302,"TLSA certificate usage 0 and 2 specifies a trust point that is found in the server's certificate chain")
TEST_TLSA_PARMS      = MakeTest(303,"TLSA Certificate Usage must be in the range 0..3, Selector in the range 0..1, and matching type in the range 0..2")
TEST_TLSA_RR_LEAF    = MakeTest(304,"TLSA RR is not supposed to match leaf with usage 0 or 2")
TEST_DANE_SMTP_RECOMMEND  = MakeTest(305,"""Internet-Draft RECOMMEND[s] the use of "DANE-EE(3) SPKI(1) SHA2-256(1)" with "DANE-TA(2) Cert(0) SHA2-256(1)" TLSA records as a second choice, depending on site needs.""","3.1",recommendation=True)
TEST_EECERT_VERIFY   = MakeTest(306,"Server EE Certificate must PKIX Verify",failed_desc="Server EE Certificate does not PKIX Verify")
TEST_EECERT_NAME_CHECK = MakeTest(307,"""When name checks are applicable (certificate usage DANE-TA(2)), if
   the server certificate contains a Subject Alternative Name extension
   ([RFC5280]), with at least one DNS-ID ([RFC6125]) then only the DNS-
   IDs are matched against the client's reference identifiers.... The
   server certificate is considered matched when one of its presented
   identifiers ([RFC5280]) matches any of the client's reference
   identifiers.""","3.2.3")
TEST_DANE2_CHAIN     = MakeTest(308,"""SMTP servers that rely on certificate usage DANE-TA(2) TLSA records for TLS authentication MUST include the TA certificate as part of the certificate chain presented in the TLS handshake server certificate message even when it is a self-signed root certificate.""","3.2.1")



### 400 series
TEST_TLSA_CU_VALIDATES = MakeTest(401,"At least one TLSA record must have a certificate usage and associated data that validates at least one EE cetficiate")
TEST_TLSA_ATLEAST1   = MakeTest(402,"There must be at least 1 usable TLSA record for a host name")
TEST_TLSA_ALL_IP     = MakeTest(403,"All IP addresses for a host that is TLSA protected must TLSA verify")

TEST_TLSA_HTTP_NO_FAIL = MakeTest(404,"No HTTP DANE test may fail")
TEST_DNSSEC_ALL      = MakeTest(405,"All DNS lookups must be secured by DNSSEC")
TEST_ALL_SMTP_PASS   = MakeTest(406,"All DANE-related tests must pass for a SMTP host")
TEST_MX_PREEMPTION   = MakeTest(407,""" "Domains that want secure inbound mail delivery need to ensure that all their SMTP servers and MX records are configured accordingly." Specifically, MX records that do not have DANE protection should not preempt MX servers that have DANE protection.""","2.2.1")

    


################################################################
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

INFO="INFO"
WARNING="WARNING"
PROGRESS="PROGRESS"


class DaneTestResult:
    def __init__(self,passed=None,test=None,dnssec=None,what='',data=None,rdata=None,hostname=None,ipaddr=None,testnumber=None,key=0):
        self.passed = passed
        self.dnssec = dnssec
        self.dnsrelied = True   # by default, assume we rely on this DNS
        self.hostname = hostname
        self.ipaddr = ipaddr
        self.test   = test
        self.testnumber = testnumber
        self.what   = what
        self.data   = data
        self.rdata  = rdata
        self.key    = key
    def __repr__(self):
        return "%s %s %s %s" % (self.passed,self.dnssec,self.what,self.data)

# Count the number of results in an array
def count_passed(ret,v):
    return len(filter(lambda a:a.passed==v,ret))

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
def hexdump(str, separator=''):
    return separator.join(x.encode('hex') for x in str)


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
def openssl_version():
    res = subprocess.check_output([openssl_exe,'version'])
    return res.strip().replace("OpenSSL ","")

def test_openssl_version():
    assert openssl_version() >= "1.0.2"

def pem_verify(anchor_cert,cert_chain,ee_cert):
    # Verify certificates using openssl
    import tempfile
    with tempfile.NamedTemporaryFile(delete=not openssl_debug) as chainfile:
        with tempfile.NamedTemporaryFile(delete=not openssl_debug) as eefile:
            with tempfile.NamedTemporaryFile(delete=not openssl_debug) as acfile:
                eefile.write(ee_cert)
                eefile.flush()

                chainfile.write(cert_chain)
                chainfile.flush()

                cmd = [openssl_exe,'verify','-purpose','sslserver','-trusted_first','-partial_chain']
                cmd += ['-CApath','/etc/no-subdir']
                if anchor_cert:
                    acfile.write(anchor_cert)
                    acfile.flush()
                    cmd += ['-CAfile',acfile.name]
                else:
                    cmd += ['-CAfile',openssl_cafile]

                cmd += ['-untrusted',chainfile.name,eefile.name]
                try:
                    if openssl_debug:sys.stderr.write("CMD: "+" ".join(cmd)+"\n")
                    p = subprocess.Popen(cmd,stdout=subprocess.PIPE)
                    res = p.communicate()[0]
                    if openssl_debug:sys.stderr.write("return code={} RES: {}\n".format(p.returncode,res))
                    if p.returncode==0:
                        return True
                except subprocess.CalledProcessError:
                    return False

def hex_der_to_pem(val):
    from M2Crypto import X509
    val = val.replace(" ","").replace("\r","").replace("\n","").replace("\t","")
    x509 = X509.load_cert_string(val.decode("hex"),X509.FORMAT_DER)
    return x509.as_pem()

# Uses external program to extract AltNames
def cert_subject_alternative_names(cert):
    cmd = [get_altnames_exe,'/dev/stdin']
    p = subprocess.Popen(cmd,stdout=subprocess.PIPE,stdin=subprocess.PIPE)
    res = p.communicate(input=cert)[0]
    if p.returncode!=0: return [] # error condition
    r = set(res.split("\n"))
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

    eecert = M2Crypto.X509.load_cert_string(certs[0])
    cn = eecert.get_subject().CN

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
        matched = hostname_match(hostname,cn)
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

# 
# TLSA Selector:
# 0 - Full Certificate
# 1 - Just the public key
def tlsa_select(s, cert):
    assert s in [0,1]
    if s==0: return cert.as_der()
    if s==1: return cert.get_pubkey().as_der()

def upperhex(s):
    s = s.replace(' ','')
    return s.upper()


# matching type:
# 0 - raw certificate in DNS
# 1 - SHA256 is in the DNS
# 2 - SHA512 is in the DNS

def tlsa_match(mtype, cert_data, from_dns):
    import hashlib
    assert mtype in [0,1,2]
    hex_data = hexdump(cert_data)
    if mtype == 1:
        hex_data = hashlib.sha256(cert_data).hexdigest()
    if mtype == 2:
        hex_data = hashlib.sha512(cert_data).hexdigest()
    hex_data = upperhex(hex_data)
    from_dns = upperhex(from_dns)
    matches = True if upperhex(hex_data) == upperhex(from_dns) else None
    return [ DaneTestResult(passed=matches,
                            what="TLSA mtype {}:  hex_data={} from_dns={}".format(mtype,hex_data,from_dns)) ]
    


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

def tlsa_verify(cert_chain,tlsa_rdata,hostnames,ipaddr, protocol):
    hostname0  = hostnames[0]
    cert_usage = tlsa_rdata['certificate_usage']
    selector   = tlsa_rdata['selector']
    mtype      = tlsa_rdata['matching_type']
    associated_data = tlsa_rdata['certificate_association_data']
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
    trust_anchors = ""
    ct = hexdump(tlsa_rdata['certificate_association_data'])

    # NOTE: For certificate usage 2, selector 0, matching 0,
    # the certificate in the TLSA record should be added to the certificate chain
    if cert_usage==2 and selector==0 and mtype==0:
        from M2Crypto import X509
        der = ct.replace(" ","").decode("hex")
        x509 = X509.load_cert_string(der,X509.FORMAT_DER)
        cert_chain += x509.as_pem()

    certs = split_certs(cert_chain)
    if len(certs)==0:           # nothing to verify???
        return ret


    # Cert usages 0 and 2 specify trust anchors in the chain.
    # Examine the chain and extract the trust anchors
    if cert_usage in [0, 2]: 
        ret_not_matching = []
        for count in range(len(certs)):
            cert = certs[count]
            cert_name = "EE certificate" if count==0 else "Chain certificate {}".format(count)
            cert_obj = M2Crypto.X509.load_cert_string(cert)
            cert_data = tlsa_select(selector, cert_obj)
            tm = tlsa_match(mtype, cert_data, ct)
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
                trust_anchors += cert
                usage_good    = True
            else:
                ret_not_matching += tm
                ret_not_matching += [ DaneTestResult(test=TEST_TLSA_CU02_TP_FOUND,
                                                     passed=None,
                                                     hostname=hostname0,
                                                     ipaddr=ipaddr,
                                                     what="Checking EE certificate {} against TLSA usage {}".format(cert_name,cert_usage)) ]
        if not trust_anchors:
            # No matching certs. This is an error condition
            ret += ret_not_matching
            ret += [ DaneTestResult(passed=None,
                                    test=TEST_TLSA_CU02_TP_FOUND,
                                    hostname=hostname0,
                                    ipaddr=ipaddr,
                                    what="Checked all server chain certificates against TLSA record") ]


    # Cert usages 1 and 3 specify the EE certificate
    if cert_usage in [1,3]:
        eecert = M2Crypto.X509.load_cert_string(certs[0])
        cert_data = tlsa_select(selector, eecert)
        tm = tlsa_match(mtype, cert_data, ct)
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
        r = cert_verify(None,cert_chain,hostnames,ipaddr,cert_usage)
        ret += r
        if count_passed(r,False) > 0:
            usage_good = False

    # Cert usage 0, 1 and 2 must verify against specified trust anchor
    if cert_usage in [0, 1, 2]:
        r = cert_verify(trust_anchors,cert_chain,hostnames,ipaddr,cert_usage)
        ret += r
        if count_passed(r,False) > 0:
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
    cert_list = []
    certs = multi_certs.split('-----END CERTIFICATE-----')
    for cert in certs:
        if len(cert) == 0 or cert == '\n':
            continue
        cert_list.append(cert + '-----END CERTIFICATE-----')
    return cert_list[0:-1]

def get_service_certificate_chain(ipaddr,hostname,port,protocol):
    from subprocess import Popen,PIPE,STDOUT
    cmd = None
    inbuf = None
    if protocol.lower()=="https":
        if not port: port = 443
        cmd = [openssl_exe,'s_client','-host',ipaddr,'-port',str(port),'-servername',hostname,'-showcerts']
    if protocol.lower()=="smtp":
        if not port: port = 25
        inbuf = b"EHLO TEST\r\nHELO TEST\r\nQUIT\r\n"
        cmd = [openssl_exe,'s_client','-host',ipaddr,'-port',str(port),'-starttls','smtp','-showcerts']
    if not cmd:
        raise RuntimeError("invalid protocol")
    with timeout(seconds=MAX_TIMEOUT):
        try:
            def get_response(p):
                response = ''
                while True:
                    line = p.stdout.readline()
                    response += line
                    if line[3:4]==' ':
                        return (response,line[0:3])
                    
            p = Popen(cmd,stdin=PIPE,stdout=PIPE,stderr=PIPE)
            (multi_certs,code) = get_response(p)
            what="Fetching EE Certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol)
            passed="END CERTIFICATE" in multi_certs
            # Just QUIT; we will test QUIT conformance elsewhere.
            p.stdin.write("QUIT\r\n")
            (resp,code) = get_response(p)
        except TimeoutError:
            what="Timeout fetching certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol)
            multi_certs = ""
            passed = False
        return [ DaneTestResult(test=TEST_EECERT_HAVE,
                                passed=passed,
                                what=what,
                                ipaddr=ipaddr,
                                hostname=hostname,
                                data=multi_certs) ]
    return []

        
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
        
        

################################################################
### DNS


#extensions = {"return_both_v4_and_v6":getdns.EXTENSION_TRUE,
#                       "dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}

extensions = {"dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}


dnssec_status = {getdns.DNSSEC_SECURE:"SECURE",
                 getdns.DNSSEC_INDETERMINATE:"INDETERMINATE",
                 getdns.DNSSEC_INSECURE:"INSECURE",
                 getdns.DNSSEC_BOGUS:"BOGUS",
                 None:""}



def tlsa_str(rdata):
    return "%s %s %s %s" % (rdata['certificate_usage'],rdata['selector'],
                            rdata['matching_type'],hexdump(rdata['certificate_association_data']))

def v(bin_addr):
    return '.'.join(map(str, map(ord, bin_addr)))

def hexdata(rdata):
    def hex2(f):
        return hex(f)[2:]
    return "".join(map(hex2,map(ord,rdata)))

ctx = getdns.Context()
def get_dns_ip(hostname,request_type=getdns.RRTYPE_A):
    ret = []
    
    ## Broken - If TLSA, do a A query first and ignore the results
    ## Not sure why, but this seems required for the NIST DNS server
    if request_type==getdns.RRTYPE_TLSA:
        ctx.general(name=hostname,request_type=getdns.RRTYPE_A,extensions=extensions)


    SUCCESS=""
    results = ctx.general(name=hostname,request_type=request_type,extensions=extensions)
    for reply in results.replies_tree:
        for a in reply['answer']:
            dstat = reply.get('dnssec_status')
            rdata = a['rdata']
            if a['type'] == getdns.RRTYPE_A == request_type:
                ipv4 = v(rdata['ipv4_address'])
                ret.append( DaneTestResult(passed=SUCCESS,
                                           what='DNS A lookup {} = {}'.format(hostname,ipv4),
                                           dnssec=dstat,data=ipv4, rdata=rdata, key=ipv4) )
            if a['type'] == getdns.RRTYPE_CNAME == request_type:
                ret.append( DaneTestResult(passed=SUCCESS,
                                           what='DNS CNAME lookup {} = {}'.format(hostname,rdata['cname']),
                                           dnssec=dstat,data=rdata['cname'],rdata=rdata,key=rdata['cname']))
            if a['type'] == getdns.RRTYPE_MX == request_type:
                ret.append( DaneTestResult(passed=SUCCESS,
                                           what='DNS MX lookup {} = {} {}'.format(hostname,rdata['preference'],rdata['exchange']),
                                           dnssec=dstat,data=rdata['exchange'],rdata=rdata,key=rdata['preference']))
            if a['type'] == getdns.RRTYPE_TLSA == request_type:
                ret.append( DaneTestResult(passed=SUCCESS,what='DNS TLSA lookup {} = {}'.format(hostname,tlsa_str(rdata)),
                                           dnssec=dstat,rdata=rdata,key=tlsa_str(rdata)))
    ret.sort(key=lambda x:x.key)
    return ret



def get_dns_mx(hostname):
    return get_dns_ip(hostname,request_type=getdns.RRTYPE_MX)

def get_dns_cname(hostname):
    return get_dns_ip(hostname,request_type=getdns.RRTYPE_CNAME)

def tlsa_hostname(host,port):
    return "_{}._tcp.{}".format(port,host)

def get_dns_tlsa(host,port):
    # See if the TLSA record is actually pointing to a CNAME
    ret = []
    tlsa_name = tlsa_hostname(host,port)
    (tlsa_name,cname_ret) = chase_dns_cname(tlsa_name)
    ret += cname_ret
    ret += get_dns_ip(tlsa_name,request_type=getdns.RRTYPE_TLSA)
    return ret


# If hostname is a cname, return (canonical name,results)
# Otherwise return (hostname,[])
def chase_dns_cname(hostname):
    original_hostname = hostname
    results = []
    depth = 0
    secure = True
    while depth < MAX_CNAME_DEPTH:
        cname_results = get_dns_cname(hostname)
        if cname_results==[]:
            if depth>0:
                results += [ DaneTestResult(passed=secure,
                                            test=TEST_CNAME_EXPANSION_SECURE,
                                            what='Expanding CNAME {} to {}'.format(original_hostname,hostname))]
            return (hostname,results)
        for r in cname_results:
            if not r.dnssec:
                secure = False
        results += cname_results
        hostname = cname_results[0].data
        depth += 1
    results += [ DaneTestResult(passed=False,
                                what='CNAME search for {} reached depth of {}'.
                                format(original_hostname,MAX_CNAME_DEPTH))]
    return (None,results)
    
def get_tlsa_records(retlist):
    return list(filter(lambda r:"certificate_usage" in str(r.rdata),retlist))


#
# For a given hostname, port, and protocol, get the list
# of IP addresses and verify the certificate of each.

def tlsa_service_verify(desc="",hostname="",port=0,protocol="",delivery_hostname=None,delivery_tlsa=[]):
    ret = []
    ret += get_dns_tlsa(hostname,port)
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
        ret += [ DaneTestResult(passed = (tlsa_records[0].dnssec==getdns.DNSSEC_SECURE),
                                what = what,
                                test = TEST_TLSA_DNSSEC,
                                hostname = hostname) ]

    # Chase the CNAME if possible
    (chased_hostname,cname_results) = chase_dns_cname(hostname)
    ret += cname_results
    if not chased_hostname:
        return ret              # CNAME recursion failed

    ip_results = get_dns_ip(chased_hostname)

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
        cert_results = get_service_certificate_chain(ipaddr,hostname,port,protocol)
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
            ret_t = tlsa_verify(cert_chain, tlsa_record.rdata, hostnames, ipaddr, protocol)
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
                                    what='Counting usable TLSA records for {} host {} ipaddr {}. Total found: {}'.format(desc,hostname,ipaddr,validating_tlsa_records)) ]
        else:
            # If not TLSA records, at least check the EE certificate
            ret += ret_tlsa_noverify
            ret += cert_verify(None,cert_chain,hostname,ipaddr,0)
    ret += [ DaneTestResult(passed=(tlsa_verified_ip_addresses == len(ip_results)),
                            test=TEST_TLSA_ALL_IP,
                            hostname=hostname,
                            what="Validating TLSA records for {} out of {} IP addresses found for host {}".format(tlsa_verified_ip_addresses,len(ip_results),hostname)) ]

    # TK: We need to indicate that it works for ALL IP addresses.
    return ret

        
def apply_dnssec_test(ret):
    valid = True
    for test in ret:
        if test.dnsrelied and (test.dnssec not in [None,getdns.DNSSEC_SECURE]):
            valid = False
            break
    ret += [ DaneTestResult(test=TEST_DNSSEC_ALL,
                            passed=valid) ]


def tlsa_http_verify(url):
    from urlparse import urlparse
    ret = []

    # Find the host and port
    o = urlparse(url)
    
    port = o.port
    if not port: port = 443
    ret += tlsa_service_verify(desc="HTTP",hostname=o.hostname,port=port,protocol='https')
    apply_dnssec_test(ret)
    # Make sure that none of the DANE tests were a hard fail
    valid = count_passed(ret,True) > 0 and count_passed(ret,False)==0
    ret += [ DaneTestResult(test=TEST_TLSA_HTTP_NO_FAIL,
                            what="Were any DANE HTTP tests a hard fail?",
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
    mx_data  = get_dns_mx(destination_hostname)
    if not mx_data:
        ret += [ DaneTestResult(what='no MX record for {}'.
                                format(destination_hostname))]
        ret += tlsa_smtp_host_verify(destination_hostname,None,None,'non-MX')
        return ret
    

    # Get the TLSA record for the final destination
    destination_tlsa_ret = get_dns_tlsa(destination_hostname,25)
    delivery_tlsa_records   = get_tlsa_records(destination_tlsa_ret)
    ret += destination_tlsa_ret + mx_data

    # Get the MX hosts
    first = True
    mx_rets = []
    smtp_tlsa_status = None
    for hostname in [h.rdata['exchange'] for h in mx_data]:
        this_ret       = tlsa_smtp_host_verify(hostname,destination_hostname,delivery_tlsa_records,'MX')
        all_tests_pass = True if count_passed(this_ret,True)>0 and count_passed(this_ret,False)==0 else False
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
        return dnssec_status[t.dnssec]+" " if t.dnssec else ""

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

    print("Tests completed: %d" % len(results))
    
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
            desc += "<b>" + dnssec(result) + "</b>" + "<i>" + result.what + "</i>"

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
        ret = tlsa_http_verify(domain)
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

if __name__=="__main__":
    import os,sys,argparse

    parser = argparse.ArgumentParser(description="Test one or more DANE servers")
    parser.add_argument("--list",help="List tests",action='store_true')
    parser.add_argument("--html",help="output in HTML",action='store_true')
    parser.add_argument("names",nargs="*")
    args = parser.parse_args()

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
            

    # These test vectors from
    # http://www.internetsociety.org/deploy360/resources/dane-test-sites/
    for domain in ["dougbarton.us","spodhuis.org", "jhcloos.com", "nlnetlabs.nl", "nlnet.nl"
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
