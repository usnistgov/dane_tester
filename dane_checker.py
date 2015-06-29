import getdns
import sys
import pytest
import M2Crypto

MAX_CNAME_DEPTH=20

get_altnames_exe = './get_altnames'
openssl_exe = 'openssl' 
openssl_cafile = 'ca-bundle.crt'
openssl_debug = False

import subprocess,os

# See if a better openssl exists
if os.path.exists("/usr/local/ssl/bin/openssl"):
    openssl_exe = "/usr/local/ssl/bin/openssl"

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

class DaneTestResult:
    def __init__(self,passed=True,dnssec=None,what=None,data=None,rdata=None):
        self.passed = passed
        self.dnssec = dnssec
        self.dnsrelied = True   # by default, assume we rely on this DNS
        self.what   = what
        self.data   = data
        self.rdata   = rdata
    def __repr__(self):
        return "%s %s %s %s" % (self.passed,self.dnssec,self.what,self.data)

# Count the number of results in an array
def count_passed(ret):
    return len(filter(lambda a:a.passed==True,ret))

def count_failed(ret):
    return len(filter(lambda a:a.passed==False,ret))

def find_result(ret,what):
    for r in ret:
        if r.what==what: return r
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
    return res.strip()

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

# Uses external program to extract AltNames
def cert_subject_alternative_names(cert):
    cmd = [get_altnames_exe,'/dev/stdin']
    p = subprocess.Popen(cmd,stdout=subprocess.PIPE,stdin=subprocess.PIPE)
    res = p.communicate(input=cert)[0]
    if p.returncode!=0: return [] # error condition
    return res.split("\n")

# Verify a certificate chain for a hostname
#
def cert_verify(anchor_cert,cert_chain,hostname,cert_usage):
    certs = split_certs(cert_chain)
    if not certs:
        return [ DaneTestResult(passed=False,what="No EE Certificate presented") ]

    eecert = M2Crypto.X509.load_cert_string(certs[0])
    cn = eecert.get_subject().CN

    ret = []
    if pem_verify(anchor_cert,cert_chain,certs[0]):
        ret += [ DaneTestResult(what="EE Certificate '{}' verifies".format(cn)) ]
    else:
        ret += [ DaneTestResult(passed=False,what="EE Certificate '{}' does not verify".format(cn)) ]

    def hostname_desc(which,hostname,name):
        msg = "EE Certificate {} '{}' matches hostname".format(which,name)
        if name_clean(hostname)!=name_clean(name): msg += " '{}'".format(hostname)
        return msg

    matched = False
    if hostname_match(hostname,cn):
        ret += [ DaneTestResult(what=hostname_desc("Common Name",hostname,cn)) ]
        matched = True
    else:
        # Check to see if any subject alternative names
        for an in cert_subject_alternative_names(certs[0]):
            if hostname_match(hostname,an):
                ret += [ DaneTestResult(what=hostname_desc("Alternative Name",hostname,an)) ]
                matched = True
                break

    if matched == False:
        ret += [ DaneTestResult(passed=False,
                                what="EE Certificate Common Name '{}' does not match hostname '{}'".format(cn,hostname)) ]
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
    matches = upperhex(hex_data) == upperhex(from_dns)
    return [ DaneTestResult(passed=matches,what="TLSA mtype {}:  hex_data={} from_dns={}".format(mtype,hex_data,from_dns)) ]
    


TLSA_VALIDATES="TLSA Validates"

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


def tlsa_verify(cert_chain,tlsa_rdata,hostname,protocol):
    cert_usage = tlsa_rdata['certificate_usage']
    selector   = tlsa_rdata['selector']
    mtype      = tlsa_rdata['matching_type']
    associated_data = tlsa_rdata['certificate_association_data']
    ret = []
    certs = split_certs(cert_chain)

    if len(certs)==0:
        print "cert_chain:",cert_chain
        return [ DaneTestResult(passed=False,what="No certificate to verify in cert-chain") ]

    if not (cert_usage in [0,1,2,3] and selector in [0,1] and mtype in [0,1,2]):
        return [ DaneTestResult(passed=False,what="TLSA Parameters bad: {} {} {}".format(cert_usage,selector,mtype)) ]

    # Cert Usage 0-1 SHOULD NOT be used with SMTP
    if cert_usage in [0,1] and protocol=='smtp':
        ret += [ DaneTestResult(passed=False,
                                what="TLSA records for the port 25 SMTP service used by client MTAs "+\
                                    "SHOULD NOT include TLSA RRs with certificate usage PKIX-TA(0) or PKIX-EE(1).") ]
        return ret
                 

    usage_good    = False
    trust_anchors = ""
    ct = hexdump(tlsa_rdata['certificate_association_data'])

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
                ret += [ DaneTestResult(what="{} matches TLSA usage {}".format(cert_name,cert_usage)) ]
                if cert==certs[0]:
                    ret += [ DaneTestResult(what="NOTE: TLSA RR is not supposed to match leaf with usage {}".format(cert_usage)) ]
                trust_anchors += cert
                usage_good    = True
            else:
                ret_not_matching += tm
                ret_not_matching += [ DaneTestResult(passed=None,what="{} does not match TLSA usage {}".format(cert_name,cert_usage)) ]
        if not trust_anchors:
            # No matching certs. This is an error condition
            ret += ret_not_matching
            ret += [ DaneTestResult(passed=None,what="No certificates in chain match TLSA-specified trust anchor") ]


    # Cert usages 1 and 3 specify the EE certificate
    if cert_usage in [1,3]:
        eecert = M2Crypto.X509.load_cert_string(certs[0])
        cert_data = tlsa_select(selector, eecert)
        tm = tlsa_match(mtype, cert_data, ct)
        if tm[0].passed:
            ret += [ DaneTestResult(what="EE certificate matches TLSA usage {}".format(cert_usage)) ]
            usage_good = True
        else:
            ret += tm
            ret += [ DaneTestResult(passed=None,what="EE certificate does not match TLSA usage {}".format(cert_usage)) ]
    
    # Cert usage 0 must validate against system trust anchors
    if cert_usage==0:
        r = cert_verify(None,cert_chain,hostname,cert_usage)
        ret += r
        if count_failed(r) > 0:
            usage_good = False

    # Cert usage 0, 1 and 2 must verify against specified trust anchor
    if cert_usage in [0, 1, 2]:
        r = cert_verify(trust_anchors,cert_chain,hostname,cert_usage)
        ret += r
        if count_failed(r) > 0:
            usage_good = False



    # If usage is still good, say so
    if usage_good:
        ret += [ DaneTestResult(what=TLSA_VALIDATES) ]
    return ret





################################################################
def get_service_certificate_chain(ipaddr,hostname,port,protocol):
    from subprocess import Popen,PIPE
    cmd = None
    if protocol.lower()=="https":
        if not port: port = 443
        cmd = [openssl_exe,'s_client','-host',ipaddr,'-port',str(port),'-servername',hostname,'-showcerts']
    if protocol.lower()=="smtp":
        if not port: port = 25
        cmd = [openssl_exe,'s_client','-host',ipaddr,'-port',str(port),'-starttls','smtp','-showcerts']
    if not cmd:
        raise RuntimeError("invalid protocol")
    with timeout(seconds=10):
        try:
            multi_certs = Popen(cmd,stdin=open("/dev/null","r"),stdout=PIPE,stderr=PIPE).communicate()[0]
            return [ DaneTestResult(what="Fetched EE Certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol),
                                    data=multi_certs) ]
        except TimeoutError:
            return [ DaneTestResult(passed=False,data="",
                                    what="Timeout fetching certificate for {} from {} port {} via {}".format(hostname,ipaddr,port,protocol)) ]
    return []

def split_certs(multi_certs):
    cert_list = []
    certs = multi_certs.split('-----END CERTIFICATE-----')
    for cert in certs:
        if len(cert) == 0 or cert == '\n':
            continue
        cert_list.append(cert + '-----END CERTIFICATE-----')
    return cert_list[0:-1]
        

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
    return "%s %s %s %s" % (rdata['certificate_usage'],rdata['selector'],rdata['matching_type'],hexdump(rdata['certificate_association_data']))

def v(bin_addr):
    return '.'.join(map(str, map(ord, bin_addr)))

def hexdata(rdata):
    def hex2(f):
        return hex(f)[2:]
    return "".join(map(hex2,map(ord,rdata)))

ctx = getdns.Context()
def get_dns_ip(hostname,request_type=getdns.RRTYPE_A):
    ret = []
    
    ## BOGUS - If TLSA, do a A query first and ignore the results
    ## Not sure why, but this seems required for the NIST DNS server
    if request_type==getdns.RRTYPE_TLSA:
        ctx.general(name=hostname,request_type=getdns.RRTYPE_A,extensions=extensions)


    results = ctx.general(name=hostname,request_type=request_type,extensions=extensions)
    for reply in results.replies_tree:
        #print reply
        for a in reply['answer']:
            dstat = reply.get('dnssec_status')
            rdata = a['rdata']
            if a['type'] == getdns.RRTYPE_A == request_type:
                ipv4 = v(rdata['ipv4_address'])
                ret.append( DaneTestResult(what='DNS A lookup {} = {}'.format(hostname,ipv4),
                                           dnssec=dstat,data=ipv4, rdata=rdata) )
            if a['type'] == getdns.RRTYPE_CNAME == request_type:
                ret.append( DaneTestResult(what='DNS CNAME lookup {} = {}'.format(hostname,rdata['cname']),
                                           dnssec=dstat,data=rdata['cname'],rdata=rdata))
            if a['type'] == getdns.RRTYPE_MX == request_type:
                ret.append( DaneTestResult(what='DNS MX lookup {} = {} {}'.format(hostname,rdata['preference'],rdata['exchange']),
                                           dnssec=dstat,data=rdata['exchange'],rdata=rdata))
            if a['type'] == getdns.RRTYPE_TLSA == request_type:
                ret.append( DaneTestResult(what='DNS TLSA lookup {} = {}'.format(hostname,tlsa_str(rdata)),
                                           dnssec=dstat,rdata=rdata))
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
    #print('ret=',ret)
    #print("tlsa_records=",get_tlsa_records(ret))
    return ret


# If hostname is a cname, return (canonical name,results)
# Otherwise return (hostname,[])
def chase_dns_cname(hostname):
    original_hostname = hostname
    results = []
    depth = 0
    while depth < MAX_CNAME_DEPTH:
        cname_results = get_dns_cname(hostname)
        if cname_results==[]:
            return (hostname,results)
        results += cname_results
        hostname = cname_results[0].data
    results += [ DaneTestResult(passed=False,what='CNAME search for %s reached depth of %d' % (original_hostname,MAX_CNAME_DEPTH))]
    return (None,results)
    
def get_tlsa_records(retlist):
    return list(filter(lambda r:hasattr(r,"rdata") and "certificate_usage" in r.rdata,retlist))

   

   
#
# For a given hostname, port, and protocol, get the list
# of IP addresses and verify the certificate of each.

def tlsa_service_verify(hostname,port,protocol):
    ret = []
    ret += get_dns_tlsa(hostname,port)
    tlsa_records = get_tlsa_records(ret)

    if not tlsa_records:
        ret += [ DaneTestResult(passed=False,what='no TLSA records for {}'.format(tlsa_hostname(hostname,port))) ]

    ip_results = get_dns_ip(hostname)

    # Check each ip address against each tlsa record
    for ip_result in ip_results:
        ret += [ip_result]

        # Get the certificate for the IP address
        cert_results = get_service_certificate_chain(ip_result.data,hostname,port,protocol)
        ret += cert_results
        cert_chain = cert_results[0].data

        # Verify against each TLSA record
        # If we find a matching TLSA record, report the success.
        # If we do not find a matching TLSA record, report all of the failures.
        ret_tlsa_noverify = []
        ret_tlsa_verified = []
        validating_tlsa_records = 0
        for tlsa_record in tlsa_records:
            ret_t = tlsa_verify(cert_chain, tlsa_record.rdata, hostname,protocol)
            if find_result(ret_t,TLSA_VALIDATES):
                ret_tlsa_verified += ret_t
                validating_tlsa_records += 1
            else:
                ret_tlsa_noverify += ret_t

        # Make sure at least one TLSA record validated
        if tlsa_records:
            if validating_tlsa_records>0:
                ret += ret_tlsa_verified
                ret += [ DaneTestResult(passed= (validating_tlsa_records>0),
                                        what='Validating TLSA records for {}: {}'.format(hostname,validating_tlsa_records)) ]
            else:
                ret += ret_tlsa_noverify
                ret += [ DaneTestResult(passed= (validating_tlsa_records>0),
                                        what='No validating TLSA records for {}'.format(hostname)) ]
        else:
            # If not TLSA records, at least check the EE certificate
            ret += ret_tlsa_noverify
            ret += cert_verify(None,cert_chain,hostname,0)
    return ret

        
def apply_dane_test(ret,desc):
    valid = False
    for test in ret:
        if test.passed and test.what.startswith("Validating TLSA"):
            return True
    ret += [ DaneTestResult(what='no TLSA record verifies '+desc,passed=False) ]
    return False

def apply_dnssec_test(ret):
    valid = True
    for test in ret:
        if test.dnsrelied and (test.dnssec not in [None,getdns.DNSSEC_SECURE]):
            ret += [ DaneTestResult(what='not all DNS lookups secured by DNSSEC',passed=False) ]
            break


def tlsa_http_verify(url):
    from urlparse import urlparse
    ret = []

    # Find the host and port
    o = urlparse(url)
    original_hostname = o.hostname
    (hostname,cname_results) = chase_dns_cname(o.hostname)
    ret += cname_results
    
    if hostname:            # no cname
        port = o.port
        if not port: port = 443
        # if first name was a cname, make sure there is no TLSA at the original name
        if original_hostname != hostname:
            # Not sure what to do here at the moment...
            # [ DaneTestResult(passed=False,what='TLSA record present for CNAME record {}'.format(tlsa_hostname(hostname,port))) ]
            pass
        ret += tlsa_service_verify(hostname,port,'https')
        apply_dane_test(ret,"for HTTP host "+hostname)
        apply_dnssec_test(ret)
    return ret
    

def tlsa_smtp_verify(hostname):
    original_hostname = hostname
    mx_results = get_dns_mx(hostname)
    if mx_results:
        ret = mx_results
        hostnamelist = [h.data for h in mx_results]
    else:
        ret = [ DaneTestResult(what='no MX record for {}'.format(hostname))]
        hostnamelist = [hostname]
    apply_dnssec_test(ret)
    for hostname in hostnamelist:
        if mx_results:
            host_type = "MX"
            ret += [ DaneTestResult(passed=None,what='=== Checking MX host {} ==='.format(hostname)) ]
        else:
            host_type = "non-MX"
        (hostname,cname_results) = chase_dns_cname(hostname)
        ret += cname_results
        if hostname:
            tlsa_rets = tlsa_service_verify(hostname,25,'smtp')
            r = apply_dane_test(tlsa_rets,"for {} host {}".format(host_type,hostname))
            if r==False and host_type=="MX":
                # if the DANE test fails and this is not an MX host
                # then we do not need to rely on it for DNSSEC
                for t in tlsa_rets:
                    t.dnsrelied=False
            if r==True:
                apply_dnssec_test(tlsa_rets)
            ret += tlsa_rets
    return ret
    


def print_test_results(tests):
    def passed(t):
        return {True:"PASSED",False:"FAILED",None:"      "}[t.passed]

    def dnssec(t):
        return dnssec_status[t.dnssec]+" " if t.dnssec else ""

    print("Tests completed: %d" % len(tests))
    print("  status ")
    print(" ------- ")
    for test in tests:
        print("  %s : %s%s" % (passed(test),dnssec(test),test.what))
    print("")
              
    
# Test system
passed = []
failed = []

def process_http(domain):
    r = tlsa_http_verify(domain)
    print_test_results(r)
    if r[-1].passed:
        passed.append(domain)
    else:
        failed.append(domain)

def process_smtp(domain):
    r = tlsa_smtp_verify(domain)
    print_test_results(r)
    if r[-1].passed:
        passed.append(domain)
    else:
        failed.append(domain)

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
    import os,sys

    def check(fn):
        print("\n==== {} ====".format(fn))
        if "http" in fn:
            print_test_results(tlsa_http_verify(fn))
        else:
            print_test_results(tlsa_smtp_verify(fn))

    if len(sys.argv)>1:
        for fn in sys.argv[1:]:
            if os.path.exists(fn):
                for line in open(fn):
                    line = line.strip()
                    if line[0]=='#':
                        print(line)
                    else:
                        check(line)
            else:
                check(fn)
        print_stats()
        exit(0)
            

    # These test vectors from
    # http://www.internetsociety.org/deploy360/resources/dane-test-sites/
    for domain in ["dougbarton.us","spodhuis.org", "jhcloos.com", "nlnetlabs.nl", "nlnet.nl"
                   ]:
        print("=== {} ===".format(domain))
        print_test_results(tlsa_smtp_verify(domain))


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
        process_http(domain)
    
    print("HTTP Valid TLSA")
    for domain in ["https://rover.secure64.com/"]:
        print("=== Valid: {} ===".format(domain))
        process_http(domain)


    print("INVALID TLSA")
    for domain in ["https://rogue.nohats.ca",
                   "https://bad-sig.dane.verisignlabs.com",
                   "https://bad-hash.dane.verisignlabs.com",
                   "https://bad-params.dane.verisignlabs.com",
                   "https://www.nist.gov"]:
        print("=== INVALID: {} ===".format(domain))
        process_http(domain)
    
    print_stats()
    exit(0)


