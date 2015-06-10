import getdns
import sys
import pytest

MAX_CNAME_DEPTH=20

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
    def __init__(self,passed=True,dnssec=None,what=None,why=None,data=None,rdata=None):
        self.passed = passed
        self.dnssec = dnssec
        self.what   = what
        self.why    = why
        self.data   = data
        self.rdata   = rdata
    def __repr__(self):
        return "%s %s %s %s %s" % (self.passed,self.dnssec,self.what,self.why,self.data)

################################################################
## Simple conversion routines
def hexdump(str, separator=''):
    return separator.join(x.encode('hex') for x in str)



################################################################
## Verification routines
##
## Verify PEM certificate chain and end entity certificates in PEM format using OpenSSL
##
def pem_verify(cert_chain,ee_cert):
    # Verify certificates using openssl
    from subprocess import Popen,PIPE
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as chainfile:
        chainfile.write(cert_chain)
        chainfile.flush()
        with tempfile.NamedTemporaryFile(delete=False) as eefile:
            eefile.write(ee_cert)
            eefile.flush()

            cmd = ['openssl','verify','-untrusted',chainfile.name,eefile.name]
            res = Popen(cmd,stdout=PIPE).communicate()[0]
            res = res.replace("\n"," ")
            if "error" in res:
                return [ DaneTestResult(what="Certificate Verification Failed: "+res) ]
            return [ DaneTestResult(what="Certificate Verified") ]

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

def tlsa_select(s, cert):
    assert s in [0,1]
    if s==0: return cert.as_der()
    if s==1: return cert.get_pubkey().as_der()

def upperhex(s):
    s = s.replace(' ','')
    return s.upper()



def tlsa_match(mtype, cert_data, from_dns):
    import hashlib
    assert mtype in [0,1,2]
    hex_data = hexdump(cert_data)
    if mtype == 1:
        hex_data = hashlib.sha256(cert_data).hexdigest()
    if mtype == 2:
        hex_data = hashlib.sha512(cert_data).hexdigest()
    return upperhex(hex_data) == upperhex(from_dns)

# CU 0 - Directly specifies the CA certificate or public key used to validate the certificate provided by the End Entity (EE)
# There must be a valid chain from the EE to the CU 0 trust anchor and the CU 0 trust anchor must be a recognized CA.
#
# CU 1 - Directly specifies the EE certificate or public key, and the certificate must validate.
#
# CU 2 - Specifies a trust anchor. There must be a valid chain from the EE to the CU 2 trust anchor.
#
# CU 3 - Directly specifies the EE's certificate or public key, and the certificate need not validate.



def tlsa_verify(certs,tlsa_rdata,hostname):
    import M2Crypto
    cert_usage = tlsa_rdata['certificate_usage']
    selector   = tlsa_rdata['selector']
    mtype      = tlsa_rdata['matching_type']
    associated_data = tlsa_rdata['certificate_association_data']
    
    if not (cert_usage in [0,1,2,3] and selector in [0,1] and mtype in [0,1,2]):
        return [ DaneTestResult(passed=False,what="TLSA Parameters bad: {} {} {}".format(cert_usage,selector,mtype)) ]

    ct = hexdump(tlsa_rdata['certificate_association_data'])
    if cert_usage in [0, 2]: # need to find one trust anchor, loop all
        for cert in certs:
            cert_obj = M2Crypto.X509.load_cert_string(cert)
            cert_data = tlsa_select(selector, cert_obj)
            if tlsa_match(mtype, cert_data, ct):
                return True
    if cert_usage in [1,3]:
        cert_obj = M2Crypto.X509.load_cert_string(certs[0])
        cert_data = tlsa_select(selector, cert_obj)
        if tlsa_match(mtype, cert_data, ct):
            ret = [ DaneTestResult(what="TLSA VERIFIED: certificate usage {} matches".format(cert_usage)) ]
            if cert_usage==1:
                # Need to validate the certificate
                if pem_verify("\n".join(certs),certs[0]):
                    ret += [ DaneTestResult(what="TLSA Certificate Usage 1: Certificates verify") ]
                # Check the name on the certificates
                cn = cert_obj.get_subject().CN
                if hostname.lower() == cn.lower():
                    ret += [ DaneTestResult(what="TLSA Certificate Usage 1: Certificate Common Name {} matches hostname".format(cn)) ]
                else:
                    ret += [ DaneTestResult(passed=False,
                                            what="TLSA Certificate Usage 1: Certificate Common Name {} does not match hostname {}".format(cn,hostname)) ]

            return ret
        else:
            return [ DaneTestResult(passed=False,what="TLSA certificate usage {} does not match".format(cert_usage)) ]
      





################################################################
def get_service_certificate_chain(ipaddr,hostname,port,protocol):
    from subprocess import Popen,PIPE
    cmd = None
    if protocol.lower()=="https":
        if not port: port = 443
        cmd = ['openssl','s_client','-host',ipaddr,'-port',str(port),'-servername',hostname,'-showcerts']
    if protocol.lower()=="smtp":
        if not port: port = 25
        cmd = ['openssl','s_client','-host',ipaddr,'-port',str(port),'-starttls','smtp','-showcerts']
    if not cmd:
        raise RuntimeError("invalid protocol")
    with timeout(seconds=10):
        multi_certs = Popen(cmd,stdin=open("/dev/null","r"),stdout=PIPE,stderr=PIPE).communicate()[0]
        return [ DaneTestResult(what="Fetched EE Certificate for {} from {} via {}".format(hostname,ipaddr,protocol),
                                data=multi_certs) ]
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


extensions = {"return_both_v4_and_v6":getdns.EXTENSION_TRUE,
                       "dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}


dnssec_status = {getdns.DNSSEC_SECURE:"SECURE",
                 getdns.DNSSEC_INDETERMINATE:"INDETERMINATE",
                 getdns.DNSSEC_INSECURE:"INSECURE",
                 getdns.DNSSEC_BOGUS:"BOGUS",
                 None:"n/a"}



def tlsa_str(rdata):
    return "%s %s %s %s" % (rdata['certificate_usage'],rdata['selector'],rdata['matching_type'],hexdump(rdata['certificate_association_data']))

def v(bin_addr):
    return '.'.join(map(str, map(ord, bin_addr)))

def hexdata(rdata):
    def hex2(f):
        return hex(f)[2:]
    return "".join(map(hex2,map(ord,rdata)))

def get_dns_ip(hostname,request_type=getdns.RRTYPE_A):
    ret = []
    ctx = getdns.Context()
    results = ctx.general(name=hostname,request_type=request_type,extensions=extensions)
    for reply in results.replies_tree:
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
                ret.append( DaneTestResult(what='DNS MX lookup {} = {}'.format(hostname,rdata['exchange']),
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
    return get_dns_ip(tlsa_hostname(host,port),request_type=getdns.RRTYPE_TLSA)


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
    return [ DaneTestResult(passed=False,what='CNAME search for %s reached depth of %d' % (original_hostname,MAX_CNAME_DEPTH))]
    
   
   

def tlsa_service_verify(hostname,port,protocol):
    test_results = []
    tlsa_records = get_dns_tlsa(hostname,port)

    if not tlsa_records:
        return [ DaneTestResult(what='NO TLSA records for {}'.format(tlsa_hostname(hostname,port))) ]

    test_results += tlsa_records
    ip_results = get_dns_ip(hostname)

    # Check each ip address against each tlsa record
    for ip_result in ip_results:
        test_results += [ip_result]
        for tlsa_record in tlsa_records:
            cert_results = get_service_certificate_chain(ip_result.data,hostname,port,protocol)
            test_results += cert_results
            certs = split_certs(cert_results[0].data)
            r = tlsa_verify(certs, tlsa_record.rdata, hostname)
            test_results += r
    return test_results

        
def apply_dane_test(test_results):
    valid = False
    for test in test_results:
        if test.passed and "TLSA VERIFIED" in test.what:
            return True
    test_results += [ DaneTestResult(what='NO TLSA record verifies.',passed=False) ]

def apply_dnssec_test(test_results):
    valid = True
    for test in test_results:
        if test.dnssec not in [None,getdns.DNSSEC_SECURE]:
            test_results += [ DaneTestResult(what='Not all DNS lookups secured by DNSSEC',passed=False) ]
            break

def tlsa_http_verify(url):
    from urlparse import urlparse
    test_results = []
    o = urlparse(url)
    (hostname,cname_results) = chase_dns_cname(o.hostname)
    port = o.port
    if not port: port = 443
    test_results += cname_results
    test_results += tlsa_service_verify(hostname,port,'https')
    apply_dane_test(test_results)
    apply_dnssec_test(test_results)
    return test_results
    


def check_dane(hostname,port=None,protocol=None):
    assert(port!=None)
    assert(protocol!=None)
    # Get the list of IP addresses and DNSSEC status associated with hostname
    tlsa  = get_dns_tlsa_hostname_port(hostname,port)
    addrs = get_ip_dnssec(hostname)
    

def print_test_results(tests):
    def passed(t):
        return {True:"PASSED",False:"FAILED"}[t.passed]

    def dnssec(t):
        return dnssec_status[t.dnssec]

    print("Tests completed: %d" % len(tests))
    print("  status  dnssec")
    print(" -------  ------")
    for test in tests:
        print("  %s  %s :  %s" % (passed(test),dnssec(test),test.what))
    print("")
              
    

if __name__=="__main__":
    #print_test_results(pem_verify(open("google_chain.pem").read(),open("google.pem").read()))
    for domain in ["https://www.had-pilot.com",
                   "https://bad-sig.dane.verisignlabs.com",
                   "https://bad-hash.dane.verisignlabs.com",
                   "https://www.nist.gov",
                   "https://www.simson.net"]:

        print("=== {} ===".format(domain))
        print_test_results(tlsa_http_verify(domain))
    exit(0)

    print("getdns.DNSSEC_SECURE={}".format(getdns.DNSSEC_SECURE))
    print("getdns.DNSSEC_INDETERMINATE={}".format(getdns.DNSSEC_INDETERMINATE))
    print("getdns.DNSSEC_INSECURE={}".format(getdns.DNSSEC_INSECURE))
    print("getdns.DNSSEC_BOGUS={}".format(getdns.DNSSEC_BOGUS))

    for name in ['fedoraproject.org','simson.net']:
        check_dane(name,port='443',protocol='http')
    exit(0)

    # Test hosts for DANE TLSA SMTP
    for host in ['dougbarton.us','jhcloos.com','nlnetlabs.nl','nlnet.nl','spodhuis.org']:
        pass

    for domain in ['dnssec-failed.org',"had-pilot.com","dnssectest.sidnlabs.nl","www.simson.net"]:
        #get_ip(domain,{})
        #get_ip(domain,{'dnssec_return_status' : getdns.EXTENSION_TRUE })
        get_ip(domain,{"dnssec_return_validation_chain" : getdns.EXTENSION_TRUE})

