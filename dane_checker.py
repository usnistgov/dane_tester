import getdns
import sys
import pytest

class DaneTestResult:
    def __init__(self,passed=None,dnssec=None,desc=None,why=None,data=None):
        self.passed = passed
        self.dnssec = dnssec
        self.desc   = desc
        self.why    = why
        self.data   = data
    def __repr__(self):
        return "%s %s %s %s %s" % (self.passed,self.dnssec,self.desc,self.why,self.data)

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

def tlsa_verify(usage,selector,mtype,data,chain):
    print("tlsa_verify not currently implemented")
    return []

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
                 getdns.DNSSEC_BOGUS:"BOGUS"}



def tohex(rdata):
    def hexnum(v): return "%02X" % ord(v)
    return ''.join(map(hexnum, rdata))

def tlsa_str(rdata):
    return "%s %s %s %s" % (rdata['certificate_usage'],rdata['selector'],rdata['matching_type'],tohex(rdata['certificate_association_data']))

def get_tlsa(host,port):
    ctx = getdns.Context()
    ret = []
    try:
        rhost = "_{}._tcp.{}".format(port,host)
        results = ctx.general(name=rhost,
                              request_type = getdns.RRTYPE_TLSA,
                              extensions=extensions)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)
    
    if results.status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']
            for answer in answers:
                if answer['type'] == getdns.RRTYPE_TLSA:
                    dstat = reply.get('dnssec_status')
                    dstat_str = dnssec_status[dstat]
                    rdata = answer['rdata']
                    print("{} TLSA usage:{}  selector:{} matching_type:{}  data:{} DNSSEC:{}".format(
                            rhost,
                            rdata['certificate_usage'],
                            rdata['selector'],
                            rdata['matching_type'],
                            tohex(rdata['certificate_association_data']),
                            dstat))
                    ret.append( DaneTestResult(passed=(dstat==getdns.DNSSEC_SECURE),data=rdata) )
                    break
    return ret
    



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
                ret.append( DaneTestResult(passed=(dstat==getdns.DNSSEC_SECURE),data=ipv4) )
            if a['type'] == getdns.RRTYPE_CNAME == request_type:
                ret.append( DaneTestResult(passed=(dstat==getdns.DNSSEC_SECURE),data=rdata['cname']))
                            
    return ret


def get_dns_cname(hostname):
    return get_dns_ip(hostname,request_type=getdns.RRTYPE_CNAME)

def get_ip_dnssec(hostname):
    ctx = getdns.Context()
    extension = {"dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}
    results = ctx.address(name=hostname,extensions=extension)
    ret = []
    for reply in results.replies_tree:
        for a in reply['answer']:
            if a['type']==getdns.RRTYPE_A:
                ipv4 = v(a['rdata']['ipv4_address'])
                dstat = reply.get('dnssec_status','NONE')
                ret.append((ipv4,dstat))
    return ret
                           
    
def get_tlsa_hostname_port(hostname,port):
    ctx = getdns.Context()
    extension = {"dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}
    qname = "_{}._tcp.{}".format(port,hostname)
    results = ctx.general(name=qname,request_type=getdns.RRTYPE_TLSA,extensions=extension)
    ret = []
    for reply in results.replies_tree:
        for a in reply['answer']:
            if a['type']==getdns.RRTYPE_TLSA:
                rdata = a['rdata']
                dstat = reply.get('dnssec_status','NONE')
                ret.append((rdata['certificate_usage'],rdata['selector'],rdata['matching_type'],hexdata(rdata['certificate_association_data'])))
    return ret
    
    
begin_certificate = '-----BEGIN CERTIFICATE-----'
end_certificate = '-----END CERTIFICATE-----'
def get_http_certificate(ipaddr,port):
    from subprocess import PIPE,Popen
    cmd = ['openssl','s_client','-connect',"{}:{}".format(ipaddr,port)]
    out = Popen(cmd,stdin=open("/dev/null"),stdout=PIPE).communicate()[0]
    start = out.find(begin_certificate)
    end   = out.find(end_certificate)
    print("start=",start)
    print("out=",out)
    return out[start:end+len(end_certificate)+1]
    


def check_dane(hostname,port=None,protocol=None):
    assert(port!=None)
    assert(protocol!=None)
    # Get the list of IP addresses and DNSSEC status associated with hostname
    tlsa  = get_tlsa_hostname_port(hostname,port)
    addrs = get_ip_dnssec(hostname)
    print("{}:".format(hostname))
    print(tlsa)
    print(addrs)
    print(get_http_certificate(addrs[0][0],443))
    

if __name__=="__main__":
    n = get_tlsa("www.had-pilot.com",443)
    print(tlsa_str(n[0].data))
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

