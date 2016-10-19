#!/usr/bin/env python2.7
# see https://github.com/getdnsapi/getdns-python-bindings/issues/33

import sys
if sys.version >= '3':
    exit(0)

import getdns
extensions = {"dnssec_return_validation_chain" : getdns.EXTENSION_TRUE}
dnssec_status = {getdns.DNSSEC_SECURE:"SECURE",
                 getdns.DNSSEC_INDETERMINATE:"INDETERMINATE",
                 getdns.DNSSEC_INSECURE:"INSECURE",
                 getdns.DNSSEC_BOGUS:"BOGUS",
                 None:""}

rtype = {getdns.RRTYPE_A:"A",
         getdns.RRTYPE_CNAME:"CNAME",
         getdns.RRTYPE_RRSIG:"RRSIG",
         getdns.RRTYPE_TLSA:"TLSA"}

#extensions = {}
def test_getdns():
    ctx = getdns.Context()
    hostname="www.nist.gov"
    indeterminate_count = 0
    for request_type in [getdns.RRTYPE_A, getdns.RRTYPE_CNAME]:
        print("hostname:",hostname,"  request_type:",rtype[request_type])
        results = ctx.general(name=hostname,request_type=request_type,extensions=extensions)
        for reply in results.replies_tree:
            for a in reply['answer']:
                dstat = reply.get('dnssec_status')
                print("request type:",a['type'],rtype[a['type']])
                print("dnssec:",dstat,dnssec_status[dstat])
                if dstat==getdns.DNSSEC_INDETERMINATE:
                    indeterminate_count += 1
                print("answer:",a)
                print("---")
            print("=====================")
    assert(indeterminate_count==0)

if __name__=="__main__":
    test_getdns()

