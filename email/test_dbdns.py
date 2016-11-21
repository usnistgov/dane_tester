#!/usr/bin/env python3
#
# Test for py.test to make sure that the dbdns connection works

import pytest
from tester import Tester
import dbdns
import dns.rdatatype

def test_cname_read():
    """This test makes use of the fact that a.nitroba.org is set as a cname to b.nitroba.org"""
    qname = "a.nitroba.org"
    print("testing",qname)
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,"CNAME")
    for rr in response.answer:
        print("{} rdclass={} rdtype={}".format(rr,rr.rdclass,rr.rdtype))
        if(rr.rdtype==dns.rdatatype.MX):
            print("cname for a.nitroba.org is {}".format(rr.target))
    print("")

def test_two_A_responses():
    qname = "dualstack.mc-12555-1019789594.us-east-1.elb.amazonaws.com."
    print("test_two_A_responses",qname)

    print("let's do this manually first")
    request = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
    response = dns.query.udp(request,dbdns.nsaddr)
    response = dns.message.from_text(response.to_text())
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                print(rr.address)

    print("now test with dbdns")
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,dns.rdatatype.A)
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                print(rr.address)

    print("")
    

if __name__=="__main__":
    test_cname_read()
    test_two_A_responses()
