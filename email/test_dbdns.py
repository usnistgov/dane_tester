#!/usr/bin/env python3
#
# Test for py.test to make sure that the dbdns connection works

import sys; assert sys.version > '3'
import pytest
from tester import Tester
import dbdns
import dns.rdatatype

def test_cname_read():
    # This test makes use of the fact that a.nitroba.org is set as a cname to b.nitroba.org
    qname = "a.nitroba.org"
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,dns.rdatatype.CNAME)
    count = 0
    for rset in response.answer:
        for rr in rset:
            if rr.rdtype==dns.rdatatype.CNAME:
                print("cname for a.nitroba.org is {}".format(rr.target))
                assert(str(rr.target)=='b.nitroba.org.')
                count += 1
    assert(count>0)               # no response?

def test_a_read():
    qname = "google-public-dns-a.google.com."
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,dns.rdatatype.A)
    count = 0
    for rrset in response.answer:
        for rr in rrset:
            if r.rdtype==dns.rdatatype.A:
                print("IP addr for {} is {}".format(qname,rr.address))
                assert(rr.address=='8.8.8.8')
                count += 1
    assert(count>0)

def test_two_A_responses():
    qname = "dualstack.mc-12555-1019789594.us-east-1.elb.amazonaws.com."
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,dns.rdatatype.A)
    count = 0
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                print("IP address for {} is {}".format(qname,rr.address))
                count +=1
    assert(count>=2)
    

def test_dnssec_response_present():
    qname = "dnsviz.net"
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,dns.rdatatype.A)
    count = 0
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                dnssec = response.flags & dns.flags.AD
                print("IP address for {} is {} DNSSEC: {}".format(qname,rr.address, dnssec))
                if dnssec: count +=1
    assert count>0

def test_dnssec_response_notpresent():
    qname = "www.google.com"
    T = Tester()
    T.newtest(testname="py.test")
    response = dbdns.query(T,qname,dns.rdatatype.A)
    count = 0
    for rrset in response.answer:
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.A:
                dnssec = response.flags & dns.flags.AD
                print("IP address for {} is {} DNSSEC: {}".format(qname,rr.address, dnssec))
                if dnssec: count += 1
    assert count==0


if __name__=="__main__":
    test_cname_read()
    test_a_read()
    test_two_A_responses()
    test_dnssec_response_present()
    test_dnssec_response_notpresent()
