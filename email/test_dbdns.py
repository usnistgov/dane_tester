#!/usr/bin/env python3
#
# Test for py.test to make sure that the dbdns connection works

import pytest
from tester import Tester
import dbdns

def test_cname_read():
    """This test makes use of the fact that a.nitroba.org is set as a cname to b.nitroba.org"""
    T = Tester()
    T.newtest(testname="py.test")
    rrset = dbdns.query(T,"a.nitroba.org","CNAME")
    for rr in rrset:
        print("cname for a.nitroba.org is {}".format(rr.target))

def test_two_responses():
    T = Tester()
    T.newtest(testname="py.test")
    rrset = dbdns.query(T,"dualstack.mc-12555-1019789594.us-east-1.elb.amazonaws.com.","A")
    for rr in rrset:
        print(rr)
    

if __name__=="__main__":
    test_cname_read()
    test_two_responses()
