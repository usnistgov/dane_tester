#!/usr/bin/env python3
#
# Test for py.test to make sure that the dbdns connection works

import pytest
from tester import Tester
import dbdns

def test_dbdns_connect():
    T = Tester()
    #T.newtest(testname="py.test")
    print("T=",T)
    r = dbdns.query(T,"a.nitroba.org","CNAME")
    print(r)


if __name__=="__main__":
    test_dbdns_connect()
