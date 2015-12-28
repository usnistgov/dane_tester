#!/usr/bin/env python3
#
# database-based DNS module.
# Implements DNS queries to database and response from the database
# See: https://github.com/rthalley/dnspython/issues/134
# 

import pytest
import dns
import dns,dns.resolver,dns.query,dns.zone,dns.message
import pickle

def query(host,rr):
    """Perform a query of host/rr, store results in database, and get results from db and return"""
    return dns.resolver.query(host,rr)


def test_query_MX():
    answers = query("dnspython.org","MX")
    for rdata in answers:
        print(rdata.exchange,rdata.preference)
    assert 0
    
def test_query_A():
    answers = query("www.nist.gov","A")
    for rdata in answers:
        print(dir(rdata))
    
def test_query_SPF():
    answers = query("dnspython.org","TXT")
    for rdata in answers:
        print(dir(rdata))
    

def test_roundTrip():
    # Get an answer:
    a = dns.resolver.query("dnspython.org","MX")
    print("answers:",a,type(a))
    answer = a.response.answer[0]
    for x in answer:
        print("answer:",x,type(x))
        print("answer:",x.preference,x.exchange)

    # Convert to wire format:
    answers_text = a.response.to_text()
    print("===WIRE FORMAT===")
    print(answers_text)
    print("=================")

    # Convert back to DNS format:
    b = dns.message.from_text(answers_text)
    answer = b.answer[0]
    for x in answer:
        print("bnswer:",x,type(x))
        print("bnswer:",x.preference,x.exchange)


if __name__=="__main__":
    test_roundTrip()
