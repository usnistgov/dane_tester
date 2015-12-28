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
import dbdns

def query(T,name,rr):
    """Perform a query of host/rr, store results in database, and get results from db and return"""
    a = dns.resolver.query(name,rr)
    response_text = a.response.to_text()
    c = T.conn.cursor()
    print("T.testid=",type(T.testid),T.testid)
    if T.rw:
        c.execute("insert into dns (testid,queryname,queryrr,answer) values (%s,%s,%s,%s)",(T.testid,name,rr,response_text))
    else:
        c.execute("select answer from dns where testid=%s and queryname=%s and queryrr=%s",(T.testid,name,rr))
        response_text = c.fetchone()[0]
    return dns.message.from_text(response_text)


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
    import argparse
    from tester import tester

    parser = argparse.ArgumentParser(description="test the DBDNS implementation")
    parser.add_argument("-t",help="specify record to test",default="A")
    parser.add_argument("-i",help="Specify Test ID to use for cache (if not specified, query is live, and a new testID is created)",type=int)
    parser.add_argument("--list",help="list all DNS queries",action="store_true")
    parser.add_argument("name",nargs="*",help="name to search")
    args = parser.parse_args()

    if args.list:
        T = tester(rw=False)
        c = T.conn.cursor()
        c.execute("select testid,queryname,queryrr,length(answer) from dns order by dnsid")
        print(" testID  Query Name     RR    Len(answer)")
        for row in c:
            print("{:8n} {:15s} {:4s} len={:5n} ".format(row[0],row[1],row[2],row[3]))
        exit(0)
                

    T = tester(testname="dig",testid=args.i)
    print("dig -t {} {}".format(args.t,args.name))
    print("TestID: {}".format(T.testid))
    b = dbdns.query(T,args.name,args.t)
    for i in range(len(b.answer)):
        print("Part {}:".format(i))
        for x in b.answer[i]:
            print(x)
