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
import pymysql


class Dbdns:
    def __init__(self,response=None):
        if response:
            self.response = response
            
    

def query(T,name,rr,replay=False):
    """Perform a query of host/rr, store results in database, and get results from db and return"""

    c = T.conn.cursor()
    if T.rw and replay==False:
        a = dns.resolver.query(name,rr)
        response_text = a.response.to_text()
        c.execute("insert into dns (testid,queryname,queryrr,answer) values (%s,%s,%s,%s)",(T.testid,name,rr,response_text))
    else:
        c.execute("select answer from dns where testid=%s and queryname=%s and queryrr=%s",(T.testid,name,rr))
        response_text = c.fetchone()[0]
    return Dbdns(response=dns.message.from_text(response_text))


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
    from tester import Tester

    parser = argparse.ArgumentParser(description="test the DBDNS implementation")
    parser.add_argument("-t",help="specify record to test",default="A")
    parser.add_argument("-i",help="Specify Test ID to use for cache (if not specified, query is live, and a new testID is created)",type=int)
    parser.add_argument("--list",help="list all DNS queries to date",action="store_true")
    parser.add_argument("--dump",help="Dump DNS queries for a specific testID")
    parser.add_argument("--demo",help="Demonstrate a database query and result.",action="store_true")
    parser.add_argument("--mxdemo",help="MX Demo, for slides",action="store_true")
    parser.add_argument("name",nargs="*",help="name to search")
    args = parser.parse_args()

    if args.list:
        T = Tester(rw=False)
        c = T.conn.cursor()
        c.execute("select testid,modified,queryname,queryrr,length(answer) from dns order by dnsid")
        print(" testID  Timestamp            Query Name      RR    Len(answer)")
        for row in c:
            when = str(row[1])
            print("{:8n} {:s}   {:15s} {:4s} len={:5n} ".format(row[0],when,row[2],row[3],row[4]))
    
    if args.dump:
        T = Tester(rw=False)
        c = T.conn.cursor(pymysql.cursors.DictCursor)
        c.execute("select dnsid,modified,queryname,queryrr,answer from dns where testid=%s order by dnsid",(args.dump,))
        for row in c:
            print("DNSID: {}   TIMESTAMP: {}   QUERY: {}    QUERYRR: {}".format(
                row['dnsid'],row['modified'],row['queryname'],row['queryrr']))
            print("")
            print(row['answer'])
            print("")
            print("===================")
            print("")

    if args.demo:
        if len(args.name)!=1:
            print("Error: One name must be provided")
            exit(1)
        name = args.name[0]
        print("DBDNS DEMO")
        T = Tester()
        T.newtest(testname="dig")
        print("dig -t {} {}".format(args.t,name))
        print("TestID: {}".format(T.testid))

        b = dbdns.query(T,name,args.t)
        for part in range(len(b.answer)):
            print("ANSWER PART {}:".format(part))
            for i in range(len(b.answer[part])):
                print("RR {}: {} {}".format(i,b.answer[part][i],type(b.answer[part][i])))
        T.commit()

        print("\n\n\nReplay:")
        c = dbdns.query(T,name,args.t,replay=True)
        for part in range(len(b.answer)):
            print("ANSWER PART {}:".format(part))
            for i in range(len(b.answer[part])):
                print("RR {}: {} {}".format(i,b.answer[part][i],type(b.answer[part][i])))

    if args.mxdemo:
        print("MX hosts for dnspython.org:")
        print("")
        print("Traditional dnspython MX resolution:")
        a = dns.resolver.query("dnspython.org","MX")
        for x in a.response.answer[0]:
            print("{} {}".format(x.preference,x.exchange))

        print("")
        print("dbdns:")
        T = Tester()
        T.newtest(testname="dig")
        a = dbdns.query(T,"dnspython.org","MX")
        for x in a.response.answer[0]:
            print("{} {}".format(x.preference,x.exchange))
