#!/usr/bin/env python3
# -*- coding: utf-8; mode: python; -*-
#
# database-based DNS module.
# Implements DNS queries to database and response from the database
# See: https://github.com/rthalley/dnspython/issues/134
# 
# Checks DNSSEC on all queries
# http://stackoverflow.com/questions/26137036/programmatically-check-if-domains-are-dnssec-protected

# force Python3
import sys
assert sys.version > '3'

import pytest
import pickle
import dbdns
import pymysql

import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.zone

nsaddr = "8.8.8.8"              # default nameserver address


class Dbdns:
    def __init__(self,response=None):
        if response:
            self.response = response
            
def query(T,qname,rr,replay=False):
    """Perform a query of host/rr, store results in database, and get results from db and return.
    @param qname - string - what you will query
    @param rr   - string - the resource records that you want
    @param replay - boolean - whether to read from the database (True) or write to the data (False; default)

    Note returned object is type <dns.resolver.Answer>
    Answers are in ret.rrset (which is type dns.rrset.RRset).
    For each element in the set:
      TXT records - rr.strings
      CNAME records - rr.target
      MX records: rr.preference, rr.exchange
      A records: rr.address
      AAAA records: rr.address
      TLSA records: 

    Get the entire line: rr.to_text()
    """
    c = T.conn.cursor()
    if T.rw and replay==False:
        try:
            print("nsaddr=",nsaddr)
            request  = dns.message.make_query(qname,rr,want_dnssec=True)
            response = dns.query.udp(request,nsaddr)
            response_text = response.to_text()

            c.execute("insert into dns (testid,queryname,queryrr,answer) values (%s,%s,%s,%s)",
                      (T.testid,qname,rr,response_text))

            return dns.message.from_text(response_text)
        except dns.resolver.NXDOMAIN as e:
            c.execute("insert into dns (testid,queryname,queryrr,NXDOMAIN) values (%s,%s,%s,True)",
                      (T.testid,qname,rr))
            raise e
        except dns.resolver.Timeout as e:
            c.execute("insert into dns (testid,queryname,queryrr,Timeout) values (%s,%s,%s,True)",
                      (T.testid,qname,rr))
            raise e
    else:
        # Replay
        c.execute("select answer,NXDOMAIN,Timeout from dns where testid=%s and queryname=%s and queryrr=%s",
                  (T.testid,qname,rr))
        (response_text,NXDOMAIN,Timeout) = c.fetchone()[0]
        if NXDOMAIN:
            raise dns.resolver.NXDOMAIN
        if Timeout:
            raise dns.resolver.Timeout
        return dns.message.from_text(response_text)
    assert 0
    

def test_query_MX():
    answers = query("dnspython.org","MX")
    for rr in answers:
        print(rr.exchange,rr.preference)
    assert 0
    
def test_query_A():
    answers = query("www.nist.gov","A")
    for rr in answers:
        print(dir(rr))
    
def test_query_SPF():
    answers = query("dnspython.org","TXT")
    for rr in answers:
        print(dir(rr))
    

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

        response = dbdns.query(T,name,args.t)
        for part in range(len(response.answer)):
            print("ANSWER PART {}:".format(part))
            for i in range(len(response.answer[part])):
                print("RR {}: {} {}".format(i,response.answer[part][i],type(response.answer[part][i])))
        T.commit()

        print("\n\n\nReplay:")
        response = dbdns.query(T,name,args.t,replay=True)
        for part in range(len(response.answer)):
            print("ANSWER PART {}:".format(part))
            for i in range(len(b.answer[part])):
                print("RR {}: {} {}".format(i,
                                            response.answer[part][i],
                                            type(response.answer[part][i])))

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
        response = dbdns.query(T,"dnspython.org","MX")
        for x in response.answer[0]:
            print("{} {}".format(x.preference,x.exchange))
